"""Los limites de recurso, y lo que el log de ingesta publicaba de mas.

Tres formas de tumbar el proceso SIN CREDENCIAL, todas medidas antes del
arreglo, y todas con la solucion escrita en el fichero de al lado.

Estos tests se hacen a proposito con limites pequenos y cuerpos pequenos: para
demostrar que el corte ocurre en el sitio correcto no hace falta escribir
200 MB en el disco de nadie, y el test que los escribiera tardaria un minuto
cada vez que alguien toca cualquier cosa.
"""

from __future__ import annotations

import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from glamdring.api.lectura import TROZO_BYTES, leer_acotado
from glamdring.main import app
from glamdring.store import STORE, redact


@pytest.fixture
def client():
    STORE.clear()
    return TestClient(app)


class FicheroFalso:
    """Un fichero subido que APUNTA cuanto le han pedido de verdad.

    Es lo unico que distingue el arreglo de lo de antes. Las dos versiones
    devuelven 413 con un fichero grande; solo una deja de leer al llegar al
    limite. Sin este contador el test pasaria igual con el fallo puesto, que es
    la trampa en la que ya se ha caido dos veces esta sesion.
    """

    def __init__(self, total: int) -> None:
        self._restante = total
        self.servido = 0

    async def read(self, tamano: int = -1) -> bytes:
        if tamano < 0:            # el read() entero de antes
            tamano = self._restante
        trozo = min(tamano, self._restante)
        self._restante -= trozo
        self.servido += trozo
        return b"\x00" * trozo


# ----------------------------------------------- el fichero que no se lee entero

@pytest.mark.asyncio
async def test_la_lectura_se_corta_en_el_limite_y_no_al_final():
    """Diez veces el limite servidos; se leen el limite y un trozo, no diez.

    Antes esto era `payload = await file.read()` seguido de mirar el tamano: el
    limite se comprobaba cuando la memoria ya estaba gastada. Medido con la
    subida de modelos, 200 MB contra un limite de 25 daban 600 MB de pico.
    """
    tope = 4 * TROZO_BYTES
    fichero = FicheroFalso(tope * 10)

    with pytest.raises(HTTPException) as fallo:
        await leer_acotado(fichero, tope)

    assert fallo.value.status_code == 413
    # El pico queda en el limite mas un trozo. Con el fallo puesto seria el
    # fichero entero, diez veces mas.
    assert fichero.servido <= tope + TROZO_BYTES
    assert fichero.servido < tope * 2


@pytest.mark.asyncio
async def test_lo_que_cabe_se_lee_entero():
    """Que el corte no se lleve por delante el caso normal."""
    fichero = FicheroFalso(TROZO_BYTES + 17)
    datos = await leer_acotado(fichero, 10 * TROZO_BYTES)
    assert len(datos) == TROZO_BYTES + 17


def test_el_glb_pasa_por_la_lectura_acotada(client, monkeypatch):
    """La subida de modelos usa el mismo camino que la ingesta.

    Se sirve como estatico y lo carga el navegador de todo el equipo, asi que
    era la ruta con peor relacion entre limite -25 MB- y lo que se tragaba.
    """
    import glamdring.api.routes_appearance as rutas
    monkeypatch.setattr(rutas, "MAX_MODEL_BYTES", 1024)

    respuesta = client.post("/api/appearance/model/host",
                            files={"file": ("x.glb", b"A" * 4096, "model/gltf-binary")})
    assert respuesta.status_code == 413


# --------------------------------------------------- la consulta sin longitud

def test_una_consulta_desmesurada_se_rechaza_antes_de_llegar_al_siem(client):
    """`query` era el unico campo de longitud libre del cuerpo.

    `limit` y `cursor` si tenian tope; este no, y pydantic construye la cadena
    ANTES de que nadie mire si el conector existe siquiera. Medido: 600 MB de
    pico con una cadena de 200 MB, sin credencial y sin SIEM configurado.
    """
    respuesta = client.post("/api/query", json={"connector": "splunk",
                                                "query": "a" * (100 * 1024)})
    assert respuesta.status_code == 422


def test_una_consulta_normal_sigue_pasando(client):
    """Una SPL de verdad son cientos de bytes. Que el tope no estorbe."""
    respuesta = client.post("/api/query", json={
        "connector": "splunk",
        "query": "index=wineventlog EventCode=4688 | table _time host user"})
    # 400 o 502 segun este configurado: lo que importa es que NO es un 422 de
    # validacion, o sea que la consulta ha llegado entera a su sitio.
    assert respuesta.status_code != 422


def test_una_consulta_vacia_se_rechaza(client):
    """Sin `min_length`, una cadena vacia llegaba al conector y cada SIEM hacia
    una cosa distinta con ella, ninguna buena."""
    respuesta = client.post("/api/query", json={"connector": "splunk", "query": ""})
    assert respuesta.status_code == 422


# ------------------------------------------------------- el tope de nodos

def test_max_nodes_no_acepta_un_numero_absurdo(client):
    """Aceptaba 2**63. `max_nodes` dimensiona el recorte del grafo, y 0 ya
    significa 'sin recorte', asi que un numero enorme no pedia nada nuevo."""
    assert client.get("/api/graph", params={"maxNodes": 2 ** 63}).status_code == 422


def test_max_nodes_util_sigue_pasando(client):
    assert client.get("/api/graph", params={"maxNodes": 500}).status_code == 200


# ------------------------------------- lo que el log de ingesta publicaba

def test_el_log_de_ingesta_no_publica_la_consulta_del_analista(client):
    """`GET /api/ingest-log` devolvia el `origin` sin tachar.

    Y el `origin` de una consulta en vivo son los primeros 80 caracteres de la
    SPL o KQL que escribio el analista: el indice, el host, el usuario que esta
    investigando. `redact()` funcionaba -el secreto DENTRO del log si salia
    tachado- pero no se aplicaba a esto.
    """
    registro = json.dumps([{"EventCode": "4688", "Account_Name": "jlopez",
                            "ComputerName": "wks-0421",
                            "_time": "2024-05-02T09:12:00Z"}])
    envenenado = "index=wineventlog token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.QWERTYUIOP"
    client.post("/api/ingest", data={"text": registro, "format_hint": "json"})
    STORE.ingest_log[-1]["origin"] = redact(envenenado)[:200]

    entradas = client.get("/api/ingest-log").json()["log"]
    publicado = entradas[-1]["origin"]
    assert "eyJhbGciOiJIUzI1NiJ9" not in publicado
    assert "redactado" in publicado


def test_el_origin_se_tacha_al_guardarlo(client):
    """En `store.add`, que es el UNICO punto de escritura: por ahi pasan tanto
    la ingesta manual como los empujones del receptor."""
    from glamdring.normalize import normalize_all
    eventos = normalize_all([{"EventCode": "4688", "Account_Name": "a",
                              "ComputerName": "b", "_time": "2024-05-02T09:12:00Z"}])
    STORE.add(eventos, origin="splunk:index=x password=Verano2024! host=DC01")

    guardado = STORE.ingest_log[-1]["origin"]
    assert "Verano2024!" not in guardado
    # Y lo de alrededor se conserva: el origen es para saber de donde vino el
    # evento, y tacharlo entero seria perder la trazabilidad por proteger una
    # palabra.
    assert "splunk:index=x" in guardado


# ------------------------------------------------ el tope de cuerpo por ruta

def test_un_tope_global_solo_dejaria_muerto_el_de_la_subida():
    """El primer intento tenia un tope global de 50 MB y el de subida en 200.

    Dos topes donde el de FUERA es menor que el de DENTRO no son dos defensas:
    son una defensa y una linea que no se ejecuta nunca. Y bajar la subida a
    50 MB tampoco valia, porque arrastrar el fichero exportado del SIEM es la
    forma en que mas se usa esto.
    """
    from glamdring.api.routes_ingest import MAX_UPLOAD_BYTES
    from glamdring.security import tope_de_cuerpo

    assert tope_de_cuerpo("/api/ingest") > MAX_UPLOAD_BYTES


def test_cada_ruta_tiene_el_tope_que_le_toca():
    from glamdring.api.routes_appearance import MAX_MODEL_BYTES
    from glamdring.security import MAX_BYTES_PETICION, tope_de_cuerpo

    assert tope_de_cuerpo("/api/appearance/model/host") > MAX_MODEL_BYTES
    assert tope_de_cuerpo("/api/query") == MAX_BYTES_PETICION
    # Y el de al lado NO hereda el de la subida. Por prefijo, "/api/ingest"
    # pillaria tambien "/api/ingest-log": es un GET sin cuerpo, pero no hay
    # ninguna razon para regalarle 200 MB.
    assert tope_de_cuerpo("/api/ingest-log") == MAX_BYTES_PETICION


def test_se_rechaza_por_content_length_sin_leer_el_cuerpo(client):
    """LO QUE MAS VALE DE TODO ESTO.

    Si la cabecera ya declara mas de lo que cabe, se responde 413 sin leer un
    solo byte. Ahi es donde muere el caso que midio la auditoria: 300 MB
    escritos en el temporal para acabar rechazandolos.

    El test manda un `Content-Length` de 100 MB con un cuerpo de dos bytes. Que
    conteste 413 demuestra que la decision se toma con la cabecera; si tuviera
    que leer el cuerpo para decidir, se quedaria esperando los 100 MB que nunca
    van a llegar.
    """
    respuesta = client.post("/api/query", content=b"{}",
                            headers={"Content-Type": "application/json",
                                     "Content-Length": str(100 * 1024 * 1024)})
    assert respuesta.status_code == 413
