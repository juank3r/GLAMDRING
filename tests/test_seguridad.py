"""La frontera de la API: de donde viene la peticion, quien la hace, y cuanto pesa.

Antes de esto habia 31 operaciones de API y cero con autenticacion. Lo que se
prueba aqui es lo que ahora se RECHAZA, y muy en particular que no se rechace de
mas: el receptor lo usan procesos que no mandan ninguna de estas cabeceras, y
dejarlos fuera romperia la ingesta en vivo sin que nadie se enterase hasta que
faltaran eventos.
"""

from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from glamdring.config import SETTINGS
from glamdring.main import app
from glamdring.receive import RateLimiter, ReceiveConfig
from glamdring.security import (MAX_BYTES_PETICION, ClaveApiMiddleware,
                                montar_seguridad)
from glamdring.store import STORE

AJENO = "https://evil.example"


@pytest.fixture
def client():
    STORE.clear()
    return TestClient(app)


# ------------------------------------------------- de donde viene la peticion

def test_reset_desde_otra_pagina_se_rechaza(client):
    """EL ATAQUE QUE FUNCIONABA HOY, sin desplegar nada.

    Reproducido antes del arreglo: `POST /api/reset` con `Origin` ajeno
    devolvia 200 y vaciaba la investigacion en curso. Cualquier pagina abierta
    en otra pestana podia hacerlo con un fetch de una linea.
    """
    client.post("/api/demo")
    antes = len(STORE.events)
    assert antes > 0

    respuesta = client.post("/api/reset", headers={"Origin": AJENO})

    assert respuesta.status_code == 403
    # Y lo que de verdad importa: que la investigacion siga ahi.
    assert len(STORE.events) == antes


def test_ingest_multipart_desde_otra_pagina_se_rechaza(client):
    """Multipart NO lleva comprobacion previa del navegador.

    Por eso atarlo a loopback no protegia: el navegador manda la peticion
    directamente, sin preguntar antes si puede.
    """
    registro = json.dumps([{"EventCode": "4688", "Account_Name": "x",
                            "ComputerName": "y", "_time": "2024-05-02T09:12:00Z"}])
    respuesta = client.post("/api/ingest", data={"text": registro},
                            headers={"Origin": AJENO})
    assert respuesta.status_code == 403
    assert len(STORE.events) == 0


@pytest.mark.parametrize("sitio,esperado", [("cross-site", 403), ("same-site", 200)])
def test_sec_fetch_site_manda_sobre_origin(client, sitio, esperado):
    """`Sec-Fetch-Site` es la respuesta directa y la mandan los navegadores.

    `same-site` se acepta: es otro subdominio de la misma organizacion, no una
    pagina cualquiera. `cross-site` no.
    """
    respuesta = client.post("/api/reset", headers={"Sec-Fetch-Site": sitio})
    assert respuesta.status_code == esperado


def test_el_usuario_escribiendo_la_url_no_es_un_ataque(client):
    """`Sec-Fetch-Site: none` es alguien usando la herramienta, no una
    falsificacion. Rechazarlo seria romper el uso normal."""
    assert client.post("/api/reset", headers={"Sec-Fetch-Site": "none"}).status_code == 200


def test_un_cliente_que_no_es_navegador_pasa(client):
    """curl, un script o un reenviador no mandan ninguna de las dos cabeceras.

    Se les deja pasar A PROPOSITO: la falsificacion entre sitios es un problema
    del navegador, que es quien adjunta las credenciales de la victima sin que
    ella lo pida. Un script hostil no necesita enganar a nadie, asi que exigirle
    una cabecera no protege de nada y si rompe la automatizacion legitima.
    """
    assert client.post("/api/reset").status_code == 200


def test_leer_desde_otra_pagina_no_se_bloquea(client):
    """Los GET pasan: el navegador no deja leer la respuesta de otro origen, y
    aqui ninguno modifica nada. Bloquearlos seria ruido sin ganancia."""
    assert client.get("/api/health", headers={"Origin": AJENO}).status_code == 200


def test_el_mismo_origen_pasa(client):
    """Que no se rompa la propia interfaz, que es de donde vienen casi todas."""
    respuesta = client.post("/api/reset",
                            headers={"Origin": "http://testserver", "Host": "testserver"})
    assert respuesta.status_code == 200


def test_el_receptor_no_pasa_por_la_comprobacion_de_origen(monkeypatch):
    """El receptor tiene su propia puerta y lo usan procesos, no navegadores.

    Un `Origin` ajeno tiene que llegar a SU comprobacion de clave -401- y no
    quedarse en un 403 de origen: si se quedara ahi, el mensaje de error
    mandaria al administrador a mirar CORS cuando lo que tiene mal es la clave.
    """
    config = ReceiveConfig(keys={"netskope": "T3jHq2vLpZ9wXn4mKd8sRy6bAc1fUgEo"},
                           max_bytes=4096, per_minute=1000)
    monkeypatch.setattr(SETTINGS, "receive", config)
    import glamdring.api.routes_receive as rutas
    monkeypatch.setattr(rutas, "_LIMITADOR", RateLimiter(config.per_minute))
    with TestClient(app) as cliente:
        respuesta = cliente.post("/api/receive/netskope", content=b"[]",
                                 headers={"Origin": AJENO})
    assert respuesta.status_code == 401


# --------------------------------------------------------------- quien la hace

@pytest.fixture
def con_clave():
    """Una aplicacion minima con la clave puesta.

    Se monta con `montar_seguridad`, que es la misma funcion que usa `main`:
    asi lo que se prueba es el montaje de verdad y no una copia parecida.
    """
    protegida = FastAPI()

    @protegida.get("/api/export")
    def exportar():
        return {"eventos": ["el corpus entero del cliente"]}

    @protegida.post("/api/receive/netskope")
    def recibir():
        return {"status": "ok"}

    @protegida.get("/")
    def raiz():
        return {"frontend": True}

    montar_seguridad(protegida, clave="clave-de-prueba-larga-y-fea")
    return TestClient(protegida)


def test_sin_clave_no_se_exporta_el_incidente(con_clave):
    """`GET /api/export` entrega el corpus completo del incidente del cliente.

    Es la operacion mas cara de las 31 que estaban abiertas: no vacia nada, asi
    que nadie se entera, y se lleva todo.
    """
    assert con_clave.get("/api/export").status_code == 401


@pytest.mark.parametrize("cabecera", [
    {"X-Glamdring-Key": "clave-de-prueba-larga-y-fea"},
    {"Authorization": "Bearer clave-de-prueba-larga-y-fea"},
])
def test_con_la_clave_pasa(con_clave, cabecera):
    assert con_clave.get("/api/export", headers=cabecera).status_code == 200


def test_una_clave_parecida_no_pasa(con_clave):
    """Un caracter menos. Con `==` la comparacion para en el primer byte
    distinto y el tiempo delata cuanto se ha acertado."""
    assert con_clave.get("/api/export",
                         headers={"X-Glamdring-Key": "clave-de-prueba-larga-y-fe"}
                         ).status_code == 401


def test_el_frontend_se_sirve_sin_clave(con_clave):
    """La pagina es codigo, no datos. Si tambien pidiera clave, el analista se
    encontraria un 401 en blanco sin sitio donde escribirla."""
    assert con_clave.get("/").status_code == 200


def test_el_receptor_conserva_su_propia_clave(con_clave):
    """Exigir ademas la clave general obligaria a poner las dos en cada
    reenviador -NSS, syslog, webhooks- sin ganar nada: el receptor ya compara
    en tiempo constante y con clave por fuente."""
    assert con_clave.post("/api/receive/netskope").status_code == 200


def test_sin_clave_configurada_todo_sigue_igual():
    """Es OPCIONAL. Sin clave la herramienta funciona como siempre, que es lo
    correcto en el portatil del analista."""
    abierta = FastAPI()

    @abierta.get("/api/export")
    def exportar():
        return {"ok": True}

    montar_seguridad(abierta, clave="")
    assert TestClient(abierta).get("/api/export").status_code == 200
    assert ClaveApiMiddleware not in [m.cls for m in abierta.user_middleware]


def test_el_orden_del_montaje():
    """El orden es la mitad del arreglo, y montarlo del reves no da error.

    El limite de cuerpo tiene que ser el MAS EXTERIOR: si fuera por dentro de la
    clave, un anonimo colaria un fichero de 300 MB y el 401 llegaria cuando ya
    estuviera escrito. `user_middleware` va del mas exterior al mas interior.
    """
    montada = FastAPI()
    montar_seguridad(montada, clave="x")
    orden = [m.cls.__name__ for m in montada.user_middleware]
    assert orden == ["LimiteDeCuerpo", "ClaveApiMiddleware", "OrigenMiddleware"]


def test_la_aplicacion_real_lleva_la_frontera_montada():
    """Que el montaje este puesto en `main`, no solo escrito."""
    montados = {m.cls.__name__ for m in app.user_middleware}
    assert "LimiteDeCuerpo" in montados
    assert "OrigenMiddleware" in montados
    assert MAX_BYTES_PETICION == 50 * 1024 * 1024
