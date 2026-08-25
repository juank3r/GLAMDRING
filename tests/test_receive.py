"""Tests del receptor de logs.

Es el unico endpoint que va a estar escuchando a lo que le manden, asi que lo
que se prueba aqui es sobre todo lo que RECHAZA.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from glamdring.config import SETTINGS
from glamdring.main import app
from glamdring.receive import (LONGITUD_MINIMA_CLAVE, RateLimiter, ReceiveConfig,
                               ReceiveError, authorize, parse_keys)
from glamdring.store import STORE

CLAVE = "T3jHq2vLpZ9wXn4mKd8sRy6bAc1fUgEo"   # 32 caracteres
OTRA = "9zPm4KdQw7sVn2LrTy5bXc8jHf3gUaEo"


@pytest.fixture
def receptor(monkeypatch):
    """Receptor con dos fuentes configuradas."""
    config = ReceiveConfig(keys={"netskope": CLAVE, "zscaler": OTRA},
                           max_bytes=4096, per_minute=1000)
    monkeypatch.setattr(SETTINGS, "receive", config)
    import glamdring.api.routes_receive as rutas
    monkeypatch.setattr(rutas, "_LIMITADOR", RateLimiter(config.per_minute))
    with TestClient(app) as client:
        yield client


LOTE = json.dumps([
    {"EventCode": "4688", "Account_Name": "jlopez", "ComputerName": "wks-0421",
     "New_Process_Name": "C:\\Windows\\System32\\cmd.exe", "_time": "2024-05-02T09:12:00Z"},
])


# ----------------------------------------------------------------- las claves

def test_parse_keys_descarta_las_claves_cortas(caplog):
    """Una clave de cuatro letras deja un endpoint que PARECE protegido."""
    salida = parse_keys(f"netskope:corta,zscaler:{OTRA}")
    assert "netskope" not in salida
    assert salida["zscaler"] == OTRA
    assert "netskope" in caplog.text
    assert "corta" not in caplog.text, "la clave descartada no se registra"


def test_parse_keys_admite_dos_puntos_dentro_de_la_clave():
    clave = "abc:def:" + "x" * LONGITUD_MINIMA_CLAVE
    assert parse_keys(f"fuente:{clave}") == {"fuente": clave}


def test_parse_keys_tolera_basura():
    assert parse_keys("") == {}
    assert parse_keys("sin_dos_puntos") == {}
    assert parse_keys(",,,") == {}


def test_sin_claves_el_receptor_no_existe():
    """Apagado por defecto y sin modo 'sin clave', ni para pruebas."""
    assert ReceiveConfig().enabled is False
    with pytest.raises(ReceiveError) as fallo:
        authorize(ReceiveConfig(), "netskope", CLAVE)
    assert fallo.value.status == 503


def test_fuente_desconocida_da_401_y_no_404():
    """Distinguirlos convertiria el receptor en un listado de integraciones."""
    config = ReceiveConfig(keys={"netskope": CLAVE})
    with pytest.raises(ReceiveError) as desconocida:
        authorize(config, "crowdstrike", CLAVE)
    with pytest.raises(ReceiveError) as mala:
        authorize(config, "netskope", OTRA)
    assert desconocida.value.status == mala.value.status == 401
    assert desconocida.value.message == mala.value.message, (
        "el mensaje tambien tiene que ser el mismo, si no se enumeran igual")


def test_la_clave_de_una_fuente_no_vale_para_otra():
    """Una clave por fuente: si se filtra la de un reenviador, el resto aguanta."""
    config = ReceiveConfig(keys={"netskope": CLAVE, "zscaler": OTRA})
    assert authorize(config, "netskope", CLAVE) == "netskope"
    with pytest.raises(ReceiveError):
        authorize(config, "zscaler", CLAVE)


def test_el_nombre_de_fuente_se_normaliza():
    config = ReceiveConfig(keys={"netskope": CLAVE})
    assert authorize(config, "  NetSkope  ", CLAVE) == "netskope"


# ------------------------------------------------------------------- el ritmo

def test_el_limitador_corta_al_pasarse():
    limitador = RateLimiter(per_minute=3)
    for i in range(3):
        limitador.check("netskope", ahora=100.0 + i)
    with pytest.raises(ReceiveError) as fallo:
        limitador.check("netskope", ahora=103.0)
    assert fallo.value.status == 429
    assert "Reintenta" in fallo.value.message


def test_el_limite_es_por_fuente_no_global():
    """Una fuente pasada de vueltas no puede dejar fuera a las demas."""
    limitador = RateLimiter(per_minute=2)
    limitador.check("netskope", ahora=100.0)
    limitador.check("netskope", ahora=100.1)
    with pytest.raises(ReceiveError):
        limitador.check("netskope", ahora=100.2)
    limitador.check("zscaler", ahora=100.3)  # esta va sobrada


def test_la_ventana_desliza():
    limitador = RateLimiter(per_minute=2)
    limitador.check("netskope", ahora=100.0)
    limitador.check("netskope", ahora=100.5)
    with pytest.raises(ReceiveError):
        limitador.check("netskope", ahora=101.0)
    # Pasado el minuto las dos primeras ya no cuentan.
    limitador.check("netskope", ahora=161.0)


# ------------------------------------------------------------------- la ruta

def test_receive_ingiere_con_la_clave_correcta(receptor):
    respuesta = receptor.post("/api/receive/netskope", content=LOTE,
                              headers={"X-Glamdring-Key": CLAVE})
    assert respuesta.status_code == 200
    cuerpo = respuesta.json()
    assert cuerpo["read"] == 1
    assert cuerpo["normalized"] == 1
    assert cuerpo["source"] == "netskope"
    assert len(STORE) == 1


def test_receive_sin_clave_es_401(receptor):
    respuesta = receptor.post("/api/receive/netskope", content=LOTE)
    assert respuesta.status_code == 401
    assert len(STORE) == 0


def test_receive_con_clave_mala_es_401(receptor):
    respuesta = receptor.post("/api/receive/netskope", content=LOTE,
                              headers={"X-Glamdring-Key": "loquesea"})
    assert respuesta.status_code == 401
    assert len(STORE) == 0


def test_receive_no_filtra_la_clave_en_la_respuesta(receptor):
    respuesta = receptor.post("/api/receive/netskope", content=LOTE,
                              headers={"X-Glamdring-Key": "loquesea"})
    assert CLAVE not in respuesta.text


def test_receive_corta_el_envio_demasiado_grande(receptor):
    grande = "x" * 8192  # el tope de la fixture son 4096
    respuesta = receptor.post("/api/receive/netskope", content=grande,
                              headers={"X-Glamdring-Key": CLAVE})
    assert respuesta.status_code == 413


def test_receive_no_se_fia_del_content_length(receptor):
    """Content-Length lo pone quien envia. Lo que cuenta es lo que llega."""
    grande = "x" * 8192
    respuesta = receptor.post("/api/receive/netskope", content=grande,
                              headers={"X-Glamdring-Key": CLAVE,
                                       "Content-Length": "10"})
    assert respuesta.status_code in (413, 400)


def test_receive_rechaza_antes_de_leer_el_cuerpo(receptor):
    """Sin clave no se traga 50 MB: el 401 llega antes del trabajo caro."""
    grande = "x" * 100_000
    respuesta = receptor.post("/api/receive/netskope", content=grande,
                              headers={"X-Glamdring-Key": "malo"})
    assert respuesta.status_code == 401, "la clave se mira antes que el tamano"


def test_receive_envio_vacio_es_400(receptor):
    respuesta = receptor.post("/api/receive/netskope", content="",
                              headers={"X-Glamdring-Key": CLAVE})
    assert respuesta.status_code == 400


def test_receive_acepta_cef(receptor):
    """NSS emite en el formato que le configures, y CEF es de los habituales."""
    cef = ("CEF:0|Zscaler|NSSWeblog|1.0|200|Allowed|3|src=10.20.3.44 "
           "dst=104.18.32.7 duser=jlopez requestMethod=GET "
           "request=https://mega.nz/upload out=4294967296")
    respuesta = receptor.post("/api/receive/zscaler", content=cef,
                              headers={"X-Glamdring-Key": OTRA})
    assert respuesta.status_code == 200
    assert respuesta.json()["read"] == 1


def test_receive_acepta_ndjson(receptor):
    ndjson = "\n".join(json.dumps({"EventCode": "4624", "Account_Name": f"u{i}",
                                   "ComputerName": "srv-01"}) for i in range(3))
    respuesta = receptor.post("/api/receive/netskope", content=ndjson,
                              headers={"X-Glamdring-Key": CLAVE})
    assert respuesta.status_code == 200
    assert respuesta.json()["read"] == 3


def test_receive_registra_el_origen(receptor):
    """De que fuente vino cada lote queda en el registro de ingestas.

    Importa para el turno siguiente: al mirar un grafo hay que poder decir si
    ese trozo entro por el receptor de Netskope o por una subida a mano.
    """
    receptor.post("/api/receive/netskope", content=LOTE,
                  headers={"X-Glamdring-Key": CLAVE})
    assert any("receive:netskope" in str(linea) for linea in STORE.ingest_log)


def test_receive_respeta_el_ritmo(receptor, monkeypatch):
    import glamdring.api.routes_receive as rutas
    monkeypatch.setattr(rutas, "_LIMITADOR", RateLimiter(per_minute=2))

    for _ in range(2):
        assert receptor.post("/api/receive/netskope", content=LOTE,
                             headers={"X-Glamdring-Key": CLAVE}).status_code == 200
    tercera = receptor.post("/api/receive/netskope", content=LOTE,
                            headers={"X-Glamdring-Key": CLAVE})
    assert tercera.status_code == 429


def test_get_receive_lista_fuentes_pero_nunca_claves(receptor):
    respuesta = receptor.get("/api/receive")
    assert respuesta.status_code == 200
    cuerpo = respuesta.json()
    assert cuerpo["enabled"] is True
    assert cuerpo["sources"] == ["netskope", "zscaler"]
    assert CLAVE not in respuesta.text and OTRA not in respuesta.text


def test_health_no_filtra_las_claves(receptor):
    respuesta = receptor.get("/api/health")
    assert CLAVE not in respuesta.text and OTRA not in respuesta.text
    assert respuesta.json()["connectors"]["receive"]["sources"] == ["netskope", "zscaler"]


def test_receptor_apagado_responde_503():
    """Sin configurar, no es un 404: el que empuja necesita saber que no reintente."""
    with TestClient(app) as client:
        respuesta = client.post("/api/receive/netskope", content=LOTE,
                                headers={"X-Glamdring-Key": CLAVE})
    assert respuesta.status_code == 503
