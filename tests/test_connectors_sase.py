"""Conectores de los proxies SASE, con transporte falso.

Igual que ``test_connectors.py``: aqui se ENTRA en el codigo del conector. Sin
esto, un conector nuevo pasaria la suite entera sin que nadie haya ejecutado una
sola linea suya, que es exactamente lo que pasaba con Splunk y QRadar.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import httpx
import pytest

from glamdring.config import NetskopeConfig, ZscalerZpaConfig
from glamdring.connectors import _FACTORIES
from glamdring.connectors.base import ConnectorError
from glamdring.connectors.netskope import NetskopeConnector
from glamdring.connectors.zscaler_zpa import ZscalerZpaConnector
from tests.test_connectors import con_transporte


def _netskope(manejador, **kwargs):
    config = NetskopeConfig(url="https://tenant.goskope.com", token="tok", **kwargs)
    return con_transporte(NetskopeConnector(config), manejador)


def _zpa(manejador):
    config = ZscalerZpaConfig(url="https://zpa.test", client_id="c",
                              client_secret="s", customer_id="123")
    return con_transporte(ZscalerZpaConnector(config), manejador)


def _con_signin(respuesta_datos):
    """Manejador que responde al /signin y despues a la consulta."""
    def manejador(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/signin"):
            return httpx.Response(200, json={"access_token": "t0k",
                                             "expires_in": "3600000"})
        return respuesta_datos(request)
    return manejador


# ------------------------------------------------------------------ Netskope

@pytest.mark.asyncio
async def test_netskope_usa_el_iterador_y_lo_devuelve_como_cursor():
    """A Netskope no se le piden fechas: se le pide 'lo siguiente'.

    Es el motivo por el que el contrato v2 lleva cursor. Y tiene una
    consecuencia que conviene tener presente: CADA LLAMADA AVANZA EL PUNTERO. Si
    se pide dos veces con el mismo iterador no salen los mismos eventos, salen
    los SIGUIENTES. Por eso el cursor se devuelve en vez de esconderlo.
    """
    visto = {}

    def manejador(request: httpx.Request) -> httpx.Response:
        visto["params"] = dict(request.url.params)
        visto["auth"] = request.headers.get("netskope-api-token")
        return httpx.Response(200, json={"result": [{"app": "Mega", "activity": "Upload"}]})

    conector = _netskope(manejador, iterator="glamdring")
    salida = await conector.fetch("application", limit=100)
    await conector.close()

    assert visto["auth"] == "tok", "el token va en cabecera propia, no como Bearer"
    assert visto["params"]["operation"] == "next"
    assert visto["params"]["index"] == "glamdring"
    assert salida.cursor == "glamdring"
    assert len(salida.records) == 1


@pytest.mark.asyncio
async def test_netskope_con_fecha_no_avanza_el_iterador():
    """Investigar hacia atras tiene que ser repetible.

    Pedir dos veces la misma ventana temporal tiene que dar lo mismo, y con el
    iterador no lo daria: daria lo siguiente.
    """
    visto = {}

    def manejador(request: httpx.Request) -> httpx.Response:
        visto["op"] = dict(request.url.params)["operation"]
        return httpx.Response(200, json={"result": []})

    conector = _netskope(manejador)
    salida = await conector.fetch("application",
                                  time_from=datetime(2026, 8, 19, tzinfo=timezone.utc),
                                  limit=10)
    await conector.close()

    assert visto["op"] != "next", "con ventana temporal no se usa el iterador"
    assert any("no avanza el iterador" in a for a in salida.warnings)


@pytest.mark.asyncio
async def test_netskope_traslada_el_retry_after():
    """Netskope limita el ritmo por iterador y dice cuanto esperar.

    Reintentar antes solo consigue que el siguiente rechazo tarde mas, asi que
    el numero que da el servidor se traslada tal cual en vez de tragarselo.
    """
    def manejador(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "17"}, text="slow down")

    conector = _netskope(manejador)
    with pytest.raises(ConnectorError) as fallo:
        await conector.fetch("application", limit=10)
    await conector.close()

    assert fallo.value.status == 429
    assert "17" in fallo.value.message


@pytest.mark.asyncio
async def test_netskope_rechaza_un_tipo_de_evento_inventado():
    conector = NetskopeConnector(NetskopeConfig(url="https://t.goskope.com", token="tok"))
    with pytest.raises(ConnectorError, match="desconocido"):
        await conector.fetch("loquesea", limit=10)


@pytest.mark.asyncio
async def test_netskope_rechaza_un_iterador_con_caracteres_raros():
    """El nombre del iterador acaba dentro de la URL: solo lo previsible."""
    conector = NetskopeConnector(NetskopeConfig(url="https://t.goskope.com", token="tok"))
    with pytest.raises(ConnectorError, match="iterador"):
        await conector.fetch("application", cursor="../../otra/cosa", limit=10)


@pytest.mark.asyncio
async def test_netskope_ping_no_consume_eventos():
    """Un semaforo no puede tener efectos secundarios sobre los datos.

    Preguntar por 'next' avanzaria el puntero: comprobar que el servicio
    responde se habria llevado por delante un lote de eventos, y nadie
    sospecharia de la comprobacion.
    """
    visto = {}

    def manejador(request: httpx.Request) -> httpx.Response:
        visto["op"] = dict(request.url.params).get("operation")
        return httpx.Response(200, json={"result": []})

    conector = _netskope(manejador)
    salud = await conector.ping()
    await conector.close()

    assert visto["op"] != "next", "el ping NO puede avanzar el iterador"
    assert salud.ok is True and salud.probed is True


@pytest.mark.asyncio
async def test_netskope_el_limite_de_ritmo_cuenta_como_vivo():
    """Que limite el ritmo significa que ha entendido la peticion."""
    def manejador(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="slow down")

    conector = _netskope(manejador)
    salud = await conector.ping()
    await conector.close()
    assert salud.ok is True


@pytest.mark.asyncio
async def test_netskope_token_rechazado_explica_lo_del_ambito():
    """El ambito del token se fija AL CREARLO, y es el fallo mas comun."""
    def manejador(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    conector = _netskope(manejador)
    with pytest.raises(ConnectorError, match="ambito"):
        await conector.fetch("application", limit=10)
    await conector.close()


# --------------------------------------------------------------- Zscaler ZPA

@pytest.mark.asyncio
async def test_zpa_lee_expires_in_como_milisegundos():
    """LA API DE ZPA DA expires_in EN MILISEGUNDOS, no en segundos.

    Tratarlo como segundos daria un token 'valido' durante mes y medio y
    despues una racha de 401 que parecen un problema de credenciales y no lo
    son: el token llevaba caducado desde hacia rato y nadie lo renovaba.
    """
    conector = _zpa(_con_signin(lambda r: httpx.Response(200, json={"list": [], "totalCount": 0})))
    await conector.fetch("user_activity", limit=10)

    restante = conector._token_expira - time.monotonic()
    # 3.600.000 ms son 3.600 s; con el margen de 60 quedan ~3.540.
    assert 3000 < restante < 3600, f"la caducidad salio de {restante:.0f}s"
    await conector.close()


@pytest.mark.asyncio
async def test_zpa_reutiliza_el_token_entre_consultas():
    """Pedir un token nuevo en cada consulta es una llamada de mas por consulta."""
    llamadas = {"signin": 0}

    def manejador(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/signin"):
            llamadas["signin"] += 1
            return httpx.Response(200, json={"access_token": "t0k", "expires_in": "3600000"})
        return httpx.Response(200, json={"list": [], "totalCount": 0})

    conector = _zpa(manejador)
    await conector.fetch("user_activity", limit=10)
    await conector.fetch("user_activity", limit=10)
    await conector.close()
    assert llamadas["signin"] == 1


@pytest.mark.asyncio
async def test_zpa_pagina_con_cursor():
    def datos(request: httpx.Request) -> httpx.Response:
        filas = [{"user": f"u{i}"} for i in range(5)]
        return httpx.Response(200, json={"list": filas, "totalCount": 500})

    conector = _zpa(_con_signin(datos))
    salida = await conector.fetch("user_activity", limit=10)
    await conector.close()

    assert salida.total == 500
    assert salida.truncated is True
    assert salida.cursor == "2", "hay mas paginas y se dice por donde seguir"


@pytest.mark.asyncio
async def test_zpa_un_401_invalida_el_token_cacheado():
    """Si no, se reintentaria eternamente con un token que ya no vale."""
    conector = _zpa(_con_signin(lambda r: httpx.Response(401, text="expired")))
    with pytest.raises(ConnectorError):
        await conector.fetch("user_activity", limit=10)
    assert conector._token is None, "un token caducado no se puede quedar cacheado"
    await conector.close()


@pytest.mark.asyncio
async def test_zpa_avisa_cuando_la_respuesta_no_cuadra():
    """Los nombres de campo estan sin comprobar contra un ZPA real.

    Asi que si no cuadran tiene que decirlo, no devolver cero en silencio. Cero
    eventos y cero eventos que no supimos leer se ven igual en pantalla.
    """
    conector = _zpa(_con_signin(lambda r: httpx.Response(200, json={"algo": "distinto"})))
    salida = await conector.fetch("user_activity", limit=10)
    await conector.close()

    assert salida.records == []
    assert salida.warnings, "devolver cero sin explicacion no vale"


@pytest.mark.asyncio
async def test_zpa_ping_no_pide_datos():
    """Si ZPA da el token, la URL resuelve, el TLS cuadra y las credenciales
    valen. Pedir ademas eventos seria pagar una llamada de mas."""
    rutas = []

    def manejador(request: httpx.Request) -> httpx.Response:
        rutas.append(request.url.path)
        return httpx.Response(200, json={"access_token": "t0k", "expires_in": "3600000"})

    conector = _zpa(manejador)
    salud = await conector.ping()
    await conector.close()

    assert salud.ok is True and salud.probed is True
    assert all(r.endswith("/signin") for r in rutas)


def test_zia_no_tiene_conector_y_es_a_proposito():
    """Los logs web de ZIA no salen por API: los empuja NSS al receptor.

    No es una limitacion nuestra, es como funciona el producto. Que no haya
    conector de 'zscaler_zia' no es un olvido, y este test esta aqui para que
    nadie lo anada creyendo que si.
    """
    assert "zscaler_zia" not in _FACTORIES
    assert "zscaler_zpa" in _FACTORIES
