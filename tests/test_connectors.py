"""Tests del contrato de conectores v2.

POR QUE ESTE FICHERO. Los 324 tests que ya habia pasaban con la migracion a
medias, y no por casualidad: ninguno llega al codigo de Splunk, Sentinel o
QRadar. Como en los tests no hay credenciales, ``/api/query`` responde 409 y se
da la vuelta antes de tocar ``fetch``. O sea que la suite entera decia verde
sobre codigo que contra un SIEM real habria reventado.

Aqui se entra de verdad, con un transporte falso de httpx: se ejerce el
``fetch``, el corte, el ``ping``, el cierre y la reutilizacion del cliente sin
necesidad de un SIEM delante.
"""

from __future__ import annotations

import asyncio
import importlib.machinery
import json
import sys
import time
import types

import httpx
import pytest

from glamdring.config import QRadarConfig, SentinelConfig, SplunkConfig
from glamdring.connectors import FetchResult, close_all, get_connector, ping_all, reset_cache
from glamdring.connectors.base import ConnectorError
from glamdring.connectors.files import FileConnector
from glamdring.connectors.qradar import QRadarConnector, _total_de
from glamdring.connectors.sentinel import SentinelConnector
from glamdring.connectors.splunk import SplunkConnector


def con_transporte(conector, manejador):
    """Mete un transporte falso conservando el resto de los kwargs reales.

    Se pisa ``_client_kwargs`` y no ``_client`` para que el test siga pasando
    por la logica de reutilizacion y de cambio de bucle, que es justo lo que
    interesa comprobar.
    """
    original = conector._client_kwargs

    def parcheado():
        kwargs = original()
        kwargs["transport"] = httpx.MockTransport(manejador)
        kwargs.pop("verify", None)  # el transporte falso no negocia TLS
        return kwargs

    conector._client_kwargs = parcheado
    return conector


def ndjson_splunk(cuantos: int, basura: int = 0) -> str:
    lineas = [json.dumps({"preview": False, "result": {"_raw": f"evento {i}", "host": f"h{i}"}})
              for i in range(cuantos)]
    lineas.extend("{esto no es json" for _ in range(basura))
    return "\n".join(lineas)


# --------------------------------------------------------------- FetchResult

def test_fetchresult_vacio_no_inventa_campos():
    salida = FetchResult().as_dict()
    assert salida == {"fetched": 0, "truncated": False}
    # total None NO es total 0: uno significa "no lo ha dicho" y el otro "no
    # habia nada". Colarlo como 0 seria afirmar algo que el SIEM no ha dicho.
    assert "total" not in salida


def test_fetchresult_lleva_la_cuenta():
    salida = FetchResult(records=[{"a": 1}, {"a": 2}], truncated=True, total=900,
                         cursor="abc", warnings=["ojo"])
    assert len(salida) == 2
    assert salida.as_dict() == {"fetched": 2, "truncated": True, "total": 900,
                                "cursor": "abc", "warnings": ["ojo"]}


# -------------------------------------------------------------------- Splunk

@pytest.mark.asyncio
async def test_splunk_marca_truncado_cuando_hay_mas():
    """El SIEM tenia mas de los pedidos y hay que decirlo.

    Es el motivo entero del contrato v2: antes esto y "habia exactamente 5"
    devolvian la misma lista de 5 y el analista no podia distinguirlos.
    """
    pedido = {}

    def manejador(request: httpx.Request) -> httpx.Response:
        pedido["count"] = dict(httpx.QueryParams(request.content.decode()))["count"]
        # Devolvemos los 6 que caben en count=6 (limite 5 + testigo).
        return httpx.Response(200, text=ndjson_splunk(6))

    conector = con_transporte(SplunkConnector(SplunkConfig(url="https://splunk.test:8089",
                                                           token="t")), manejador)
    salida = await conector.fetch("index=x", limit=5)
    await conector.close()

    assert pedido["count"] == "6", "hay que pedir uno mas para saber si sobran"
    assert len(salida.records) == 5, "el testigo no se entrega"
    assert salida.truncated is True


@pytest.mark.asyncio
async def test_splunk_no_marca_truncado_cuando_cabe_todo():
    def manejador(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=ndjson_splunk(3))

    conector = con_transporte(SplunkConnector(SplunkConfig(url="https://splunk.test:8089",
                                                           token="t")), manejador)
    salida = await conector.fetch("index=x", limit=5)
    await conector.close()

    assert len(salida.records) == 3
    assert salida.truncated is False
    assert salida.warnings == []


@pytest.mark.asyncio
async def test_splunk_avisa_de_las_lineas_que_no_entiende():
    """Tragarse lineas ilegibles en silencio es perder eventos sin decirlo."""
    def manejador(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=ndjson_splunk(2, basura=3))

    conector = con_transporte(SplunkConnector(SplunkConfig(url="https://splunk.test:8089",
                                                           token="t")), manejador)
    salida = await conector.fetch("index=x", limit=100)
    await conector.close()

    assert len(salida.records) == 2
    assert salida.warnings and "3 lineas" in salida.warnings[0]


@pytest.mark.asyncio
async def test_splunk_usa_el_esquema_splunk_no_bearer():
    """Un token de Splunk con 'Bearer' delante lo rechaza el propio Splunk."""
    visto = {}

    def manejador(request: httpx.Request) -> httpx.Response:
        visto["auth"] = request.headers.get("authorization")
        return httpx.Response(200, text=ndjson_splunk(1))

    conector = con_transporte(SplunkConnector(SplunkConfig(url="https://splunk.test:8089",
                                                           token="secreto")), manejador)
    await conector.fetch("index=x", limit=10)
    await conector.close()
    assert visto["auth"] == "Splunk secreto"


@pytest.mark.asyncio
async def test_splunk_error_http_se_convierte_en_connectorerror():
    def manejador(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="Service Unavailable")

    conector = con_transporte(SplunkConnector(SplunkConfig(url="https://splunk.test:8089",
                                                           token="t")), manejador)
    with pytest.raises(ConnectorError) as fallo:
        await conector.fetch("index=x", limit=10)
    await conector.close()
    assert fallo.value.status == 503


@pytest.mark.asyncio
async def test_splunk_reutiliza_el_cliente_entre_consultas():
    """El pool TLS existe para no repetir el apreton de manos en cada consulta."""
    def manejador(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=ndjson_splunk(1))

    conector = con_transporte(SplunkConnector(SplunkConfig(url="https://splunk.test:8089",
                                                           token="t")), manejador)
    await conector.fetch("index=x", limit=10)
    primero = conector._cliente
    await conector.fetch("index=y", limit=10)
    assert conector._cliente is primero

    await conector.close()
    assert conector._cliente is None, "close deja el conector limpio"


@pytest.mark.asyncio
async def test_splunk_abre_cliente_nuevo_si_el_de_antes_esta_cerrado():
    def manejador(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=ndjson_splunk(1))

    conector = con_transporte(SplunkConnector(SplunkConfig(url="https://splunk.test:8089",
                                                           token="t")), manejador)
    await conector.fetch("index=x", limit=10)
    viejo = conector._cliente
    await viejo.aclose()
    conector._cliente = viejo  # simula el cliente cerrado por fuera

    await conector.fetch("index=x", limit=10)
    assert conector._cliente is not viejo
    await conector.close()


@pytest.mark.asyncio
async def test_splunk_ping_distingue_credenciales_malas_de_caida():
    def rechaza(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="unauthorized")

    conector = con_transporte(SplunkConnector(SplunkConfig(url="https://splunk.test:8089",
                                                           token="malo")), rechaza)
    salud = await conector.ping()
    await conector.close()

    assert salud.ok is False
    assert salud.probed is True, "se ha preguntado de verdad"
    assert "rechazadas" in salud.detail.lower()


@pytest.mark.asyncio
async def test_splunk_ping_sin_configurar_no_finge_haber_probado():
    conector = SplunkConnector(SplunkConfig())
    salud = await conector.ping()
    assert salud.ok is False
    assert salud.probed is False, "sin credenciales no se ha llegado a preguntar"


# -------------------------------------------------------------------- QRadar

def test_qradar_lee_el_total_del_content_range():
    assert _total_de("items 0-49/1000") == 1000
    assert _total_de("items 0-0/1") == 1
    assert _total_de(None) is None
    assert _total_de("basura") is None


@pytest.mark.asyncio
async def test_qradar_pide_uno_mas_y_reporta_el_total():
    """QRadar es el unico de los cuatro que dice cuantos habia de verdad."""
    rangos = []

    def manejador(request: httpx.Request) -> httpx.Response:
        ruta = request.url.path
        if ruta.endswith("/api/ariel/searches") and request.method == "POST":
            return httpx.Response(201, json={"search_id": "s1"})
        if ruta.endswith("/api/ariel/searches/s1"):
            return httpx.Response(200, json={"status": "COMPLETED"})
        if ruta.endswith("/results"):
            rangos.append(request.headers.get("range"))
            filas = [{"sourceip": f"10.0.0.{i}"} for i in range(4)]
            return httpx.Response(200, json={"events": filas},
                                  headers={"Content-Range": "items 0-3/40000"})
        return httpx.Response(404)

    conector = con_transporte(QRadarConnector(QRadarConfig(url="https://qradar.test",
                                                           token="t")), manejador)
    salida = await conector.fetch("SELECT * FROM events", limit=3)
    await conector.close()

    assert rangos == ["items=0-3"], "items=0-3 son cuatro: tres y el testigo"
    assert len(salida.records) == 3
    assert salida.truncated is True
    assert salida.total == 40000


@pytest.mark.asyncio
async def test_qradar_respuesta_sin_arrays_conocidos_avisa_en_vez_de_callar():
    def manejador(request: httpx.Request) -> httpx.Response:
        ruta = request.url.path
        if ruta.endswith("/api/ariel/searches") and request.method == "POST":
            return httpx.Response(201, json={"search_id": "s1"})
        if ruta.endswith("/api/ariel/searches/s1"):
            return httpx.Response(200, json={"status": "COMPLETED"})
        return httpx.Response(200, json={"algo_raro": []})

    conector = con_transporte(QRadarConnector(QRadarConfig(url="https://qradar.test",
                                                           token="t")), manejador)
    salida = await conector.fetch("SELECT * FROM events", limit=5)
    await conector.close()

    assert salida.records == []
    assert salida.warnings, "devolver cero sin explicacion no vale"


@pytest.mark.asyncio
async def test_qradar_busqueda_en_error_no_devuelve_lista_vacia():
    """Una busqueda fallida y una sin resultados NO son lo mismo."""
    def manejador(request: httpx.Request) -> httpx.Response:
        ruta = request.url.path
        if ruta.endswith("/api/ariel/searches") and request.method == "POST":
            return httpx.Response(201, json={"search_id": "s1"})
        return httpx.Response(200, json={"status": "ERROR"})

    conector = con_transporte(QRadarConnector(QRadarConfig(url="https://qradar.test",
                                                           token="t")), manejador)
    with pytest.raises(ConnectorError, match="ERROR"):
        await conector.fetch("SELECT * FROM events", limit=5)
    await conector.close()


@pytest.mark.asyncio
async def test_qradar_ping_explica_la_version_mal_puesta():
    """El 422 de QRadar a secas no sugiere que el problema es la cabecera Version."""
    def manejador(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, text="unsupported version")

    conector = con_transporte(QRadarConnector(QRadarConfig(url="https://qradar.test",
                                                           token="t", api_version="99.0")),
                              manejador)
    salud = await conector.ping()
    await conector.close()

    assert salud.ok is False
    assert "99.0" in salud.detail


# ------------------------------------------------------------------ Sentinel

class _EstadoFalso:
    SUCCESS = "Success"
    PARTIAL = "PartialError"
    FAILURE = "Failure"


class _TablaFalsa:
    def __init__(self, filas):
        self.name = "DeviceProcessEvents"
        self.columns = ["TimeGenerated", "DeviceName"]
        self.rows = filas


class _RespuestaFalsa:
    def __init__(self, filas, status=_EstadoFalso.SUCCESS, partial_error=""):
        self.tables = [_TablaFalsa(filas)]
        self.status = status
        self.partial_error = partial_error


@pytest.fixture
def sdk_azure_falso(monkeypatch):
    """Instala un azure-monitor-query de mentira que BLOQUEA al consultar.

    Bloquear es el punto: es lo que hace el SDK de verdad, y es lo que permite
    comprobar que la consulta se va a un hilo en vez de parar el bucle.
    """
    espera = {"segundos": 0.0, "filas": [["2024-01-01T00:00:00Z", "wks-1"]],
              "status": _EstadoFalso.SUCCESS, "partial_error": ""}

    class LogsQueryClientFalso:
        def __init__(self, credential):
            self.credential = credential

        def query_workspace(self, **kwargs):
            time.sleep(espera["segundos"])   # sincrono a proposito
            return _RespuestaFalsa(espera["filas"], espera["status"], espera["partial_error"])

    def modulo(nombre, **atributos):
        m = types.ModuleType(nombre)
        m.__spec__ = importlib.machinery.ModuleSpec(nombre, loader=None)
        for clave, valor in atributos.items():
            setattr(m, clave, valor)
        return m

    azure = modulo("azure")
    azure.__path__ = []
    monitor = modulo("azure.monitor")
    monitor.__path__ = []
    query = modulo("azure.monitor.query",
                   LogsQueryClient=LogsQueryClientFalso,
                   LogsQueryStatus=_EstadoFalso)
    identity = modulo("azure.identity",
                      ClientSecretCredential=lambda **k: "cred-explicita",
                      DefaultAzureCredential=lambda: "cred-por-defecto")

    for nombre, mod in (("azure", azure), ("azure.monitor", monitor),
                        ("azure.monitor.query", query), ("azure.identity", identity)):
        monkeypatch.setitem(sys.modules, nombre, mod)

    return espera


@pytest.mark.asyncio
async def test_sentinel_no_congela_el_bucle_mientras_consulta(sdk_azure_falso):
    """LA REGRESION QUE IMPORTA.

    query_workspace es sincrono. Llamandolo dentro de una corrutina no se
    ralentiza esa consulta: se para el BUCLE ENTERO, y con el el frontend,
    /api/health y la consulta del companero de turno. Hasta 120 segundos.

    Aqui se mide directamente: mientras la consulta duerme medio segundo, un
    latido intenta correr cada 10 ms. Con asyncio.to_thread avanza; sin el, se
    queda clavado y este test se pone rojo.
    """
    sdk_azure_falso["segundos"] = 0.5

    latidos = {"n": 0}

    async def latir():
        while True:
            latidos["n"] += 1
            await asyncio.sleep(0.01)

    conector = SentinelConnector(SentinelConfig(workspace_id="w1"))
    tarea = asyncio.create_task(latir())
    await asyncio.sleep(0)  # que arranque el latido antes de la consulta

    salida = await conector.fetch("DeviceProcessEvents | take 10", limit=100)

    tarea.cancel()
    assert len(salida.records) == 1
    # Bloqueando el bucle no pasaria de 1 o 2. En un hilo, ~50.
    assert latidos["n"] > 10, (
        f"el bucle se quedo parado durante la consulta (solo {latidos['n']} latidos): "
        "query_workspace se esta llamando sin asyncio.to_thread")


@pytest.mark.asyncio
async def test_sentinel_inyecta_el_nombre_de_tabla(sdk_azure_falso):
    """Las filas de Log Analytics no traen Type y el normalizador lo necesita."""
    conector = SentinelConnector(SentinelConfig(workspace_id="w1"))
    salida = await conector.fetch("DeviceProcessEvents", limit=10)
    assert salida.records[0]["Type"] == "DeviceProcessEvents"


@pytest.mark.asyncio
async def test_sentinel_avisa_del_resultado_parcial(sdk_azure_falso):
    """Log Analytics corta por tamano y lo dice SOLO aqui."""
    sdk_azure_falso["status"] = _EstadoFalso.PARTIAL
    sdk_azure_falso["partial_error"] = "Query result set has exceeded the internal record count"

    conector = SentinelConnector(SentinelConfig(workspace_id="w1"))
    salida = await conector.fetch("DeviceProcessEvents", limit=10)

    assert salida.warnings
    assert "PARCIAL" in salida.warnings[0]


@pytest.mark.asyncio
async def test_sentinel_consulta_fallida_es_error_no_lista_vacia(sdk_azure_falso):
    sdk_azure_falso["status"] = _EstadoFalso.FAILURE
    conector = SentinelConnector(SentinelConfig(workspace_id="w1"))
    with pytest.raises(ConnectorError):
        await conector.fetch("KQL invalida", limit=10)


@pytest.mark.asyncio
async def test_sentinel_corta_por_limite_y_lo_marca(sdk_azure_falso):
    """Log Analytics no acepta un tope por parametro: el corte es nuestro."""
    sdk_azure_falso["filas"] = [["t", f"wks-{i}"] for i in range(10)]
    conector = SentinelConnector(SentinelConfig(workspace_id="w1"))
    salida = await conector.fetch("DeviceProcessEvents", limit=4)

    assert len(salida.records) == 4
    assert salida.truncated is True


def test_sentinel_configured_no_se_conforma_con_el_workspace(monkeypatch):
    """El semaforo verde con un workspace y nada mas era una mentira.

    Sin SDK y sin las variables de Entra ID no hay ninguna via de
    autenticacion: la consulta falla siempre. El analista escribia su KQL,
    esperaba, y recibia un error de credenciales que el semaforo llevaba rato
    asegurando que no existia.
    """
    import glamdring.config as config
    monkeypatch.setattr(config, "_sdk_azure_disponible", lambda: False)

    assert SentinelConfig(workspace_id="w1").configured is False
    assert SentinelConfig(workspace_id="w1", tenant_id="t", client_id="c",
                          client_secret="s").configured is True

    # Con el SDK puesto si vale solo el workspace: DefaultAzureCredential sabe
    # sacar las credenciales de az login o de una identidad administrada.
    monkeypatch.setattr(config, "_sdk_azure_disponible", lambda: True)
    assert SentinelConfig(workspace_id="w1").configured is True

    # Sin workspace no hay nada que hacer, haya lo que haya instalado.
    assert SentinelConfig().configured is False


# --------------------------------------------------------------------- files

@pytest.mark.asyncio
async def test_files_devuelve_fetchresult_con_el_total():
    conector = FileConnector()
    salida = await conector.fetch("minimo/incidente.json", limit=2)
    assert isinstance(salida, FetchResult)
    assert len(salida.records) == 2
    assert salida.total is not None and salida.total > 2
    assert salida.truncated is True


@pytest.mark.asyncio
async def test_files_ping_comprueba_de_verdad():
    salud = await FileConnector().ping()
    assert salud.ok is True
    assert salud.probed is True


# ------------------------------------------------------------------ registro

@pytest.mark.asyncio
async def test_ping_all_devuelve_los_cuatro_y_no_revienta():
    """Un SIEM caido no puede tumbar el semaforo de los demas."""
    reset_cache()
    salida = await ping_all()
    assert set(salida) == {"splunk", "sentinel", "qradar", "files"}
    assert salida["files"]["ok"] is True
    for nombre, estado in salida.items():
        assert "probed" in estado, f"{nombre} no dice si se ha comprobado"
    await close_all()


@pytest.mark.asyncio
async def test_ping_all_cuenta_como_rojo_el_que_revienta(monkeypatch):
    conector = get_connector("splunk")

    async def explota():
        raise RuntimeError("boom")

    monkeypatch.setattr(conector, "ping", explota)
    salida = await ping_all()
    assert salida["splunk"]["ok"] is False
    assert "boom" in salida["splunk"]["detail"]
    # Los demas siguen contestando.
    assert salida["files"]["ok"] is True
    reset_cache()


def test_describe_all_publica_si_hay_cursor():
    for ficha in get_connector("files").describe(), get_connector("splunk").describe():
        assert "supportsCursor" in ficha
    reset_cache()
