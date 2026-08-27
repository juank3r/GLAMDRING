"""La API HTTP, con TestClient. No hace falta ningun SIEM."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from glamdring.config import SAMPLES_DIR
from glamdring.main import app
from glamdring.store import STORE


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def loaded(client):
    """Cliente con el incidente de ejemplo ya ingerido."""
    response = client.post("/api/demo")
    assert response.status_code == 200
    return client


# --------------------------------------------------------------------- meta


def test_health_without_data(client):
    payload = client.get("/api/health").json()
    assert payload["status"] == "ok"
    assert payload["events"] == 0
    assert "connectors" in payload


def test_ontology_is_served(client):
    payload = client.get("/api/ontology").json()
    assert "entities" in payload and "relations" in payload
    assert payload["entities"]["host"]["color"]
    assert "lateral-movement" in payload["tactics"]


def test_connectors_listed(client):
    payload = client.get("/api/connectors").json()
    names = {c["name"] for c in payload["connectors"]}
    # La lista se compara con el REGISTRO, no con una copia escrita a mano:
    # clavarla aqui obliga a tocar el test cada vez que se anade una fuente, y
    # eso no es un fallo. Lo que si importa es que la API publique todo lo que
    # hay registrado y nada mas.
    from glamdring.connectors import _FACTORIES
    assert names == set(_FACTORIES)
    # Y las cuatro de siempre tienen que seguir estando.
    assert {"splunk", "sentinel", "qradar", "files"} <= names
    # El conector de ficheros siempre esta disponible.
    files = [c for c in payload["connectors"] if c["name"] == "files"][0]
    assert files["configured"] is True


def test_health_never_leaks_secrets(client):
    body = client.get("/api/health").text.lower()
    for forbidden in ("password", "client_secret", "splunk_token", "qradar_token"):
        assert forbidden not in body


# ------------------------------------------------------------------- ingesta


def test_demo_loads_all_samples(client):
    payload = client.post("/api/demo").json()
    assert payload["events"] > 40
    # El numero exacto se cuenta, no se fija a mano: cada fuente nueva anade su
    # muestra y clavarlo aqui obliga a tocar el test por algo que no es un
    # fallo. Lo que si importa es que TODAS entren y ninguna se quede fuera.
    esperadas = sorted(f.name for f in SAMPLES_DIR.iterdir()
                       if f.is_file() and f.suffix.lower() in
                       (".json", ".ndjson", ".csv", ".cef", ".log", ".txt"))
    assert sorted(f["file"] for f in payload["files"]) == esperadas
    assert not [f for f in payload["files"] if f.get("error")], "alguna muestra no se pudo leer"
    assert payload["totals"]["unmatched"] == 0
    assert all("error" not in item for item in payload["files"])


def test_ingest_uploaded_json(client):
    records = [{
        "_time": "2026-08-19T09:00:00Z",
        "sourcetype": "WinEventLog:Security",
        "EventCode": "4624",
        "Account_Name": "CORP\\ana",
        "ComputerName": "WKS-0100",
        "Logon_Type": "2",
    }]
    response = client.post(
        "/api/ingest",
        files={"file": ("export.json", json.dumps(records), "application/json")},
    )
    payload = response.json()
    assert response.status_code == 200
    assert payload["added"] == 1
    assert payload["format"] == "json"


def test_ingest_cef_text(client):
    line = ("CEF:0|Fortinet|FortiGate|7.4|13|Traffic Allowed|4|"
            "src=10.0.0.5 dst=1.2.3.4 dpt=443 act=accept suser=ana")
    response = client.post("/api/ingest", data={"text": line})
    payload = response.json()
    assert payload["added"] == 1
    assert payload["format"] == "cef"


def test_ingest_deduplicates(client):
    records = [{
        "_time": "2026-08-19T09:00:00Z",
        "sourcetype": "WinEventLog:Security",
        "EventCode": "4624",
        "Account_Name": "CORP\\ana",
        "ComputerName": "WKS-0100",
    }]
    body = json.dumps(records)
    client.post("/api/ingest", files={"file": ("a.json", body, "application/json")})
    second = client.post("/api/ingest", files={"file": ("a.json", body, "application/json")}).json()
    assert second["added"] == 0
    assert second["duplicates"] == 1


def test_ingest_without_payload_is_400(client):
    assert client.post("/api/ingest", data={}).status_code == 400


def test_ingest_redacts_secrets(client):
    records = [{
        "_time": "2026-08-19T09:00:00Z",
        "sourcetype": "generic:app",
        "user": "ana",
        "password": "SuperSecreto123",
        "api_key": "ak_live_0001",
        "message": "login",
    }]
    client.post("/api/ingest", files={"file": ("a.json", json.dumps(records), "application/json")})
    event = STORE.events[0]
    assert event.raw["password"] == "***redactado***"
    assert event.raw["api_key"] == "***redactado***"
    assert event.raw["user"] == "ana"


def test_reset_empties_the_store(loaded):
    assert loaded.get("/api/health").json()["events"] > 0
    loaded.post("/api/reset")
    assert loaded.get("/api/health").json()["events"] == 0


# --------------------------------------------------------------------- grafo


def test_graph_shape(loaded):
    payload = loaded.get("/api/graph").json()
    assert payload["nodes"] and payload["links"]

    node = payload["nodes"][0]
    # Nombres en camelCase: son los que espera 3d-force-graph.
    for key in ("id", "type", "label", "firstSeen", "lastSeen", "eventCount",
                "maxSeverity", "risk", "sources", "props"):
        assert key in node

    link = payload["links"][0]
    for key in ("id", "source", "target", "type", "count", "eventUids"):
        assert key in link

    assert payload["meta"]["counts"]["events"] > 0


def test_graph_severity_filter_reduces(loaded):
    everything = loaded.get("/api/graph").json()
    critical = loaded.get("/api/graph", params={"minSeverity": 5}).json()
    assert len(critical["nodes"]) < len(everything["nodes"])
    assert critical["meta"]["counts"]["events"] < everything["meta"]["counts"]["events"]


def test_graph_type_filter(loaded):
    payload = loaded.get("/api/graph", params={"types": "user,host"}).json()
    assert {node["type"] for node in payload["nodes"]} <= {"user", "host"}


def test_graph_text_filter(loaded):
    payload = loaded.get("/api/graph", params={"q": "certutil"}).json()
    assert payload["nodes"]
    assert payload["meta"]["counts"]["events"] >= 1


def test_graph_focus_and_hops(loaded):
    full = loaded.get("/api/graph").json()
    assert any(node["id"] == "host:wks-0421" for node in full["nodes"])

    focused = loaded.get("/api/graph", params={"focus": "host:wks-0421", "hops": 1}).json()
    assert len(focused["nodes"]) < len(full["nodes"])
    assert any(node["id"] == "host:wks-0421" for node in focused["nodes"])


def test_graph_nodes_have_killchain_level(loaded):
    payload = loaded.get("/api/graph").json()
    assert all("level" in node["props"] for node in payload["nodes"])


def test_neighbors_endpoint(loaded):
    payload = loaded.get("/api/graph/neighbors",
                         params={"node": "host:wks-0421", "hops": 1}).json()
    assert any(node["id"] == "host:wks-0421" for node in payload["nodes"])


def test_neighbors_unknown_node_is_404(loaded):
    response = loaded.get("/api/graph/neighbors", params={"node": "host:no-existe"})
    assert response.status_code == 404


# ------------------------------------------------------------------ timeline


def test_timeline_endpoint(loaded):
    payload = loaded.get("/api/timeline", params={"buckets": 40}).json()
    assert payload["buckets"]
    assert payload["bucketSeconds"] >= 1
    assert all({"t", "count", "maxSeverity"} <= set(bucket) for bucket in payload["buckets"])


# -------------------------------------------------------------- logs crudos


def test_events_by_node_returns_raw_logs(loaded):
    payload = loaded.get("/api/events", params={"node": "host:wks-0421", "limit": 5}).json()
    assert payload["count"] > 0
    event = payload["events"][0]
    assert event["raw"], "el log original tiene que viajar entero"
    assert "time" in event and "source" in event


def test_events_by_uid(loaded):
    graph = loaded.get("/api/graph").json()
    link = [l for l in graph["links"] if l["eventUids"]][0]
    payload = loaded.get("/api/events", params={"uids": ",".join(link["eventUids"][:3])}).json()
    assert payload["count"] == len(link["eventUids"][:3])


def test_events_requires_a_selector(loaded):
    assert loaded.get("/api/events").status_code == 400


# ------------------------------------------------------------------ consulta


def test_query_unknown_connector_is_400(client):
    response = client.post("/api/query", json={"connector": "elastic", "query": "*"})
    assert response.status_code == 400


def test_query_unconfigured_connector_is_409(client):
    response = client.post("/api/query", json={"connector": "splunk", "query": "index=*"})
    assert response.status_code == 409


# -------------------------------------------------------------------- estatico


def test_frontend_is_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "GLAMDRING" in response.text


# ------------------------------------------------------- limite de subida


def test_an_oversized_upload_is_rejected(client):
    """413 al pasarse del limite, y sin habersela comido antes.

    El fallo que cubre esto es de ORDEN, no de logica: antes se leia el fichero
    entero con `await file.read()` y DESPUES se miraba el tamano. O sea, el
    limite se comprobaba cuando el fichero ya estaba en memoria, que es justo
    cuando ya da igual: subir diez gigas devolvia un 413 despues de habersela
    comido. Ahora se lee a trozos y se corta en el primero que se pasa.
    """
    from glamdring.api.routes_ingest import MAX_UPLOAD_BYTES
    gordo = b'[{"a":1}]' + b" " * (MAX_UPLOAD_BYTES + 2048)
    response = client.post("/api/ingest",
                           files={"file": ("gordo.json", gordo, "application/json")})
    assert response.status_code == 413
    assert "MB" in response.json()["detail"], "el mensaje tiene que decir cual es el limite"


def test_a_normal_upload_still_works(client):
    """La red de seguridad no puede cerrarle la puerta al caso normal.

    Se sube una muestra de verdad y no un evento inventado a mano: lo que se
    comprueba es que la lectura por trozos entrega los mismos bytes que antes,
    no que el normalizador entienda un JSON recien fabricado.
    """
    from pathlib import Path
    from glamdring.config import SAMPLES_DIR
    muestra = Path(SAMPLES_DIR) / "minimo" / "incidente.json"
    contenido = muestra.read_bytes()

    response = client.post("/api/ingest",
                           files={"file": (muestra.name, contenido, "application/json")})
    assert response.status_code == 200
    assert response.json()["added"] > 0, "una muestra valida tiene que entrar entera"


# --------------------------------------- el .env y el comentario en linea


def test_un_comentario_en_linea_no_apaga_la_verificacion_tls(tmp_path):
    """ERA FAIL-OPEN, y el .env.example enseñaba a escribirlo asi.

    El valor se recortaba con `.strip().strip('"').strip("'")` sin cortar en
    '#', asi que `SPLUNK_VERIFY_TLS=1   # comentario` producia la cadena
    "1 # comentario", que `_env_bool` no reconoce y cae al valor por defecto del
    parametro.

    En los limites numericos eso degrada de forma benigna. En el TLS significa
    entregar el token de servicio del SIEM en claro al primer intermediario que
    haya por el camino, y poder manipular el resultado de la consulta sin que
    nada lo indique.
    """
    from glamdring.config import load_dotenv

    fichero = tmp_path / ".env"
    fichero.write_text(
        "SPLUNK_VERIFY_TLS=1       # comentario al final\n"
        "QRADAR_VERIFY_TLS=0 # otro comentario\n"
        "GLAMDRING_MAX_RESULTS=50000   # eventos por consulta\n",
        encoding="utf-8")

    leido = load_dotenv(fichero)
    assert leido["SPLUNK_VERIFY_TLS"] == "1"
    assert leido["QRADAR_VERIFY_TLS"] == "0"
    assert leido["GLAMDRING_MAX_RESULTS"] == "50000"


def test_una_almohadilla_dentro_del_valor_se_conserva(tmp_path):
    """La contraprueba: una contrasena puede llevar '#' y cortarla la rompe.

    Se corta en '#' solo cuando viene precedido de espacio, o cuando el valor
    esta entrecomillado se respeta lo que hay entre comillas.
    """
    from glamdring.config import load_dotenv

    fichero = tmp_path / ".env"
    fichero.write_text(
        'SPLUNK_PASSWORD="mi#clave#secreta"\n'
        "QRADAR_TOKEN=abc#def\n"
        "SPLUNK_USERNAME='con#comillas'\n",
        encoding="utf-8")

    leido = load_dotenv(fichero)
    assert leido["SPLUNK_PASSWORD"] == "mi#clave#secreta"
    assert leido["QRADAR_TOKEN"] == "abc#def"
    assert leido["SPLUNK_USERNAME"] == "con#comillas"


def test_el_env_example_no_ensena_a_apagar_el_tls():
    """El propio ejemplo usaba comentarios en linea en las lineas de limites.

    Ahora que el parser los entiende ya no hace dano, pero la comprobacion se
    queda: si alguien vuelve a romper el parser, este test dice DONDE se nota.
    """
    from glamdring.config import BASE_DIR, load_dotenv

    ejemplo = BASE_DIR / ".env.example"
    if not ejemplo.exists():
        return
    leido = load_dotenv(ejemplo)
    for clave, valor in leido.items():
        assert "#" not in valor or not valor.split("#")[0].endswith(" "), (
            f"{clave} conserva un comentario dentro del valor: {valor!r}")
