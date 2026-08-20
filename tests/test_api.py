"""La API HTTP, con TestClient. No hace falta ningun SIEM."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

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
    assert names == {"splunk", "sentinel", "qradar", "files"}
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
    assert len(payload["files"]) == 4
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
