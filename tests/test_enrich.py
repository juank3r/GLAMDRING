"""Roles, clusters, figuras 3D y pesos del riesgo."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from glamdring.graph import ontology
from glamdring.graph.build import build_graph
from glamdring.graph.enrich import (
    DEFAULT_RISK_WEIGHTS,
    ROLE_ASSET,
    ROLE_HOSTILE,
    ROLE_NEUTRAL,
    ROLE_SUSPICIOUS,
    ROLE_VICTIM,
    assign_clusters,
    assign_roles,
    enrich,
    guess_device_class,
    reset_risk_weights,
    risk_weights,
    score,
    set_risk_weights,
)
from glamdring.graph.query import build_filtered
from glamdring.models import ActorRef, HostRef, NormalizedEvent


@pytest.fixture(autouse=True)
def clean_weights():
    """Los pesos son estado de proceso: si un test los toca, se restauran."""
    reset_risk_weights()
    yield
    reset_risk_weights()


def _graph(events):
    return enrich(build_graph(events))


def _by_id(graph):
    return {node.id: node for node in graph.nodes}


# ------------------------------------------------------- clase de dispositivo


@pytest.mark.parametrize("hostname,expected", [
    ("WKS-0421", "workstation"),
    ("LAPTOP-JLOPEZ", "workstation"),
    ("SRV-DC01", "server"),
    ("srv-fs02", "server"),
    ("sql-prod-01", "server"),
    ("FGT-PERIM-01", "firewall"),
    ("fw-dmz", "firewall"),
    ("rtr-core-1", "router"),
    ("", "workstation"),
])
def test_guess_device_class(hostname, expected):
    assert guess_device_class(hostname) == expected


def test_device_class_picks_the_3d_model():
    """La clase de equipo es lo que hace que un rack no parezca un portatil."""
    assert ontology.model_for("host", ROLE_ASSET, "server") == "server"
    assert ontology.model_for("host", ROLE_ASSET, "firewall") == "firewall"
    assert ontology.model_for("host", ROLE_ASSET, "workstation") == "workstation"


def test_role_beats_device_class_for_the_model():
    """Que algo sea del atacante importa mas que si es un servidor."""
    assert ontology.model_for("ip", ROLE_HOSTILE) == "attacker"
    assert ontology.model_for("ip", ROLE_NEUTRAL) == "endpoint"


# ------------------------------------------------------------------- roles


def test_external_c2_ip_is_hostile():
    now = datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc)
    events = [NormalizedEvent(
        uid="a", time=now, class_name="Network Activity", activity="connect", severity=4,
        device=HostRef(hostname="WKS-0421", ip="10.4.2.11"),
        dst=HostRef(ip="45.132.88.17"),
        mitre=[{"id": "T1071.001", "name": "Web Protocols", "tactic": "command-and-control"}],
    )]
    nodes = _by_id(_graph(events))
    assert nodes["ip:45.132.88.17"].props["role"] == ROLE_HOSTILE
    assert nodes["ip:45.132.88.17"].props["external"] is True
    assert nodes["ip:45.132.88.17"].props["model"] == "attacker"


def test_internal_ip_is_never_hostile():
    now = datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc)
    events = [NormalizedEvent(
        uid="a", time=now, class_name="Network Activity", activity="connect", severity=5,
        device=HostRef(hostname="WKS-0421"), dst=HostRef(ip="10.4.0.10"),
    )]
    nodes = _by_id(_graph(events))
    assert nodes["ip:10.4.0.10"].props["external"] is False
    assert nodes["ip:10.4.0.10"].props["role"] != ROLE_HOSTILE


def test_host_with_critical_severity_is_a_victim():
    now = datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc)
    events = [NormalizedEvent(
        uid="a", time=now, class_name="Authentication", activity="logon", severity=5,
        actor=ActorRef(user="jlopez"), device=HostRef(hostname="WKS-0421"),
    )]
    nodes = _by_id(_graph(events))
    assert nodes["host:wks-0421"].props["role"] == ROLE_VICTIM
    assert nodes["user:jlopez"].props["role"] == ROLE_VICTIM


def test_quiet_host_is_an_asset():
    now = datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc)
    events = [NormalizedEvent(
        uid="a", time=now, class_name="Authentication", activity="logon", severity=1,
        actor=ActorRef(user="ana"), device=HostRef(hostname="WKS-0100"),
    )]
    nodes = _by_id(_graph(events))
    assert nodes["host:wks-0100"].props["role"] == ROLE_ASSET


def test_alert_marks_its_neighbours_even_without_severity():
    """Un host tocado por una alerta no puede quedarse como activo sano."""
    now = datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc)
    events = [
        NormalizedEvent(uid="q", time=now, class_name="Authentication", activity="logon",
                        severity=1, actor=ActorRef(user="ana"),
                        device=HostRef(hostname="WKS-0100")),
        NormalizedEvent(uid="a", time=now, class_name="Detection Finding", activity="alert",
                        severity=2, message="Actividad anomala",
                        device=HostRef(hostname="WKS-0100")),
    ]
    nodes = _by_id(_graph(events))
    assert nodes["host:wks-0100"].props["touchedByAlert"] is True
    assert nodes["host:wks-0100"].props["role"] == ROLE_SUSPICIOUS


def test_alert_node_is_always_hostile():
    now = datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc)
    events = [NormalizedEvent(uid="a", time=now, class_name="Detection Finding",
                              activity="alert", severity=5, message="Ransomware",
                              device=HostRef(hostname="SRV-FS02"))]
    graph = _graph(events)
    alerts = [n for n in graph.nodes if n.type == "alert"]
    assert alerts and all(n.props["role"] == ROLE_HOSTILE for n in alerts)


def test_context_entities_stay_neutral_when_nothing_points_at_them():
    now = datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc)
    events = [NormalizedEvent(
        uid="a", time=now, class_name="File System Activity", activity="create", severity=1,
        device=HostRef(hostname="WKS-0100"),
        file={"name": "informe.docx", "path": "C:\\Users\\ana\\informe.docx"},
    )]
    nodes = _by_id(_graph(events))
    assert nodes["file:c:\\users\\ana\\informe.docx"].props["role"] == ROLE_NEUTRAL


# ----------------------------------------------------- roles sobre datos reales


def test_demo_incident_roles(all_events):
    """Sobre el incidente de ejemplo, cada pieza cae donde debe."""
    graph = build_filtered(all_events, max_nodes=0)
    nodes = _by_id(graph)

    assert nodes["ip:45.132.88.17"].props["role"] == ROLE_HOSTILE
    assert nodes["domain:cdn-update-svc.com"].props["role"] == ROLE_HOSTILE
    assert nodes["host:wks-0421"].props["role"] == ROLE_VICTIM
    assert nodes["host:srv-dc01"].props["role"] == ROLE_VICTIM
    assert nodes["user:jlopez"].props["role"] == ROLE_VICTIM

    # SRV-DC01 se dibuja como rack y WKS-0421 como puesto de trabajo.
    assert nodes["host:srv-dc01"].props["model"] == "server"
    assert nodes["host:wks-0421"].props["model"] == "workstation"


def test_attacker_mailbox_is_hostile(all_events):
    """El remitente del phishing vive en el dominio del atacante: es suyo."""
    graph = build_filtered(all_events, max_nodes=0)
    nodes = _by_id(graph)
    attacker_mailbox = nodes["mailbox:billing@cdn-update-svc.com"]
    assert attacker_mailbox.props["role"] == ROLE_HOSTILE
    assert attacker_mailbox.props["model"] == "attacker"
    # Y el de la victima sigue siendo nuestro.
    assert nodes["mailbox:jlopez@corp.com"].props["role"] != ROLE_HOSTILE


def test_product_names_do_not_become_hosts(all_events):
    """'TrendMicro-AV' es un producto, no una maquina del parque."""
    graph = build_filtered(all_events, max_nodes=0)
    hostnames = {n.label.lower() for n in graph.nodes if n.type == "host"}
    for product in ("trendmicro-av", "bluecoat-proxy", "paloalto-perimeter", "infoblox-dns"):
        assert product not in hostnames


def test_cloud_app_is_a_service_not_a_host(all_events):
    graph = build_filtered(all_events, max_nodes=0)
    portal = [n for n in graph.nodes if "office 365" in n.label.lower()]
    assert portal, "la app cloud del SigninLogs deberia estar en el grafo"
    assert portal[0].type == "service"


def test_same_binary_is_one_node(all_events):
    """m.exe visto por Sysmon con ruta y por la alerta sin ella: un solo nodo."""
    graph = build_filtered(all_events, max_nodes=0)
    files = [n for n in graph.nodes if n.type == "file" and n.label.lower() == "m.exe"]
    assert len(files) == 1
    assert "\\" in files[0].id, "gana la version con ruta completa"

    processes = [n for n in graph.nodes
                 if n.type == "process" and n.label.lower() == "explorer.exe"]
    assert len(processes) == 1


# ---------------------------------------------------------------- clusters


def test_clusters_are_deterministic(all_events):
    """Dos ejecuciones dan los mismos numeros: si no, los colores bailarian."""
    first = {n.id: n.props["cluster"] for n in build_filtered(all_events, max_nodes=0).nodes}
    second = {n.id: n.props["cluster"] for n in build_filtered(all_events, max_nodes=0).nodes}
    assert first == second


def test_cluster_zero_is_the_largest(all_events):
    graph = build_filtered(all_events, max_nodes=0)
    sizes = {}
    for node in graph.nodes:
        sizes[node.props["cluster"]] = sizes.get(node.props["cluster"], 0) + 1
    assert sizes[0] == max(sizes.values())


def test_disconnected_components_land_in_different_clusters():
    now = datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc)
    events = [
        NormalizedEvent(uid="a", time=now, class_name="Authentication", activity="logon",
                        actor=ActorRef(user="ana"), device=HostRef(hostname="WKS-1")),
        NormalizedEvent(uid="b", time=now, class_name="Authentication", activity="logon",
                        actor=ActorRef(user="luis"), device=HostRef(hostname="WKS-2")),
    ]
    graph = assign_clusters(assign_roles(build_graph(events)))
    nodes = _by_id(graph)
    assert nodes["user:ana"].props["cluster"] != nodes["user:luis"].props["cluster"]
    assert nodes["user:ana"].props["cluster"] == nodes["host:wks-1"].props["cluster"]


# ------------------------------------------------------------ pesos del riesgo


def test_score_is_bounded():
    assert score(5, 10, 100, 10_000, 10_000, True) == 100
    assert score(0, 0, 0, 0, 0, False) == 0


def test_severity_dominates_volume():
    chatty = score(1, 0, 2, 5000, 900, False)
    critical = score(5, 0, 1, 1, 3, False)
    assert critical > chatty


def test_set_risk_weights_changes_the_score():
    baseline = score(3, 0, 0, 0, 0, False)
    set_risk_weights({"severity": 20})
    assert score(3, 0, 0, 0, 0, False) > baseline
    assert risk_weights()["severity"] == 20


def test_set_risk_weights_ignores_junk():
    """Estos numeros vienen de un formulario web y acaban ordenando el triaje."""
    set_risk_weights({"severity": "no-es-un-numero", "inventado": 99, "degree": -5})
    weights = risk_weights()
    assert weights["severity"] == DEFAULT_RISK_WEIGHTS["severity"]
    assert "inventado" not in weights
    assert weights["degree"] == 0  # los negativos se recortan a cero


def test_reset_restores_defaults():
    set_risk_weights({"severity": 1})
    assert reset_risk_weights() == DEFAULT_RISK_WEIGHTS
