"""Informes: narrativa, IOCs y los cuatro formatos de salida."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from glamdring.graph.query import build_filtered
from glamdring.main import app
from glamdring.models import ActorRef, HostRef, NormalizedEvent, ProcRef
from glamdring.report import build, collect_iocs, html, markdown, narrative, stix


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def loaded(client):
    client.post("/api/demo")
    return client


@pytest.fixture
def report(all_events):
    graph = build_filtered(all_events, max_nodes=0)
    return build(graph, all_events)


# ------------------------------------------------------------------ narrativa


def test_describe_logon():
    event = NormalizedEvent(
        uid="a", time=datetime(2026, 8, 19, 9, 40, tzinfo=timezone.utc),
        class_name="Authentication", activity="logon_remote", status="success",
        actor=ActorRef(user="CORP\\jlopez"),
        device=HostRef(hostname="srv-dc01"), src=HostRef(hostname="wks-0421"),
    )
    text = narrative.describe(event)
    assert "jlopez" in text and "srv-dc01" in text
    assert "movimiento lateral" in text


def test_describe_process_includes_cmdline():
    event = NormalizedEvent(
        uid="a", time=datetime(2026, 8, 19, 9, 15, tzinfo=timezone.utc),
        class_name="Process Activity", activity="launch",
        actor=ActorRef(user="jlopez"), device=HostRef(hostname="wks-0421"),
        process=ProcRef(name="powershell.exe", parent_name="explorer.exe",
                        cmdline="powershell.exe -nop -w hidden -enc SQBFAFgA"),
    )
    text = narrative.describe(event)
    assert "powershell.exe" in text and "explorer.exe" in text and "-enc" in text


def test_describe_truncates_monster_cmdlines():
    event = NormalizedEvent(
        uid="a", time=datetime(2026, 8, 19, 9, 15, tzinfo=timezone.utc),
        class_name="Process Activity", activity="launch",
        device=HostRef(hostname="wks-0421"),
        process=ProcRef(name="powershell.exe", cmdline="A" * 5000),
    )
    assert len(narrative.describe(event)) < 400


def test_repeated_events_collapse_into_one_line():
    """Catorce fallos de login identicos son un hecho, no catorce hechos."""
    events = [
        NormalizedEvent(
            uid=f"u{i}", time=datetime(2026, 8, 19, 9, 35, i, tzinfo=timezone.utc),
            class_name="Authentication", activity="logon_failed", status="failure",
            severity=3, actor=ActorRef(user="administrator"),
            device=HostRef(hostname="srv-dc01"),
        )
        for i in range(14)
    ]
    entries = narrative.summarize_events(events)
    assert len(entries) == 1
    assert entries[0]["count"] == 14
    assert len(entries[0]["uids"]) == 14


def test_narrative_is_chronological(report):
    times = [entry["time"] for entry in report["narrative"]]
    assert times == sorted(times)


def test_narrative_is_deterministic(all_events):
    graph = build_filtered(all_events, max_nodes=0)
    first = [e["text"] for e in build(graph, all_events)["narrative"]]
    second = [e["text"] for e in build(graph, all_events)["narrative"]]
    assert first == second


def test_narrative_tells_the_incident(report):
    """La cronologia tiene que contener las piezas clave del ataque de demo."""
    blob = " ".join(entry["text"] for entry in report["narrative"]).lower()
    assert "powershell.exe" in blob
    assert "certutil.exe" in blob
    assert "movimiento lateral" in blob
    assert "cdn-update-svc.com" in blob or "45.132.88.17" in blob


# ---------------------------------------------------------------------- IOCs


def test_iocs_never_include_private_addresses(report):
    """Una lista de bloqueo con la propia red dentro es peor que no tenerla."""
    values = [item["value"] for item in report["iocs"]["ip"]]
    assert values
    for value in values:
        assert not value.startswith(("10.", "192.168.", "172.16."))


def test_iocs_contain_the_attacker_infrastructure(report):
    ips = {item["value"] for item in report["iocs"]["ip"]}
    domains = {item["value"] for item in report["iocs"]["domain"]}
    assert "45.132.88.17" in ips
    assert "cdn-update-svc.com" in domains


def test_domain_iocs_are_domains_not_urls(report):
    """Una URL entera colandose como dominio arruina la regla de bloqueo."""
    for item in report["iocs"]["domain"]:
        assert "/" not in item["value"]
        assert ":" not in item["value"]


def test_hash_iocs_are_complete(report):
    for item in report["iocs"]["hash"]:
        assert len(item["value"]) in (32, 64), "el hash no puede ir truncado"


def test_attacker_mailbox_is_an_ioc(report):
    values = {item["value"] for item in report["iocs"]["mailbox"]}
    assert "billing@cdn-update-svc.com" in values
    assert "jlopez@corp.com" not in values


# ------------------------------------------------------------------ estructura


def test_report_has_every_section(report):
    for key in ("title", "generated", "window", "summary", "narrative",
                "killchain", "entities", "iocs", "recommendations"):
        assert key in report


def test_title_names_the_victims(report):
    assert "wks-0421" in report["title"].lower() or "srv-dc01" in report["title"].lower()


def test_killchain_is_in_attack_order(report):
    ranks = [stage["rank"] for stage in report["killchain"]]
    assert ranks == sorted(ranks)
    tactics = [stage["tactic"] for stage in report["killchain"]]
    assert "lateral-movement" in tactics
    assert "credential-access" in tactics


def test_recommendations_follow_the_tactics(report):
    """Cada recomendacion sale de algo observado, nunca de la nada.

    Hay dos origenes: las tacticas MITRE de la cadena de ataque y las etapas de
    despliegue de ransomware que se hayan alcanzado. Ambas cuentan, pero nada
    mas: una recomendacion sin evidencia detras es ruido en el informe.
    """
    tactics = {stage["tactic"] for stage in report["killchain"]}
    stages = {
        etapa["id"]
        for etapa in (report.get("threat", {}).get("detection", {}).get("stages", []))
        if etapa.get("reached")
    }
    recommended = {item["tactic"] for item in report["recommendations"]}
    assert recommended <= (tactics | stages)
    # Con volcado de credenciales detectado, rotar contrasenas es prioritario.
    credential = [r for r in report["recommendations"] if r["tactic"] == "credential-access"]
    assert credential and credential[0]["priority"] == 0


def test_entities_sorted_by_risk(report):
    risks = [item["risk"] for item in report["entities"]]
    assert risks == sorted(risks, reverse=True)


# ------------------------------------------------------------------ formatos


def test_html_is_self_contained(report):
    body = html.render(report)
    assert body.startswith("<!DOCTYPE html>")
    assert "<style>" in body
    # Nada de recursos externos: el informe viaja por correo y se abre offline.
    assert "http://" not in body.replace("http://www.w3.org", "")
    assert "<script" not in body.lower()


def test_html_escapes_hostile_content():
    """Los nombres vienen de logs, y un log puede traer HTML dentro."""
    fake = {
        "title": "<script>alert(1)</script>", "generated": "2026-08-19T09:00:00+00:00",
        "analyst": "", "window": {"from": None, "to": None, "duration": None},
        "summary": {"events": 1, "nodes": 1, "links": 0, "maxSeverity": 5,
                    "maxSeverityLabel": "Critica", "sources": ["splunk"],
                    "roles": {}, "tactics": [], "iocCount": 0},
        "narrative": [{"time": "2026-08-19T09:00:00+00:00", "until": None,
                       "text": "<img src=x onerror=alert(1)>", "count": 1,
                       "severity": 5, "source": "splunk", "techniques": [],
                       "tactics": [], "uids": []}],
        "killchain": [], "entities": [], "iocs": {}, "recommendations": [], "image": None,
    }
    body = html.render(fake)
    # Lo que importa es que no quede NINGUNA etiqueta viva: el texto escapado
    # ("&lt;img src=x onerror=...&gt;") es inerte y puede aparecer tal cual.
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body
    assert "<img src=x" not in body
    assert "&lt;img src=x onerror=alert(1)&gt;" in body


def test_html_embeds_the_snapshot(report):
    report = dict(report, image="data:image/png;base64,iVBORw0KGgo=")
    assert "data:image/png;base64,iVBORw0KGgo=" in html.render(report)


def test_markdown_is_clean(report):
    body = markdown.render(report)
    assert body.startswith("# ")
    assert "## Cronología" in body
    assert "## Indicadores de compromiso" in body
    # La imagen no se incrusta: en base64 dentro de Markdown es ilegible.
    assert "base64" not in body


def test_stix_indicators_are_wellformed(report):
    bundle = json.loads(stix.render_stix(report))
    assert bundle["type"] == "bundle"
    indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
    assert indicators
    for indicator in indicators:
        assert indicator["pattern"].startswith("[")
        assert indicator["pattern_type"] == "stix"
        assert indicator["id"].startswith("indicator--")


def test_stix_ids_are_stable(report):
    """Reexportar el mismo incidente no puede duplicar objetos en el TIP."""
    first = json.loads(stix.render_stix(report))
    second = json.loads(stix.render_stix(report))
    ids = lambda b: [o["id"] for o in b["objects"] if o["type"] == "indicator"]  # noqa: E731
    assert ids(first) == ids(second)


def test_flat_iocs_are_one_per_line(report):
    body = stix.render_flat(report, with_headers=False)
    lines = [line for line in body.splitlines() if line.strip()]
    assert lines
    assert all(" " not in line for line in lines)
    assert "45.132.88.17" in lines


# ---------------------------------------------------------------------- API


@pytest.mark.parametrize("fmt,marker", [
    ("html", "<!DOCTYPE html>"),
    ("markdown", "# "),
    ("json", '"summary"'),
    ("stix", '"bundle"'),
    ("iocs", "45.132.88.17"),
])
def test_report_endpoint_every_format(loaded, fmt, marker):
    response = loaded.post("/api/report", json={"format": fmt, "download": False})
    assert response.status_code == 200
    assert marker in response.text


def test_report_download_headers(loaded):
    response = loaded.post("/api/report", json={"format": "html"})
    assert "attachment" in response.headers["content-disposition"]
    assert ".html" in response.headers["content-disposition"]


def test_report_rejects_unknown_format(loaded):
    assert loaded.post("/api/report", json={"format": "pdf"}).status_code == 400


def test_report_without_data_is_409(client):
    client.post("/api/reset")
    assert client.post("/api/report", json={"format": "html"}).status_code == 409


def test_report_with_impossible_filters_is_409(loaded):
    response = loaded.post("/api/report",
                           json={"format": "html", "q": "cadena-que-no-existe-jamas"})
    assert response.status_code == 409


def test_report_rejects_a_bogus_image(loaded):
    response = loaded.post("/api/report", json={
        "format": "html", "image": "javascript:alert(1)",
    })
    assert response.status_code == 400


def test_report_accepts_a_real_snapshot(loaded):
    response = loaded.post("/api/report", json={
        "format": "html", "download": False,
        "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==",
    })
    assert response.status_code == 200
    assert "data:image/png;base64" in response.text


def test_preview_returns_structure(loaded):
    payload = loaded.get("/api/report/preview").json()
    assert payload["narrative"] and payload["killchain"]


def test_iocs_endpoint(loaded):
    payload = loaded.get("/api/iocs").json()
    assert payload["count"] > 0
    flat = loaded.get("/api/iocs", params={"flat": True}).text
    assert "45.132.88.17" in flat
