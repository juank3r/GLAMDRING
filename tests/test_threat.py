"""Deteccion de herramientas, comportamiento de ransomware y atribucion."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from glamdring import threat
from glamdring.config import SAMPLES_DIR
from glamdring.graph.query import build_filtered
from glamdring.main import app
from glamdring.models import ActorRef, FileRef, HostRef, NormalizedEvent, ProcRef
from glamdring.normalize import normalize_all, parse_payload

APT_DIR = SAMPLES_DIR / "apt"


@pytest.fixture(scope="module")
def kb():
    return threat.reload_catalog()


def evento(cmdline: str = "", proceso: str = "", fichero: str = "",
           clase: str = "Process Activity", host: str = "WKS-1180") -> NormalizedEvent:
    return NormalizedEvent(
        uid=f"u{abs(hash(cmdline + proceso + fichero)) % 10**12}",
        time=datetime(2026, 8, 24, 9, 0, tzinfo=timezone.utc),
        class_name=clase,
        activity="launch",
        severity=2,
        message="",
        actor=ActorRef(user="mgarcia"),
        device=HostRef(hostname=host),
        process=ProcRef(name=proceso or None, path=proceso or None,
                        cmdline=cmdline or None) if (proceso or cmdline) else None,
        file=FileRef(name=fichero.rsplit("\\", 1)[-1], path=fichero) if fichero else None,
    )


def cargar(nombre: str):
    ruta = APT_DIR / f"{nombre}.json"
    registros, _ = parse_payload(ruta.read_text(encoding="utf-8"))
    return normalize_all(registros)


# --------------------------------------------------------------- el catalogo


def test_catalog_loaded(kb):
    stats = kb.stats()
    assert stats["tools"] > 200, "el catalogo de herramientas parece vacio"
    assert stats["groups"] >= 15
    assert stats["ransomNotes"] > 200
    assert stats["binaryPatterns"] > 200


def test_catalog_credits_its_sources(kb):
    """La licencia CC BY exige atribucion, y ademas es de justicia."""
    nombres = {src["name"] for src in kb.stats()["sources"]}
    assert "Ransomware Tool Matrix" in nombres
    assert "ransomware.live" in nombres
    assert kb.stats()["caveat"], "el aviso sobre la atribucion no puede faltar"


def test_catalog_has_no_parsing_garbage(kb):
    """Los encabezados de la tabla de fuentes no son herramientas."""
    for basura in ("Date Published", "Report", "Source", "Sources"):
        assert basura not in kb.tools


def test_discriminating_weight_favours_rare_tools(kb):
    """PsExec no distingue a nadie; una herramienta de un solo grupo, si."""
    conteos = kb.tool_group_count
    comunes = [t for t, n in conteos.items() if n >= 8]
    raras = [t for t, n in conteos.items() if n == 1]
    assert comunes and raras
    assert kb.discriminating_weight(raras[0]) > kb.discriminating_weight(comunes[0])


# ------------------------------------------------------ deteccion de herramientas


@pytest.mark.parametrize("cmdline,proceso,esperada", [
    ("", "C:\\Windows\\Temp\\rclone.exe", "RClone"),
    ("rclone.exe copy C:\\datos remote:exfil", "C:\\Windows\\System32\\cmd.exe", "RClone"),
    ("", "C:\\ProgramData\\anydesk.exe", "AnyDesk"),
    ("", "C:\\Temp\\advanced_ip_scanner.exe", "Advanced IP Scanner"),
    ("m.exe \"sekurlsa::logonpasswords\" exit", "C:\\Temp\\m.exe", "Mimikatz"),
])
def test_detects_known_tools(kb, cmdline, proceso, esperada):
    hallazgos = threat.scan([evento(cmdline=cmdline, proceso=proceso)], kb)
    assert esperada in hallazgos.tool_names()


def test_path_containing_a_tool_name_is_not_a_detection(kb):
    """'C:\\Users\\rclone-backup\\informe.docx' no es rclone.

    Se tokeniza y se compara el nombre de fichero, en vez de buscar la subcadena
    dentro del texto. Sin eso, cualquier ruta con la palabra dentro dispararia.
    """
    hallazgos = threat.scan([evento(
        cmdline="notepad.exe C:\\Users\\rclone-backup\\informe.docx",
        proceso="C:\\Windows\\System32\\notepad.exe")], kb)
    assert "RClone" not in hallazgos.tool_names()


def test_generic_binaries_need_an_exact_match(kb):
    """'net' aparece en mil sitios: no puede detectarse desde una linea suelta."""
    hallazgos = threat.scan([evento(
        cmdline="robocopy C:\\net\\share D:\\copia /MIR",
        proceso="C:\\Windows\\System32\\robocopy.exe")], kb)
    assert "Net" not in hallazgos.tool_names()


# ------------------------------------------------------------- notas de rescate


def test_detects_known_ransom_note(kb):
    hallazgos = threat.scan([evento(
        fichero="C:\\akira_readme.txt", clase="File System Activity")], kb)
    assert hallazgos.notes
    assert hallazgos.notes[0].known
    assert "Akira" in hallazgos.notes[0].groups


def test_detects_unknown_note_by_shape(kb):
    """Un grupo nuevo no esta en ningun catalogo, y es cuando mas falta hace.

    El nombre de la prueba lleva un sufijo inventado a proposito: el catalogo
    de ransomware.live es tan completo que casi cualquier nombre "obvio" ya
    esta dentro, y entonces la prueba estaria midiendo el catalogo en vez de la
    heuristica.
    """
    hallazgos = threat.scan([evento(
        fichero="C:\\HOW-TO-RESTORE-FILES-QQ7781.txt",
        clase="File System Activity")], kb)
    assert hallazgos.notes
    assert hallazgos.notes[0].known is False
    assert hallazgos.notes[0].groups == []


def test_an_executable_is_never_a_ransom_note(kb):
    hallazgos = threat.scan([evento(
        fichero="C:\\Temp\\readme.exe", clase="File System Activity")], kb)
    assert not hallazgos.notes


# ---------------------------------------------------------------- comportamiento


@pytest.mark.parametrize("cmdline,firma", [
    ("vssadmin.exe delete shadows /all /quiet", "shadow_copy_delete"),
    ("bcdedit /set {default} recoveryenabled no", "recovery_disable"),
    ("wbadmin delete catalog -quiet", "backup_catalog_delete"),
    ("powershell Set-MpPreference -DisableRealtimeMonitoring $true", "defender_disable"),
    ("wevtutil.exe cl Security", "event_log_clear"),
    ("rclone.exe copy C:\\datos remote:exfil", "exfil_tooling"),
    ("7z.exe a -psecreto C:\\Temp\\datos.7z \\\\FS01\\finanzas\\*", "archive_staging"),
    ("procdump64.exe -ma lsass.exe C:\\Temp\\out.dmp", "credential_dump"),
    ("nltest /dclist:corp.local", "domain_recon"),
])
def test_behaviour_signatures(kb, cmdline, firma):
    hallazgos = threat.scan([evento(cmdline=cmdline, proceso="C:\\Windows\\System32\\cmd.exe")], kb)
    assert firma in {hit.signature.id for hit in hallazgos.behaviours}


def test_shadow_copy_delete_is_maximum_severity(kb):
    """Es el paso que convierte un incidente en un desastre."""
    hallazgos = threat.scan([evento(cmdline="vssadmin delete shadows /all")], kb)
    assert threat.severity_floor(hallazgos) == 5


def test_normal_admin_work_triggers_nothing(kb):
    """Sin esto, la deteccion seria inutil: todo dispararia siempre."""
    inocentes = [
        evento(cmdline="net use Z: \\\\SRV-FS01\\comun /persistent:yes"),
        evento(cmdline="gpupdate /force"),
        evento(cmdline="ipconfig /all"),
        evento(fichero="C:\\Users\\ana\\Documentos\\presupuesto.xlsx",
               clase="File System Activity"),
    ]
    hallazgos = threat.scan(inocentes, kb)
    assert not hallazgos.behaviours
    assert not hallazgos.notes


# ------------------------------------------------------------------- etapas


def test_stage_assessment_orders_the_deployment(kb):
    eventos = cargar("Akira")
    resumen = threat.summarize(threat.scan(eventos, kb))
    etapas = resumen["stages"]
    assert [e["id"] for e in etapas] == [s["id"] for s in threat.STAGES]
    alcanzadas = [e["id"] for e in etapas if e["reached"]]
    assert "impact" in alcanzadas and "inhibit" in alcanzadas


def test_next_stage_is_the_useful_part(kb):
    """Saber lo que falta por pasar es mas accionable que saber por donde va."""
    eventos = [evento(cmdline="advanced_ip_scanner.exe 10.0.0.0/8",
                      proceso="C:\\Temp\\advanced_ip_scanner.exe")]
    resumen = threat.summarize(threat.scan(eventos, kb))
    assert resumen["nextStage"] is not None
    assert resumen["nextStage"]["id"] != "discovery"


# --------------------------------------------------------------- atribucion


@pytest.mark.parametrize("grupo", ["Akira", "Qilin", "BlackBasta", "PLAY", "BianLian"])
def test_attribution_finds_the_right_group(kb, grupo):
    """Cada incidente sintetico usa el arsenal real de su grupo."""
    hallazgos = threat.scan(cargar(grupo), kb)
    candidatos = threat.attribute(hallazgos, kb)
    assert candidatos, f"sin candidatos para {grupo}"
    assert candidatos[0].group.replace(" ", "").lower() == grupo.replace(" ", "").lower()


def test_generic_note_does_not_grant_high_confidence(kb):
    """El fallo que mas dano haria: senalar a un grupo por un 'README.txt'.

    Ese nombre lo comparten decenas de familias. Antes bastaba con encontrar
    cualquier nota para dar confianza alta, y eso colocaba arriba a grupos sin
    una sola herramienta en comun: manda al analista a buscar el arsenal
    equivocado.
    """
    hallazgos = threat.scan([evento(fichero="C:\\README.txt",
                                    clase="File System Activity")], kb)
    assert hallazgos.notes and hallazgos.notes[0].known
    for candidato in threat.attribute(hallazgos, kb):
        if not candidato.discriminating:
            assert candidato.confidence != "alta"


def test_unique_note_does_grant_high_confidence(kb):
    hallazgos = threat.scan([evento(fichero="C:\\akira_readme.txt",
                                    clase="File System Activity")], kb)
    candidatos = threat.attribute(hallazgos, kb)
    assert candidatos[0].group == "Akira"
    assert candidatos[0].confidence == "alta"


def test_ubiquitous_tools_are_listed_apart(kb):
    """Se dice cuales NO sirven para atribuir, para que se vea por que no puntuan."""
    valoracion = threat.assess(threat.scan(cargar("Akira"), kb), kb)
    assert "ubiquitousTools" in valoracion
    assert valoracion["caveat"]


def test_nothing_observed_means_no_attribution(kb):
    valoracion = threat.assess(threat.scan([evento(cmdline="ipconfig /all")], kb), kb)
    assert valoracion["candidates"] == []
    assert valoracion["confidence"] == "no concluyente"


def test_explanation_is_honest_about_confidence(kb):
    hallazgos = threat.scan([evento(fichero="C:\\README.txt",
                                    clase="File System Activity")], kb)
    candidatos = threat.attribute(hallazgos, kb)
    if candidatos and candidatos[0].note_strength < 3.0:
        texto = threat.explain(candidatos[0], kb).lower()
        assert "no senala" in texto or "no dice cual" in texto


# ------------------------------------------------------------------- el grafo


def test_graph_marks_known_tools(kb):
    grafo = build_filtered(cargar("Akira"), max_nodes=0)
    con_herramienta = [n for n in grafo.nodes if n.props.get("tool")]
    assert len(con_herramienta) >= 10
    assert all(n.type in ("process", "file") for n in con_herramienta)
    assert grafo.meta.counts.get("knownTools")


def test_a_known_tool_is_suspicious_never_hostile(kb):
    """rclone es legitimo: ser conocido pone el foco, no acusa."""
    grafo = build_filtered(cargar("Akira"), max_nodes=0)
    for node in grafo.nodes:
        if node.props.get("tool"):
            assert node.props["role"] != "hostile"


# --------------------------------------------------------------------- API


@pytest.fixture
def client():
    return TestClient(app)


def test_threat_catalog_endpoint(client):
    payload = client.get("/api/threat/catalog").json()
    assert payload["available"] is True
    assert payload["tools"] > 200
    assert "Akira" in payload["groups"]
    assert payload["sources"]


def test_threat_group_endpoint(client):
    payload = client.get("/api/threat/group/Akira").json()
    assert payload["name"] == "Akira"
    assert payload["tools"]
    # El detalle explica por que puntua como puntua.
    assert payload["toolDetail"][0]["weight"] >= payload["toolDetail"][-1]["weight"]


def test_threat_group_unknown_is_404(client):
    assert client.get("/api/threat/group/NoExisteEsteGrupo").status_code == 404


def test_threat_endpoint_without_data_is_409(client):
    client.post("/api/reset")
    assert client.get("/api/threat").status_code == 409


def test_threat_endpoint_on_an_apt_sample(client):
    registros = json.loads((APT_DIR / "Qilin.json").read_text(encoding="utf-8"))
    client.post("/api/ingest", files={"file": ("qilin.json", json.dumps(registros),
                                               "application/json")})
    payload = client.get("/api/threat").json()
    assert payload["detection"]["toolCount"] > 5
    assert payload["attribution"]["best"]["group"] == "Qilin"
    assert payload["attribution"]["explanation"]


# ----------------------------------------------------------------- informes


def test_report_includes_the_threat_section(client):
    registros = json.loads((APT_DIR / "Akira.json").read_text(encoding="utf-8"))
    client.post("/api/ingest", files={"file": ("akira.json", json.dumps(registros),
                                               "application/json")})

    markdown = client.post("/api/report",
                           json={"format": "markdown", "download": False}).text
    assert "Herramientas de intrusión y ransomware" in markdown
    assert "Etapa del despliegue" in markdown
    assert "Akira" in markdown
    # El aviso sobre la atribucion no puede faltar en el documento que se archiva.
    assert "hipotesis" in markdown.lower() or "hipótesis" in markdown.lower()

    html = client.post("/api/report", json={"format": "html", "download": False}).text
    assert "Herramientas de intrusion y ransomware" in html
    assert "Ransomware Tool Matrix" in html


def test_report_survives_without_the_catalog(client, monkeypatch, tmp_path):
    """Sin inteligencia de amenazas el informe tiene que salir igual."""
    # Hay que ir por importlib: tanto `from glamdring.threat import catalog`
    # como `import glamdring.threat.catalog as x` resuelven por atributo del
    # paquete, y ahi `catalog` es la FUNCION que reexporta __init__, no el
    # modulo. import_module devuelve el modulo de verdad.
    from importlib import import_module

    catalog_module = import_module("glamdring.threat.catalog")
    monkeypatch.setattr(catalog_module, "DATA_DIR", tmp_path)
    catalog_module.reload_catalog()
    try:
        registros = json.loads((APT_DIR / "PLAY.json").read_text(encoding="utf-8"))
        client.post("/api/ingest", files={"file": ("play.json", json.dumps(registros),
                                                  "application/json")})
        response = client.post("/api/report", json={"format": "markdown", "download": False})
        assert response.status_code == 200
        assert "Cronología" in response.text
    finally:
        catalog_module.reload_catalog()
