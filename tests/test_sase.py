"""Netskope y Zscaler: lo que un proxy SASE ve y ningun SIEM de los cuatro da.

La diferencia practica, con un ejemplo del propio conjunto de muestras: el
cortafuegos dice "10.4.1.5 saco 734 MB hacia 104.18.32.7". Netskope dice
"svc_backup intento subir backup-dc01.7z a Dropbox y la politica lo bloqueo".

Es el mismo hecho y son dos cosas distintas para quien tiene que decidir si
aislar el equipo.
"""

from __future__ import annotations

import pytest

from glamdring.config import SAMPLES_DIR
from glamdring.graph.build import build_graph
from glamdring.graph.enrich import enrich
from glamdring.models import (
    ACTIVITIES,
    ACTIVITY_CLASS,
    CLASS_AUTHENTICATION,
    CLASS_FILE,
    CLASS_FINDING,
    CLASS_NETWORK,
)
from glamdring.normalize import normalize_all, parse_payload


def _eventos(nombre: str):
    registros, _fmt = parse_payload((SAMPLES_DIR / nombre).read_text(encoding="utf-8"))
    return normalize_all(registros)


@pytest.fixture(scope="module")
def netskope():
    return _eventos("netskope_casb.json")


@pytest.fixture(scope="module")
def zscaler():
    return _eventos("zscaler_web.json")


MUESTRAS_SASE = ("netskope_casb.json", "zscaler_web.json")


# ---------------------------------------------------------------- contrato --

@pytest.mark.parametrize("muestra", MUESTRAS_SASE)
def test_el_vocabulario_sigue_siendo_cerrado(muestra):
    """Una fuente nueva no puede volver a meter su propio dialecto.

    Es la comprobacion que sostiene la correlacion: si Netskope llamara 'upload'
    a lo que Zscaler llama 'file_upload', volveriamos al punto de partida.
    """
    fuera = {e.activity for e in _eventos(muestra)} - set(ACTIVITIES)
    assert not fuera, f"{muestra} emite actividades que no existen: {sorted(fuera)}"


@pytest.mark.parametrize("muestra", MUESTRAS_SASE)
def test_la_clase_concuerda_con_la_actividad(muestra):
    for evento in _eventos(muestra):
        assert evento.class_name == ACTIVITY_CLASS.get(evento.activity), (
            f"{muestra}: '{evento.activity}' en {evento.class_name}")


@pytest.mark.parametrize("muestra", MUESTRAS_SASE)
def test_ningun_evento_sin_clasificar_ni_sin_mensaje(muestra):
    for evento in _eventos(muestra):
        assert evento.activity != "unknown"
        assert evento.message, "un nodo sin texto no se puede interpretar"


@pytest.mark.parametrize("muestra", MUESTRAS_SASE)
def test_sin_nodos_sueltos(muestra):
    grafo = enrich(build_graph(_eventos(muestra)))
    sueltos = [n.id for n in grafo.nodes if n.degree == 0]
    assert not sueltos, f"{muestra} deja sueltos: {sueltos}"


# --------------------------------------------------------------- Netskope --

def test_netskope_distingue_subir_de_bajar(netskope):
    """Bajarse 4 MB de SharePoint es trabajar. Subirlos a Mega no.

    Es la distincion entera: el cortafuegos ve dos conexiones salientes iguales.
    """
    bajada = netskope[0]
    subida = netskope[1]

    assert bajada.activity == "file_download"
    assert bajada.app == "Microsoft Office 365 SharePoint"
    assert bajada.severity <= 2, "bajarse un fichero del SharePoint corporativo es trabajar"

    assert subida.activity == "file_upload"
    assert subida.app == "Mega"
    assert subida.severity >= 4, "el MISMO fichero subido a almacenamiento personal si importa"
    assert any(t.id.startswith("T1567") for t in subida.mitre)


def test_netskope_da_el_fichero_concreto(netskope):
    """"Subio 4 MB" y "subio informe-clientes-2026.xlsx" no son lo mismo."""
    subida = netskope[1]
    assert subida.file and subida.file.name == "informe-clientes-2026.xlsx"
    assert subida.net and subida.net.bytes_out == 4718592


def test_netskope_lo_bloqueado_tambien_cuenta(netskope):
    """Que la politica lo parase no lo hace irrelevante: alguien lo intento."""
    bloqueado = netskope[3]
    assert bloqueado.activity == "file_upload"
    assert bloqueado.status == "failure"
    assert bloqueado.app == "Dropbox"
    assert bloqueado.net.bytes_out == 734003200
    assert bloqueado.severity >= 4


def test_netskope_una_alerta_de_dlp_es_un_hallazgo_no_un_fichero(netskope):
    """El producto esta diciendo que ENCONTRO algo, no que alguien movio un fichero.

    Es el mismo error que hacia que 'Malware Detected' saliera como "jlopez creo
    m.exe": confundir el aviso con la operacion.
    """
    dlp = netskope[2]
    assert dlp.class_name == CLASS_FINDING
    assert dlp.activity == "alert"
    assert dlp.net.rule == "DLP - Datos de nomina"


def test_netskope_marca_el_equipo_no_gestionado(netskope):
    """No es un ataque: es una via por la que los datos salen del control."""
    assert netskope[1].raw.get("device_classification") == "unmanaged"
    assert netskope[1].severity >= 3


def test_netskope_ata_la_sesion_al_usuario(netskope):
    """La sesion es lo que une persona, equipo y salida a Internet."""
    subida = netskope[1]
    assert subida.session and subida.session.id == "7f21a9c4e0b8"

    grafo = enrich(build_graph(netskope))
    aristas = {(e.source, e.type, e.target) for e in grafo.links}
    assert ("user:jlopez", "tunneled_to", "tunnel:7f21a9c4e0b8") in aristas
    assert ("user:jlopez", "uploaded_to", "service:mega") in aristas


def test_netskope_la_aplicacion_no_es_una_maquina(netskope):
    """Mega no es un equipo. Meterla como host llenaba el grafo de maquinas falsas."""
    grafo = enrich(build_graph(netskope))
    servicios = {n.id for n in grafo.nodes if n.type == "service"}
    hosts = {n.id for n in grafo.nodes if n.type == "host"}
    assert "service:mega" in servicios
    assert not any("mega" in h for h in hosts)


# --------------------------------------------------------------- Zscaler ---

def test_zscaler_la_amenaza_es_un_hallazgo(zscaler):
    """Y si Zscaler la dejo pasar, es lo mas grave que hay en el fichero."""
    amenaza = zscaler[3]
    assert amenaza.activity == "malware_detect"
    assert amenaza.class_name == CLASS_FINDING
    assert amenaza.severity == 5, "action=Allowed significa que llego"
    assert any(t.id == "T1189" for t in amenaza.mitre)


def test_zscaler_hostname_no_es_el_equipo_que_reporta(zscaler):
    """En un log web de NSS 'hostname' es el sitio al que se navega.

    Tomarlo por el equipo creaba un 'host:cdn-update-svc' al lado del
    'domain:cdn-update-svc.com' que ya existia: la misma cosa partida en dos, y
    una de las mitades disfrazada de maquina de la empresa.
    """
    grafo = enrich(build_graph(zscaler))
    hosts = {n.id for n in grafo.nodes if n.type == "host"}
    assert not any("cdn-update-svc" in h for h in hosts)
    assert any(n.id == "domain:cdn-update-svc.com" for n in grafo.nodes)


def test_zscaler_no_inventa_aplicaciones(zscaler):
    """'General Browsing' es lo que pone Zscaler cuando NO ha reconocido nada.

    Convertirlo en nodo haria que todo el trafico sin clasificar colgara del
    mismo sitio, que es peor que no tener el nodo.
    """
    grafo = enrich(build_graph(zscaler))
    servicios = {n.label.lower() for n in grafo.nodes if n.type == "service"}
    assert "general browsing" not in servicios


def test_zscaler_el_tunel_ata_la_ip_publica(zscaler):
    """La pregunta que se hace un analista cuando le llega una alerta externa
    con una IP: quien hay detras de esa IP."""
    tunel = zscaler[4]
    assert tunel.activity == "tunnel_open"
    assert tunel.session and tunel.session.assigned_ip == "88.12.44.201"

    grafo = enrich(build_graph(zscaler))
    tuneles = [n for n in grafo.nodes if n.type == "tunnel"]
    assert tuneles
    assert any(n.props.get("assignedIp") == "88.12.44.201" for n in tuneles)


def test_zscaler_un_post_cualquiera_no_es_una_subida(zscaler):
    """Rellenar un formulario no es exfiltrar.

    Se exige la COMBINACION: metodo de escritura, mas bytes de subida que de
    bajada, y una categoria por la que se sacan datos. El bloqueo hacia el nodo
    Tor es un POST y NO es una subida de fichero.
    """
    tor = zscaler[1]
    assert tor.activity == "network_connect"
    assert tor.status == "failure"
    assert tor.severity >= 4, "Anonymizer es una senal por si sola"


def test_zscaler_la_subida_real_si_se_marca(zscaler):
    subida = zscaler[2]
    assert subida.activity == "file_upload"
    assert subida.app == "Mega"
    assert subida.net.bytes_out == 734003200
    assert any(t.id.startswith("T1567") for t in subida.mitre)


def test_zscaler_avisado_no_es_ni_exito_ni_fallo(zscaler):
    """'Cautioned' es un tercer desenlace: paso, pero avisando.

    Meterlo en cualquiera de los dos cubos miente en un sentido o en el otro.
    """
    avisado = zscaler[5]
    assert avisado.status == "unknown"


# ------------------------------------------------------- las seis fuentes --

def test_las_seis_fuentes_convergen_en_las_mismas_entidades():
    """El punto entero de la herramienta.

    Seis productos distintos -Splunk, Sentinel, QRadar, CEF, Netskope y
    Zscaler- hablando del mismo incidente. Si la normalizacion vale, el mismo
    dominio y la misma persona son UN nodo, no seis.
    """
    todos = []
    for nombre in ("splunk_windows.json", "perimeter.cef", "qradar_ariel.json",
                   "sentinel_defender.json", "netskope_casb.json", "zscaler_web.json"):
        todos.extend(_eventos(nombre))

    grafo = enrich(build_graph(todos))
    assert not [n.id for n in grafo.nodes if n.degree == 0], "quedan nodos sueltos"

    por_id = {n.id: n for n in grafo.nodes}
    dominio = por_id.get("domain:cdn-update-svc.com")
    assert dominio, "el dominio del incidente tiene que ser un solo nodo"
    assert len(dominio.sources) >= 3, (
        f"deberian verlo varias fuentes y solo lo ven {dominio.sources}")

    usuario = por_id.get("user:jlopez")
    assert usuario, "la misma persona vista por seis productos es un solo nodo"
    assert len(usuario.sources) >= 3
