"""Cada linea de las muestras cae en su clase. Linea a linea, sin excepciones.

POR QUE ESTE FICHERO. Los tests de normalizacion que ya habia CUENTAN: que no se
descarte nada, que haya al menos dos fallos de autenticacion, que el total
cuadre. Ninguno mira que cada evento concreto salga bien clasificado, y por eso
pasaban en verde sobre cosas como estas, todas medidas:

  - una peticion DNS que salia como "creacion de fichero"
  - trafico de mando y control que salia como "lanzamiento de proceso"
  - una deteccion de antivirus con la contencion FALLIDA que el informe
    redactaba como "jlopez creo m.exe"
  - un cierre de sesion de Windows que salia como movimiento lateral con una
    tecnica de ATT&CK inventada

Una clasificacion equivocada no es un fallo cosmetico: es una afirmacion con
aplomo sobre lo que paso. El analista la lee, se la cree, y decide con ella.

Aqui se fija la clasificacion de cada linea. Si alguien cambia la escalera de
palabras de cef.py o el despacho de splunk_windows.py y algo se mueve, salta.
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
    CLASS_DNS,
    CLASS_FINDING,
    CLASS_NETWORK,
)
from glamdring.normalize import normalize_all, parse_payload


def _eventos(nombre: str):
    registros, _fmt = parse_payload((SAMPLES_DIR / nombre).read_text(encoding="utf-8"))
    return normalize_all(registros)


@pytest.fixture(scope="module")
def perimetro():
    return _eventos("perimeter.cef")


# ---------------------------------------------------------------------------
# El vocabulario es cerrado, y eso hay que comprobarlo
# ---------------------------------------------------------------------------

# QRadar y Sentinel todavia emiten el vocabulario antiguo: son las dos tandas
# que quedan de la fase 2. Se marcan como fallo ESPERADO y en modo estricto, de
# forma que en cuanto se arreglen el test pase a XPASS y obligue a quitar la
# marca. Un pendiente que se limpia solo es mejor que un pendiente en una lista.
_PENDIENTES = ("qradar_ariel.json", "sentinel_defender.json")


def _muestra(nombre: str, *, motivo: str):
    if nombre in _PENDIENTES:
        return pytest.param(nombre, marks=pytest.mark.xfail(strict=True, reason=motivo))
    return nombre


MUESTRAS = ("splunk_windows.json", "perimeter.cef", "qradar_ariel.json",
            "sentinel_defender.json")

VOCABULARIO = [_muestra(n, motivo="pendiente de migrar al vocabulario cerrado")
               for n in MUESTRAS]
SIN_SUELTOS = [_muestra(n, motivo="pendiente: deja nodos sin aristas")
               if n == "qradar_ariel.json" else n for n in MUESTRAS]


@pytest.mark.parametrize("muestra", VOCABULARIO)
def test_toda_actividad_esta_en_el_vocabulario(muestra):
    """Si un normalizador inventa un valor, es que el vocabulario no es cerrado.

    Es la comprobacion que sostiene todo lo demas: sin ella, cada fabricante
    nuevo vuelve a meter su propio dialecto y se acaba otra vez con la misma
    cosa en tres nombres, que es lo que impide correlacionar dos SIEM.
    """
    fuera = {e.activity for e in _eventos(muestra)} - set(ACTIVITIES)
    assert not fuera, f"{muestra} emite actividades que no existen: {sorted(fuera)}"


@pytest.mark.parametrize("muestra", VOCABULARIO)
def test_la_clase_concuerda_con_la_actividad(muestra):
    """Un dns_query dentro de 'File System Activity' es una pareja imposible.

    Y era exactamente lo que pasaba con los registros de Umbrella.
    """
    for evento in _eventos(muestra):
        esperada = ACTIVITY_CLASS.get(evento.activity)
        assert evento.class_name == esperada, (
            f"{muestra}: '{evento.activity}' deberia ser {esperada} "
            f"y sale como {evento.class_name}")


@pytest.mark.parametrize("muestra", MUESTRAS)
def test_ningun_evento_se_queda_sin_clasificar(muestra):
    """'unknown' es una senal de fallo, no un valor de trabajo."""
    sin_clasificar = [e for e in _eventos(muestra) if e.activity == "unknown"]
    assert not sin_clasificar, (
        f"{muestra}: {len(sin_clasificar)} eventos sin clasificar. "
        "Hace falta un normalizador para ellos.")


@pytest.mark.parametrize("muestra", VOCABULARIO)
def test_los_valores_retirados_no_vuelven(muestra):
    """Los que se fueron a `status` o se renombraron, y por que.

    'blocked' y 'logon_failed' eran el desenlace duplicado como actividad.
    'connect', 'create', 'launch' y 'query' significaban cosas distintas segun
    quien los emitiera.
    """
    retirados = {"blocked", "logon_failed", "connect", "create", "launch",
                 "query", "create_account", "deliver", "delete", "modify", "read"}
    presentes = {e.activity for e in _eventos(muestra)} & retirados
    assert not presentes, f"{muestra} sigue emitiendo {sorted(presentes)}"


# ---------------------------------------------------------------------------
# perimeter.cef, las once lineas
# ---------------------------------------------------------------------------

# (indice, actividad, clase, status, y una comprobacion extra si hace falta)
LINEAS_CEF = [
    (0,  "network_connect", CLASS_NETWORK,        "success", "Fortinet, sesion permitida"),
    (1,  "network_connect", CLASS_NETWORK,        "success", "Zscaler, descarga permitida"),
    (2,  "network_connect", CLASS_NETWORK,        "failure", "Zscaler, bloqueo a nodo Tor"),
    (3,  "network_connect", CLASS_NETWORK,        "failure", "Fortinet, denegado por politica"),
    (4,  "network_connect", CLASS_NETWORK,        "success", "Fortinet, transferencia grande"),
    (5,  "dns_query",       CLASS_DNS,            "success", "Umbrella, resolucion DNS"),
    (6,  "malware_detect",  CLASS_FINDING,        "failure", "Defender, cuarentena fallida"),
    (7,  "network_connect", CLASS_NETWORK,        "success", "PAN-OS, trafico C2"),
    (8,  "logon",           CLASS_AUTHENTICATION, "failure", "sshd, password fallido"),
    (9,  "logon",           CLASS_AUTHENTICATION, "failure", "sshd, password fallido"),
    (10, "logon_remote",    CLASS_AUTHENTICATION, "success", "sshd, acceso correcto"),
]


@pytest.mark.parametrize("indice,actividad,clase,estado,descripcion", LINEAS_CEF)
def test_cada_linea_de_perimeter_cef(perimetro, indice, actividad, clase, estado, descripcion):
    evento = perimetro[indice]
    assert evento.activity == actividad, f"linea {indice + 1} ({descripcion})"
    assert evento.class_name == clase, f"linea {indice + 1} ({descripcion})"
    assert evento.status == estado, f"linea {indice + 1} ({descripcion})"


def test_la_peticion_dns_de_umbrella_trae_su_dominio(perimetro):
    """No basta con clasificarla bien: sin dominio el nodo no existe.

    Umbrella pone el nombre consultado en `dhost`, y `event.domain` solo se
    alimentaba desde `url` o desde `domain`/`dest_domain`/`query`. Cambiar solo
    la clasificacion habria producido una consulta DNS... sin dominio, o sea un
    nodo huerfano. Eran dos piezas.
    """
    evento = perimetro[5]
    assert evento.domain == "cdn-update-svc.com"


def test_el_trafico_c2_de_pan_os_conserva_los_dos_extremos(perimetro):
    """Salia como 'launch' porque 'command' casaba con 'command-and-control'.

    Y con eso se perdia lo unico que aporta el evento: quien habla con quien.
    """
    evento = perimetro[7]
    assert evento.src and evento.src.ip == "10.4.2.11"
    assert evento.dst and evento.dst.ip == "45.132.88.17"
    assert evento.net and evento.net.category == "command-and-control"


def test_leef_conserva_la_severidad(perimetro):
    """sev=8 salia como severidad 2 por un alias que faltaba.

    El evento mas grave del fichero era el mas facil de esconder con un filtro.
    """
    assert perimetro[7].severity >= 4


def test_la_transferencia_grande_conserva_los_bytes(perimetro):
    """700 MiB salientes. Sin ellos, la fuga es identica a abrir una web."""
    evento = perimetro[4]
    assert evento.net and evento.net.bytes_out == 734003200
    assert evento.severity >= 4, "una salida de 700 MiB no es un evento rutinario"


def test_la_deteccion_de_malware_no_dice_que_el_usuario_creo_el_fichero(perimetro):
    """El evento dice que Defender ENCONTRO m.exe, no que jlopez lo escribiera.

    Salia como creacion de fichero con exito, y el relato lo redactaba como
    "jlopez creo m.exe": el antivirus avisando de que NO pudo contener un
    volcador de credenciales, contado como una tarea rutinaria del usuario.
    """
    evento = perimetro[6]
    assert evento.activity == "malware_detect"
    assert evento.status == "failure", "act=quarantine_failed significa que sigue ahi"
    assert evento.severity == 5

    grafo = enrich(build_graph([evento]))
    verbos = {enlace.type for enlace in grafo.links}
    assert "wrote" not in verbos, "el evento no dice que nadie escribiera nada"
    # Y la maquina donde esta el fichero tiene que colgar de algo.
    sueltos = [n.id for n in grafo.nodes if n.degree == 0]
    assert not sueltos, f"nodos sin ninguna arista: {sueltos}"


def test_la_fuerza_bruta_ssh_dibuja_el_salto(perimetro):
    """Dos fallos y un acierto desde la misma IP. El patron mas reconocible.

    Antes no dibujaba NADA: el usuario y la IP se quedaban dentro de la cadena
    del mensaje de syslog, porque nadie volvia a leerla.
    """
    grafo = enrich(build_graph(perimetro))
    aristas = {(e.source, e.type, e.target) for e in grafo.links}

    assert ("user:administrator", "failed_auth", "host:srv-dc01") in aristas
    assert ("user:svc_backup", "failed_auth", "host:srv-dc01") in aristas
    # Y el acceso que si entra, desde la misma maquina, como movimiento lateral.
    assert ("host:wks-0421", "lateral", "host:srv-dc01") in aristas


def test_el_cortafuegos_no_queda_flotando(perimetro):
    """El FortiGate salia con grado 0 en el grafo 3D: una esfera suelta.

    Se podia confundir con un equipo aislado y no aportaba nada. Y al reves, se
    perdia por donde salio el trafico, que es lo unico que aporta el perimetro
    cuando el EDR no cubre esa maquina.
    """
    grafo = enrich(build_graph(perimetro))
    sueltos = [n.id for n in grafo.nodes if n.degree == 0]
    assert not sueltos, f"nodos sin ninguna arista: {sueltos}"

    cortafuegos = [n for n in grafo.nodes if n.id == "host:fgt-perim-01"]
    assert cortafuegos, "el cortafuegos deberia estar en el grafo"
    assert cortafuegos[0].degree > 0


@pytest.mark.parametrize("muestra", SIN_SUELTOS)
def test_ninguna_muestra_deja_nodos_sueltos(muestra):
    """Un nodo creado y sin aristas es un fallo, no un detalle.

    En el grafo 3D flota, ocupa sitio, se confunde con una maquina aislada y no
    cuenta nada.
    """
    grafo = enrich(build_graph(_eventos(muestra)))
    sueltos = [n.id for n in grafo.nodes if n.degree == 0]
    assert not sueltos, f"{muestra} deja sueltos: {sueltos}"
