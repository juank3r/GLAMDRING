"""Normalizador de Netskope (CASB y SWG).

LO QUE APORTA Y NINGUN SIEM DE LOS CUATRO DA. Un proxy SASE no entrega solo
trafico: entrega la identidad detras de cada sesion, la APLICACION cloud
concreta, la accion dentro de esa aplicacion, el veredicto de la politica y los
bytes en cada sentido.

La diferencia practica, con un ejemplo: un cortafuegos dice "10.4.2.11 saco 4 GB
hacia 104.18.32.7". Netskope dice "jlopez subio informe-clientes.xlsx a Mega
desde un portatil no gestionado, y la politica lo permitio". Es el mismo hecho y
son dos cosas distintas para quien tiene que decidir si aislar el equipo.

Y el hueco que tapa: un equipo con el cliente SASE puesto NO pasa por el
cortafuegos de la oficina. En el grafo de hoy ese trafico no existe, y el hueco
no se nota, que es lo peor que puede tener un hueco.

Campos segun la documentacion de eventos de aplicacion de Netskope: ``user``,
``app``, ``activity``, ``object``, ``object_type``, ``alert_type``, ``numbytes``,
``srcip``, ``dstip``, ``access_method``, ``app_session_id``, ``policy``, ``ccl``.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..mitre import technique
from ..models import (
    CLASS_AUTHENTICATION,
    CLASS_FILE,
    CLASS_FINDING,
    CLASS_NETWORK,
    ActorRef,
    FileRef,
    HostRef,
    NetRef,
    NormalizedEvent,
    SessionRef,
    make_uid,
)
from .base import (
    basename,
    canon_domain,
    canon_host,
    first,
    is_ip,
    parse_time,
    register,
    to_int,
)

# Campos que solo se ven juntos en un evento de Netskope.
_MARCADORES = ("app_session_id", "access_method", "appcategory", "traffic_type",
               "instance_id", "ccl", "nsdeviceuid", "browser_session_id")

# La actividad dentro de la aplicacion, que es lo mas valioso que da la CASB:
# no "hubo trafico" sino "que hizo la persona con el fichero".
_ACTIVIDADES = {
    "upload": ("file_upload", 3),
    "post": ("file_upload", 3),
    "put": ("file_upload", 3),
    "download": ("file_download", 2),
    "get": ("file_download", 2),
    "view": ("file_read", 1),
    "preview": ("file_read", 1),
    "open": ("file_read", 1),
    "share": ("file_share", 4),
    "unshare": ("file_share", 2),
    "invite": ("file_share", 4),
    "edit": ("file_modify", 2),
    "rename": ("file_modify", 2),
    "move": ("file_modify", 2),
    "copy": ("file_download", 2),
    "delete": ("file_delete", 3),
    "restore": ("file_modify", 2),
    "login successful": ("logon", 2),
    "login failed": ("logon", 3),
    "login attempt": ("logon", 2),
    "logout": ("logoff", 1),
}

# Categorias de aplicacion cuyo uso importa por si mismo. No son prueba de nada,
# pero son la diferencia entre "subio 4 GB a Internet" y "subio 4 GB a Mega".
_CATEGORIAS_DE_RIESGO = ("cloud storage", "file sharing", "webmail",
                         "generative ai", "anonymizer", "remote access",
                         "code repository", "personal storage")

# Actividades que sacan datos de la organizacion. Solo estas suben por volumen:
# bajarse 4 GB de SharePoint es trabajar, subirlos a Mega no.
_SALIDA_DE_DATOS = ("file_upload", "file_share")


def matches(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    if record.get("__format__"):
        return False
    presentes = sum(1 for marcador in _MARCADORES if marcador in record)
    if presentes >= 2:
        return True
    # Un evento con app y activity y algo de Netskope alrededor.
    return bool(presentes and record.get("app") and record.get("activity"))


def _clasificar(record: Dict[str, Any]):
    """Devuelve (clase, actividad, severidad base)."""
    alerta = str(first(record, "alert_type", "alert") or "").strip().lower()
    # Una alerta de DLP o de malware es un hallazgo, no una operacion de
    # fichero: el producto esta diciendo que ha encontrado algo.
    if alerta in ("dlp", "malware", "malsite", "compromised credential",
                  "anomaly", "ctep", "quarantine", "remediation"):
        clase = CLASS_FINDING
        return clase, ("malware_detect" if alerta in ("malware", "malsite") else "alert"), 4

    actividad = str(first(record, "activity") or "").strip().lower()
    for clave, (nombre, severidad) in _ACTIVIDADES.items():
        if clave in actividad:
            if nombre in ("logon", "logoff"):
                return CLASS_AUTHENTICATION, nombre, severidad
            return CLASS_FILE, nombre, severidad

    # Sin actividad reconocida pero con dos extremos, es trafico.
    if first(record, "dstip", "url", "hostname"):
        return CLASS_NETWORK, "network_connect", 2
    return CLASS_FINDING, "alert", 2


def normalize(record: Dict[str, Any]) -> Optional[NormalizedEvent]:
    clase, actividad, severidad = _clasificar(record)

    accion = str(first(record, "action") or "").strip().lower()
    # 'block' y 'userbypass' son desenlaces distintos y los dos importan: lo
    # bloqueado dice que la politica funciono, y un bypass del usuario dice que
    # alguien la esquivo a proposito.
    if accion in ("block", "blocked", "deny", "denied"):
        estado = "failure"
    elif accion in ("allow", "allowed", "alert", "bypass", "userbypass"):
        estado = "success"
    else:
        estado = "unknown"

    evento = NormalizedEvent(
        uid=make_uid("netskope", record),
        time=parse_time(first(record, "timestamp", "_insertion_epoch_timestamp",
                              "time", "@timestamp")),
        source="generic",
        origin=str(first(record, "app", "appcategory") or "netskope"),
        class_name=clase,
        activity=actividad,
        severity=severidad,
        status=estado,
        message=_mensaje(record, actividad),
        raw=record,
    )

    usuario = first(record, "user", "userkey", "srcip_user", "user_id")
    if usuario:
        evento.actor = ActorRef(user=str(usuario),
                                domain=str(first(record, "userip_domain", "org") or "") or None)

    # La aplicacion cloud, que es el dato que ningun SIEM da. Va a `app` y no a
    # `dst` a proposito: Dropbox no es una maquina, y meterla como host llenaba
    # el grafo de "equipos" llamados 'Microsoft Office 365 Portal'.
    app = first(record, "app", "appname")
    if app:
        evento.app = str(app)

    origen_ip = first(record, "srcip", "src_ip", "client_ip", "userip")
    if origen_ip and is_ip(str(origen_ip)):
        evento.src = HostRef(ip=str(origen_ip), port=to_int(first(record, "srcport")))
    equipo = canon_host(first(record, "device", "hostname", "device_name"))
    if equipo:
        evento.device = HostRef(hostname=equipo)

    destino_ip = first(record, "dstip", "dst_ip", "server_ip")
    if destino_ip and is_ip(str(destino_ip)):
        evento.dst = HostRef(ip=str(destino_ip), port=to_int(first(record, "dstport")))

    url = first(record, "url", "referer")
    if url:
        evento.url = str(url)
        evento.domain = canon_domain(str(url).split("//")[-1].split("/")[0].split(":")[0])
    if not evento.domain:
        evento.domain = canon_domain(first(record, "domain", "hostname"))

    # El objeto sobre el que se actua: casi siempre un fichero dentro de la
    # aplicacion. Es lo que convierte "subio algo" en "subio nominas.xlsx".
    objeto = first(record, "object", "file_name", "filename")
    tipo_objeto = str(first(record, "object_type") or "").lower()
    if objeto and (clase == CLASS_FILE or "file" in tipo_objeto or "document" in tipo_objeto):
        evento.file = FileRef(
            name=basename(objeto) or str(objeto),
            path=str(objeto),
            sha256=str(first(record, "sha256", "file_hash") or "").lower() or None,
            md5=str(first(record, "md5") or "").lower() or None,
            size=to_int(first(record, "file_size", "object_size")),
        )

    # Los bytes en cada sentido. La asimetria es la firma de la exfiltracion.
    subidos = to_int(first(record, "client_bytes", "bytes_uploaded", "req_size"))
    bajados = to_int(first(record, "server_bytes", "bytes_downloaded", "resp_size"))
    total = to_int(first(record, "numbytes", "bytes"))
    if total and not (subidos or bajados):
        # Netskope da el total; se atribuye al sentido de la actividad, que es
        # lo unico que se sabe. No se reparte a medias: inventar un reparto
        # seria peor que dar solo el total.
        if actividad in _SALIDA_DE_DATOS:
            subidos = total
        elif actividad == "file_download":
            bajados = total
    categoria = first(record, "appcategory", "category", "urlcategory")
    politica = first(record, "policy", "policy_name", "dlp_profile")
    if any((subidos, bajados, categoria, politica)):
        evento.net = NetRef(bytes_in=bajados, bytes_out=subidos,
                            protocol=str(first(record, "protocol") or "").lower() or None,
                            rule=str(politica) if politica else None,
                            category=str(categoria) if categoria else None)

    # La sesion del cliente SASE.
    sesion = first(record, "app_session_id", "browser_session_id", "session_id")
    if sesion:
        evento.session = SessionRef(
            id=str(sesion),
            assigned_ip=str(origen_ip) if origen_ip and is_ip(str(origen_ip)) else None,
            client=str(first(record, "access_method", "client_version") or "") or None,
            location=str(first(record, "src_location", "location", "src_country") or "") or None,
        )

    _afinar(evento, record, actividad, categoria)
    return evento


def _mensaje(record: Dict[str, Any], actividad: str) -> str:
    """Una frase que se entienda en el inspector sin abrir el registro crudo."""
    usuario = first(record, "user") or "alguien"
    accion = str(first(record, "activity") or actividad).strip()
    app = first(record, "app") or "una aplicacion cloud"
    objeto = first(record, "object", "file_name")
    alerta = first(record, "alert_type")
    partes = [f"{usuario}: {accion} en {app}"]
    if objeto:
        partes.append(f"({objeto})")
    if alerta:
        partes.append(f"[alerta {alerta}]")
    return " ".join(partes)[:400]


def _afinar(evento: NormalizedEvent, record: Dict[str, Any],
            actividad: str, categoria: Any) -> None:
    baja = str(categoria or "").lower()
    de_riesgo = any(c in baja for c in _CATEGORIAS_DE_RIESGO)

    if de_riesgo and actividad in _SALIDA_DE_DATOS:
        # Subir a almacenamiento personal o compartir fuera. Aqui si hay una
        # afirmacion defendible que hacer.
        evento.severity = max(evento.severity, 4)
        tech = technique("T1567.002")
        if tech:
            evento.mitre = [tech]

    salientes = evento.net.bytes_out if evento.net else None
    if salientes and salientes > 100 * 1024 * 1024 and actividad in _SALIDA_DE_DATOS:
        evento.severity = max(evento.severity, 4)
        if not evento.mitre:
            tech = technique("T1567")
            if tech:
                evento.mitre = [tech]

    # Un equipo no gestionado tocando datos de la empresa merece mirarse: no es
    # un ataque, es una via por la que los datos salen del perimetro de control.
    if str(first(record, "device_classification") or "").lower() in ("unmanaged", "not managed"):
        evento.severity = max(evento.severity, 3)

    if evento.activity == "logon" and evento.status == "failure":
        tech = technique("T1078.004")
        if tech and not evento.mitre:
            evento.mitre = [tech]


# Prioridad 9: antes que el generico y antes que los cuatro SIEM, porque sus
# marcadores son inconfundibles y no hay riesgo de robarles registros.
register("netskope", matches, normalize, priority=9)
