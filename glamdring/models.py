"""Contratos de datos de GLAMDRING.

Dos modelos importan de verdad:

* ``NormalizedEvent`` -- un evento de cualquier SIEM traducido a un subconjunto
  pragmatico de OCSF (Open Cybersecurity Schema Framework). Es la frontera entre
  "cada fabricante hace lo que quiere" y el resto del sistema.
* ``GraphDoc`` -- lo unico que llega al navegador. Los nombres de campo
  (``id`` / ``source`` / ``target``) son los que ``3d-force-graph`` espera por
  defecto, para no tener que reconfigurar accesores en el frontend.

Regla que no se rompe: ``NormalizedEvent.raw`` conserva SIEMPRE el registro
original. Todo nodo y toda arista del grafo pueden volver al log literal del
SIEM; sin eso la herramienta no es defendible en un informe.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

SourceId = Literal["splunk", "sentinel", "qradar", "elastic", "generic"]

Status = Literal["success", "failure", "unknown"]

# Clases de evento OCSF que usamos (nombre legible; el uid OCSF va en class_uid).
CLASS_AUTHENTICATION = "Authentication"
CLASS_PROCESS = "Process Activity"
CLASS_NETWORK = "Network Activity"
CLASS_FILE = "File System Activity"
CLASS_FINDING = "Detection Finding"
CLASS_EMAIL = "Email Activity"
CLASS_DNS = "DNS Activity"
CLASS_ACCOUNT = "Account Change"
# La ontologia YA admitia nodos de tipo 'registry' (enrich.CONTEXT_TYPES),
# pero no habia clase que los produjera: extract.py no crea ese nodo en
# ningun sitio. Sin ella, Sysmon 12/13 -las claves Run, que son LA forma
# clasica de persistencia en Windows- salian como 'launch' y sin el objeto
# tocado, o sea sin decir QUE clave se habia escrito.
CLASS_REGISTRY = "Registry Value Activity"

# Correspondencia con los class_uid reales de OCSF, por si algun dia se exporta
# a un data lake que los espere.
CLASS_UIDS: Dict[str, int] = {
    CLASS_AUTHENTICATION: 3002,
    CLASS_ACCOUNT: 3001,
    CLASS_PROCESS: 1007,
    CLASS_FILE: 1001,
    CLASS_NETWORK: 4001,
    CLASS_DNS: 4003,
    CLASS_EMAIL: 4009,
    CLASS_FINDING: 2004,
    CLASS_REGISTRY: 201003,
}


# ---------------------------------------------------------------------------
# Vocabulario cerrado de `activity`
# ---------------------------------------------------------------------------
#
# POR QUE CERRADO. Antes cada normalizador ponia la cadena que le parecia, y el
# resultado medido eran catorce valores sin definicion con la MISMA cosa en tres
# nombres: una resolucion DNS del mismo dominio salia como 'query' desde Splunk,
# 'connect' desde QRadar y 'create' desde CEF.
#
# Eso no es un problema de estilo. Es lo que impide correlacionar dos SIEM, que
# es el motivo entero por el que existe esta herramienta: si el mismo hecho no
# produce el mismo valor, el grafo no puede unir lo que cuenta uno con lo que
# cuenta el otro, y juntar dos SIEM se queda en ponerlos uno al lado del otro.
#
# TRES REGLAS, cada una comprobada midiendo y no opinando:
#
# 1. EL DESENLACE NO ES UNA ACTIVIDAD, va en `status`. 'blocked' y
#    'logon_failed' desaparecen. Comprobado colapsandolos sobre los once eventos
#    que los llevaban: nodos, aristas, frase del relato e is_key_event salen
#    IDENTICOS. Eran dos nombres que no ganaban nada y rompian la correlacion.
#
# 2. UN VALOR SOLO EXISTE SI CAMBIA ALGO. Es la contraprueba de la regla
#    anterior: 'logon_remote' SI se queda, porque colapsarlo a 'logon' cambia la
#    arista de 'lateral' a 'connected' y la frase pierde lo que la hacia util.
#
# 3. EL VALOR ES UNICO EN TODO EL VOCABULARIO, no dentro de su clase. Antes
#    'create' significaba a la vez fichero creado, consulta DNS y deteccion de
#    antivirus, asi que filtrar por actividad obligaba a filtrar tambien por
#    clase. Con el objeto delante -file_create, dns_query- se filtra solo.

ACTIVITIES: Dict[str, str] = {
    # -- Authentication -----------------------------------------------------
    "logon": "Inicio de sesion local o interactivo en el equipo que lo registra",
    "logon_remote": "Inicio de sesion desde otra maquina de la red (tipos 3 y 10, SSH)",
    "logon_explicit": "Autenticacion con credenciales distintas a las de la sesion (4648, runas)",
    "logoff": "Cierre de sesion (4634, 4647)",
    "auth_ticket": "Peticion o renovacion de ticket Kerberos (4768, 4769)",
    # -- Account Change -----------------------------------------------------
    "account_create": "Se crea una cuenta de usuario o de servicio",
    "account_modify": "Cambio de contrasena, atributos o estado de una cuenta",
    "account_delete": "Se elimina una cuenta",
    "group_member_add": "Una cuenta se anade a un grupo (4728, 4732)",
    # -- Process Activity ---------------------------------------------------
    "process_launch": "Creacion de proceso",
    "process_terminate": "Fin de proceso (Sysmon 5)",
    "process_inject": "Un proceso escribe en el espacio de otro (Sysmon 8, T1055)",
    "process_access": "Un proceso abre un handle sobre otro (Sysmon 10, LSASS = T1003.001)",
    "module_load": "Carga de DLL o imagen en un proceso (Sysmon 7)",
    # -- File System Activity -----------------------------------------------
    "file_create": "Se escribe un fichero nuevo en disco",
    "file_modify": "Se altera contenido o metadatos de un fichero (incluye timestomp)",
    "file_delete": "Se borra un fichero (Sysmon 23, T1070.004)",
    "file_read": "Se abre un fichero para lectura",
    "file_upload": "Subida de fichero a una aplicacion cloud",
    "file_download": "Descarga desde una aplicacion cloud o desde la web",
    "file_share": "Se concede acceso a un fichero cloud (enlace publico, invitado)",
    # -- Registry Value Activity --------------------------------------------
    "registry_set": "Se crea o modifica una clave de registro (Sysmon 12/13, Run = T1547.001)",
    "registry_delete": "Se borra una clave o valor de registro",
    # -- Network Activity ---------------------------------------------------
    "network_connect": "Conexion o flujo entre dos extremos; permitida o denegada segun status",
    "tunnel_open": "Se establece una sesion de tunel (SASE, VPN, ZTNA)",
    "tunnel_close": "Fin de una sesion de tunel",
    # -- DNS Activity -------------------------------------------------------
    "dns_query": "Resolucion de un nombre, con o sin respuesta",
    # -- Email Activity -----------------------------------------------------
    "email_deliver": "El correo llega al buzon",
    "email_quarantine": "El correo se entrega neutralizado o desviado (Junked, Replaced)",
    "email_access": "Acceso a elementos del buzon (MailItemsAccessed, T1114)",
    # -- Detection Finding --------------------------------------------------
    "alert": "Un producto de deteccion o correlacion emite un hallazgo",
    "malware_detect": "Un AV o EDR identifica un artefacto malicioso",
    "log_clear": "Se vacia un registro de auditoria (1102). Severidad minima 4",
    # -- Reservado ----------------------------------------------------------
    # No es un valor de trabajo: es una SENAL DE FALLO. Significa que el
    # normalizador reclamo el registro y no supo con que quedarse. Se cuenta y
    # se expone en la ingesta; que llegue al grafo en silencio es el fallo.
    "unknown": "El normalizador reclamo el registro y no supo clasificarlo",
}

# La clase OCSF de cada actividad. Existe para poder comprobar que un
# normalizador no emite una pareja imposible, como un dns_query dentro de
# 'File System Activity', que es exactamente lo que hacia CEF con Umbrella.
ACTIVITY_CLASS: Dict[str, str] = {
    "logon": CLASS_AUTHENTICATION, "logon_remote": CLASS_AUTHENTICATION,
    "logon_explicit": CLASS_AUTHENTICATION, "logoff": CLASS_AUTHENTICATION,
    "auth_ticket": CLASS_AUTHENTICATION,
    "account_create": CLASS_ACCOUNT, "account_modify": CLASS_ACCOUNT,
    "account_delete": CLASS_ACCOUNT, "group_member_add": CLASS_ACCOUNT,
    "process_launch": CLASS_PROCESS, "process_terminate": CLASS_PROCESS,
    "process_inject": CLASS_PROCESS, "process_access": CLASS_PROCESS,
    "module_load": CLASS_PROCESS,
    "file_create": CLASS_FILE, "file_modify": CLASS_FILE,
    "file_delete": CLASS_FILE, "file_read": CLASS_FILE,
    "file_upload": CLASS_FILE, "file_download": CLASS_FILE, "file_share": CLASS_FILE,
    "registry_set": CLASS_REGISTRY, "registry_delete": CLASS_REGISTRY,
    "network_connect": CLASS_NETWORK,
    "tunnel_open": CLASS_NETWORK, "tunnel_close": CLASS_NETWORK,
    "dns_query": CLASS_DNS,
    "email_deliver": CLASS_EMAIL, "email_quarantine": CLASS_EMAIL,
    "email_access": CLASS_EMAIL,
    "alert": CLASS_FINDING, "malware_detect": CLASS_FINDING, "log_clear": CLASS_FINDING,
    "unknown": CLASS_FINDING,
}


# ---------------------------------------------------------------------------
# Sub-objetos de un evento
# ---------------------------------------------------------------------------


class Technique(BaseModel):
    """Tecnica MITRE ATT&CK asociada al evento."""

    id: str  # 'T1021.002'
    name: str = ""
    tactic: str = ""  # slug: 'lateral-movement'


class ActorRef(BaseModel):
    """Quien hace la accion."""

    user: Optional[str] = None
    domain: Optional[str] = None
    sid: Optional[str] = None
    session_id: Optional[str] = None


class HostRef(BaseModel):
    """Un extremo de red: puede tener hostname, IP o ambos."""

    hostname: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    mac: Optional[str] = None
    os: Optional[str] = None

    def is_empty(self) -> bool:
        return not (self.hostname or self.ip)


class NetRef(BaseModel):
    """Lo que se movio por una conexion, y bajo que regla.

    Va aparte de HostRef porque no describe un extremo sino el TRAFICO entre
    dos. Sin esto, 'Large Outbound Transfer' con 700 MiB salientes quedaba
    indistinguible de abrir una pagina web: el dato que convierte una conexion
    en una exfiltracion se tiraba al normalizar.
    """

    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    protocol: Optional[str] = None
    rule: Optional[str] = None       # regla de cortafuegos o politica que actuo
    category: Optional[str] = None   # categoria del destino segun el proxy

    def is_empty(self) -> bool:
        return not any((self.bytes_in, self.bytes_out, self.protocol,
                        self.rule, self.category))


class RegistryRef(BaseModel):
    """Una clave de registro de Windows."""

    key: Optional[str] = None      # HKLM\\Software\\Microsoft\\...\\Run
    value: Optional[str] = None    # nombre del valor
    data: Optional[str] = None     # contenido, normalmente la ruta que se ejecuta

    def is_empty(self) -> bool:
        return not self.key


class ProcRef(BaseModel):
    """Un proceso, y opcionalmente su padre."""

    name: Optional[str] = None
    path: Optional[str] = None
    cmdline: Optional[str] = None
    pid: Optional[int] = None
    parent_name: Optional[str] = None
    parent_path: Optional[str] = None
    parent_pid: Optional[int] = None
    integrity: Optional[str] = None

    def is_empty(self) -> bool:
        return not (self.name or self.path)


class FileRef(BaseModel):
    name: Optional[str] = None
    path: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    size: Optional[int] = None

    def is_empty(self) -> bool:
        return not (self.name or self.path or self.sha256 or self.md5)


class EmailRef(BaseModel):
    sender: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    url: Optional[str] = None


# ---------------------------------------------------------------------------
# Evento normalizado
# ---------------------------------------------------------------------------


class NormalizedEvent(BaseModel):
    """Un evento de SIEM en forma OCSF-lite."""

    uid: str
    time: datetime
    source: SourceId = "generic"
    origin: str = ""  # sourcetype / tabla / QID de donde vino, para depurar
    class_name: str = CLASS_FINDING
    activity: str = "unknown"
    severity: int = Field(default=1, ge=0, le=5)
    status: Status = "unknown"
    message: str = ""

    actor: Optional[ActorRef] = None
    src: Optional[HostRef] = None
    dst: Optional[HostRef] = None
    device: Optional[HostRef] = None
    process: Optional[ProcRef] = None
    file: Optional[FileRef] = None
    email: Optional[EmailRef] = None
    domain: Optional[str] = None  # dominio/FQDN consultado o contactado
    url: Optional[str] = None
    # Aplicacion cloud contra la que se autentica (Office 365, AWS Console...).
    # Va aparte de `dst` a proposito: no es una maquina y meterla como host
    # llenaba el grafo de "equipos" llamados 'Microsoft Office 365 Portal'.
    app: Optional[str] = None
    # Lo que se movio por la conexion. La asimetria entre bytes_in y bytes_out
    # es la firma de la exfiltracion.
    net: Optional[NetRef] = None
    registry: Optional[RegistryRef] = None
    # Proceso DESTINO. Solo lo llevan process_inject y process_access, que son
    # los dos unicos hechos con dos procesos en un mismo evento: quien inyecta y
    # en quien, quien abre el handle y sobre quien.
    target_process: Optional[ProcRef] = None

    mitre: List[Technique] = Field(default_factory=list)
    raw: Dict[str, Any] = Field(default_factory=dict)

    @property
    def class_uid(self) -> int:
        return CLASS_UIDS.get(self.class_name, 0)

    @property
    def tactics(self) -> List[str]:
        return [t.tactic for t in self.mitre if t.tactic]


# ---------------------------------------------------------------------------
# Grafo
# ---------------------------------------------------------------------------


class Node(BaseModel):
    """Una entidad. ``id`` es la clave canonica '<tipo>:<valor normalizado>'."""

    id: str
    type: str
    label: str
    first_seen: Optional[datetime] = Field(default=None, alias="firstSeen")
    last_seen: Optional[datetime] = Field(default=None, alias="lastSeen")
    event_count: int = Field(default=0, alias="eventCount")
    max_severity: int = Field(default=0, alias="maxSeverity")
    risk: int = 0
    degree: int = 0
    sources: List[str] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    props: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


class Link(BaseModel):
    """Una relacion dirigida entre dos entidades, agregada en el tiempo."""

    id: str
    source: str
    target: str
    type: str
    count: int = 1
    severity: int = 0
    first_seen: Optional[datetime] = Field(default=None, alias="firstSeen")
    last_seen: Optional[datetime] = Field(default=None, alias="lastSeen")
    event_uids: List[str] = Field(default_factory=list, alias="eventUids")
    sources: List[str] = Field(default_factory=list)
    props: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


class GraphWindow(BaseModel):
    from_: Optional[datetime] = Field(default=None, alias="from")
    to: Optional[datetime] = None

    model_config = {"populate_by_name": True}


class GraphMeta(BaseModel):
    generated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    window: GraphWindow = Field(default_factory=GraphWindow)
    counts: Dict[str, int] = Field(default_factory=dict)
    sources: List[str] = Field(default_factory=list)
    truncated: bool = False
    notes: List[str] = Field(default_factory=list)


class GraphDoc(BaseModel):
    """El unico contrato que consume el frontend."""

    meta: GraphMeta = Field(default_factory=GraphMeta)
    nodes: List[Node] = Field(default_factory=list)
    links: List[Link] = Field(default_factory=list)


class TimelineBucket(BaseModel):
    t: datetime
    count: int
    max_severity: int = Field(default=0, alias="maxSeverity")

    model_config = {"populate_by_name": True}


class Timeline(BaseModel):
    bucket_seconds: int = Field(alias="bucketSeconds")
    buckets: List[TimelineBucket] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Utilidades compartidas por los normalizadores
# ---------------------------------------------------------------------------


def make_uid(source: str, raw: Dict[str, Any]) -> str:
    """Hash estable del registro crudo.

    Sirve para deduplicar cuando el mismo evento llega por dos caminos (p.ej. el
    reenvio de Defender a Sentinel y a Splunk a la vez). Se ordenan las claves
    para que el hash no dependa del orden de serializacion.
    """
    blob = json.dumps(raw, sort_keys=True, default=str, ensure_ascii=False)
    digest = hashlib.sha256(f"{source}|{blob}".encode("utf-8")).hexdigest()
    return digest[:16]


def utc(dt: datetime) -> datetime:
    """Normaliza a UTC consciente de zona. Los naive se asumen UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
