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
