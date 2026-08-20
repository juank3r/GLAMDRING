"""Normalizador de Microsoft Sentinel / Defender (Advanced Hunting).

Las filas de Log Analytics no dicen de que tabla vienen: la tabla es metadato de
la consulta. El conector inyecta ``Type`` en cada fila antes de llegar aqui, y
si falta se deduce por los campos presentes (``DeviceProcessEvents`` es la unica
tabla con ``ProcessCommandLine`` + ``InitiatingProcessFileName``, por ejemplo).

Ventaja de esta fuente: Defender ya trae tacticas y tecnicas ATT&CK etiquetadas,
asi que aqui casi no hay que inferir nada.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..mitre import infer_from_cmdline, techniques
from ..models import (
    CLASS_AUTHENTICATION,
    CLASS_DNS,
    CLASS_EMAIL,
    CLASS_FILE,
    CLASS_FINDING,
    CLASS_NETWORK,
    CLASS_PROCESS,
    ActorRef,
    EmailRef,
    FileRef,
    HostRef,
    NormalizedEvent,
    ProcRef,
    make_uid,
)
from .base import (
    basename,
    canon_domain,
    canon_host,
    first,
    is_ip,
    parse_severity,
    parse_time,
    register,
    to_int,
)

# Marcadores que solo aparecen en tablas de Microsoft.
_MS_MARKERS = (
    "TimeGenerated", "DeviceName", "AlertName", "UserPrincipalName",
    "InitiatingProcessFileName", "ReportId", "DeviceId",
)


def matches(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    table = str(record.get("Type") or record.get("TableName") or "")
    if table in _TABLES:
        return True
    return sum(1 for marker in _MS_MARKERS if marker in record) >= 2


def _guess_table(record: Dict[str, Any]) -> str:
    """Deduce la tabla por la huella de campos cuando no viene ``Type``."""
    if "AlertName" in record or "AlertSeverity" in record:
        return "SecurityAlert"
    if "ProcessCommandLine" in record or "FolderPath" in record:
        return "DeviceProcessEvents"
    if "RemoteUrl" in record or "RemoteIP" in record:
        return "DeviceNetworkEvents"
    if "UserPrincipalName" in record and "ResultType" in record:
        return "SigninLogs"
    if "SenderFromAddress" in record or "RecipientEmailAddress" in record:
        return "EmailEvents"
    if "SHA256" in record and "FileName" in record:
        return "DeviceFileEvents"
    if "LogonType" in record:
        return "DeviceLogonEvents"
    return ""


def _base(record: Dict[str, Any], table: str, class_name: str, activity: str, severity: int) -> NormalizedEvent:
    device = canon_host(first(record, "DeviceName", "Computer", "HostName"))
    return NormalizedEvent(
        uid=make_uid("sentinel", record),
        time=parse_time(first(record, "TimeGenerated", "Timestamp", "EventTime")),
        source="sentinel",
        origin=table or "sentinel",
        class_name=class_name,
        activity=activity,
        severity=severity,
        status="unknown",
        message=str(first(record, "AlertName", "Description", "ActionType", "Title") or "")[:400],
        device=HostRef(hostname=device) if device else None,
        raw=record,
    )


def _initiating_process(record: Dict[str, Any]) -> Optional[ProcRef]:
    """El proceso que origina la accion (comun a casi todas las tablas Device*)."""
    name = first(record, "InitiatingProcessFileName")
    if not name:
        return None
    folder = first(record, "InitiatingProcessFolderPath")
    return ProcRef(
        name=basename(name),
        path=str(folder) if folder else str(name),
        cmdline=str(first(record, "InitiatingProcessCommandLine") or "") or None,
        pid=to_int(first(record, "InitiatingProcessId")),
        parent_name=basename(first(record, "InitiatingProcessParentFileName")),
        parent_pid=to_int(first(record, "InitiatingProcessParentId")),
    )


# ---------------------------------------------------------------------------
# Tablas
# ---------------------------------------------------------------------------


def _device_process(record: Dict[str, Any]) -> NormalizedEvent:
    event = _base(record, "DeviceProcessEvents", CLASS_PROCESS, "launch", 2)
    event.status = "success"

    name = first(record, "FileName", "ProcessName")
    folder = first(record, "FolderPath")
    event.process = ProcRef(
        name=basename(name),
        path=str(folder) if folder else (str(name) if name else None),
        cmdline=str(first(record, "ProcessCommandLine") or "") or None,
        pid=to_int(first(record, "ProcessId")),
        parent_name=basename(first(record, "InitiatingProcessFileName")),
        parent_path=str(first(record, "InitiatingProcessFolderPath") or "") or None,
        parent_pid=to_int(first(record, "InitiatingProcessId")),
    )
    user = first(record, "AccountName", "InitiatingProcessAccountName", "AccountUpn")
    if user:
        event.actor = ActorRef(user=str(user),
                               domain=str(first(record, "AccountDomain") or "") or None)
    sha = first(record, "SHA256")
    if sha:
        event.file = FileRef(name=basename(name), path=str(folder) if folder else None,
                             sha256=str(sha).lower(), md5=str(first(record, "MD5") or "").lower() or None)

    event.mitre = infer_from_cmdline(event.process.cmdline)
    if event.mitre:
        event.severity = max(event.severity, 3)
    return event


def _device_network(record: Dict[str, Any]) -> NormalizedEvent:
    event = _base(record, "DeviceNetworkEvents", CLASS_NETWORK, "connect", 2)
    action = str(first(record, "ActionType") or "").lower()
    event.status = "failure" if "fail" in action or "block" in action else "success"
    if "block" in action:
        event.activity = "blocked"

    remote_ip = first(record, "RemoteIP")
    remote_url = first(record, "RemoteUrl")
    event.dst = HostRef(
        ip=str(remote_ip) if remote_ip and is_ip(str(remote_ip)) else None,
        hostname=None,
        port=to_int(first(record, "RemotePort")),
    )
    if remote_url:
        event.url = str(remote_url)
        host_part = str(remote_url).split("//")[-1].split("/")[0].split(":")[0]
        event.domain = canon_domain(host_part)

    local_ip = first(record, "LocalIP")
    if local_ip:
        event.src = HostRef(ip=str(local_ip), port=to_int(first(record, "LocalPort")))
        # LocalIP es, por definicion, la IP del equipo que reporta. Guardarla en
        # el device es lo que luego funde 'ip:10.4.1.5' con 'host:srv-dc01'.
        if event.device and is_ip(str(local_ip)):
            event.device.ip = str(local_ip)

    event.process = _initiating_process(record)
    user = first(record, "InitiatingProcessAccountName", "InitiatingProcessAccountUpn")
    if user:
        event.actor = ActorRef(user=str(user))

    from .base import is_private_ip

    if event.dst.ip and not is_private_ip(event.dst.ip):
        event.severity = max(event.severity, 3)
    return event


def _device_file(record: Dict[str, Any]) -> NormalizedEvent:
    action = str(first(record, "ActionType") or "FileCreated")
    activity = "delete" if "delete" in action.lower() else ("modify" if "modif" in action.lower() else "create")
    event = _base(record, "DeviceFileEvents", CLASS_FILE, activity, 2)
    event.status = "success"
    event.file = FileRef(
        name=basename(first(record, "FileName")),
        path=str(first(record, "FolderPath") or first(record, "FileName") or "") or None,
        sha256=str(first(record, "SHA256") or "").lower() or None,
        md5=str(first(record, "MD5") or "").lower() or None,
        size=to_int(first(record, "FileSize")),
    )
    event.process = _initiating_process(record)
    user = first(record, "InitiatingProcessAccountName")
    if user:
        event.actor = ActorRef(user=str(user))
    return event


def _device_logon(record: Dict[str, Any]) -> NormalizedEvent:
    action = str(first(record, "ActionType") or "").lower()
    success = "success" in action or action == "logonsuccess"
    event = _base(record, "DeviceLogonEvents", CLASS_AUTHENTICATION,
                  "logon" if success else "logon_failed", 2 if success else 3)
    event.status = "success" if success else "failure"
    user = first(record, "AccountName", "AccountUpn")
    event.actor = ActorRef(user=str(user) if user else None,
                           domain=str(first(record, "AccountDomain") or "") or None)
    remote_ip = first(record, "RemoteIP")
    remote_device = first(record, "RemoteDeviceName")
    if remote_ip or remote_device:
        event.src = HostRef(ip=str(remote_ip) if remote_ip and is_ip(str(remote_ip)) else None,
                            hostname=canon_host(remote_device) if remote_device else None)
    logon_type = str(first(record, "LogonType") or "").lower()
    if success and logon_type in ("network", "remoteinteractive"):
        event.activity = "logon_remote"
        event.mitre = techniques("T1021.001" if logon_type == "remoteinteractive" else "T1021.002")
    return event


def _signin(record: Dict[str, Any]) -> NormalizedEvent:
    result = to_int(first(record, "ResultType"))
    success = result == 0
    event = _base(record, "SigninLogs", CLASS_AUTHENTICATION,
                  "logon" if success else "logon_failed", 2 if success else 3)
    event.status = "success" if success else "failure"
    upn = first(record, "UserPrincipalName", "UserDisplayName", "Identity")
    event.actor = ActorRef(user=str(upn) if upn else None)
    ip = first(record, "IPAddress")
    if ip:
        event.src = HostRef(ip=str(ip))
    app = first(record, "AppDisplayName", "ResourceDisplayName")
    if app:
        event.app = str(app)
    if not success:
        event.mitre = techniques("T1110")
    return event


def _email(record: Dict[str, Any]) -> NormalizedEvent:
    event = _base(record, "EmailEvents", CLASS_EMAIL, "deliver", 3)
    # Los dos campos a la vez: un correo con DeliveryAction=Delivered y
    # ThreatTypes=Phish es justo el caso peligroso, porque llego a la bandeja.
    verdict = " ".join(str(record.get(k) or "") for k in ("DeliveryAction", "ThreatTypes")).lower()
    event.status = "failure" if "block" in verdict else "success"
    event.email = EmailRef(
        sender=str(first(record, "SenderFromAddress", "SenderMailFromAddress") or "") or None,
        recipient=str(first(record, "RecipientEmailAddress") or "") or None,
        subject=str(first(record, "Subject") or "") or None,
        url=str(first(record, "Url", "UrlDomain") or "") or None,
    )
    if "phish" in verdict or "malware" in verdict:
        event.severity = 4
        event.mitre = techniques("T1566.002")
    return event


def _parse_entities(value: Any) -> List[Dict[str, Any]]:
    """``SecurityAlert.Entities`` viene como cadena JSON, no como lista."""
    if not value:
        return []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return []
    return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []


def _alert(record: Dict[str, Any]) -> NormalizedEvent:
    """SecurityAlert / SecurityIncident: la alerta y todo lo que toca."""
    event = _base(record, "SecurityAlert", CLASS_FINDING, "alert",
                  parse_severity(first(record, "AlertSeverity", "Severity"), scale_max=5))
    event.status = "unknown"
    event.message = str(first(record, "AlertName", "DisplayName", "Title") or "Alerta")[:400]
    event.mitre = techniques(first(record, "Techniques", "Tactics"))

    # Las entidades de la alerta se vuelcan a los campos OCSF que correspondan;
    # el extractor las convertira en aristas 'affects' colgando de la alerta.
    entities = _parse_entities(record.get("Entities"))
    extra: List[Dict[str, Any]] = []
    for item in entities:
        kind = str(item.get("Type") or item.get("$id") or "").lower()
        if kind == "host":
            name = canon_host(item.get("HostName") or item.get("NetBiosName"))
            if name and not event.device:
                event.device = HostRef(hostname=name)
            elif name:
                extra.append({"type": "host", "value": name})
        elif kind == "account":
            name = item.get("Name") or item.get("AadUserId")
            if name and not event.actor:
                event.actor = ActorRef(user=str(name), domain=str(item.get("UPNSuffix") or "") or None)
            elif name:
                extra.append({"type": "user", "value": str(name)})
        elif kind == "ip":
            addr = item.get("Address")
            if addr and not event.dst:
                event.dst = HostRef(ip=str(addr))
            elif addr:
                extra.append({"type": "ip", "value": str(addr)})
        elif kind in ("file", "filehash"):
            name = item.get("Name") or item.get("Value")
            if name and not event.file:
                event.file = FileRef(name=basename(str(name)),
                                     sha256=str(item.get("Value") or "").lower() or None)
        elif kind in ("url", "dnsresolution"):
            value = item.get("Url") or item.get("DomainName")
            if value:
                event.url = str(value)
                event.domain = canon_domain(str(value).split("//")[-1].split("/")[0])

    compromised = first(record, "CompromisedEntity")
    if compromised and not event.device:
        event.device = HostRef(hostname=canon_host(compromised))

    if extra:
        event.raw = dict(record)
        event.raw["_extra_entities"] = extra
    return event


def _dns(record: Dict[str, Any]) -> NormalizedEvent:
    event = _base(record, "DeviceEvents", CLASS_DNS, "query", 1)
    event.domain = canon_domain(first(record, "RemoteUrl", "AdditionalFields"))
    event.process = _initiating_process(record)
    return event


_TABLES = {
    "DeviceProcessEvents": _device_process,
    "DeviceNetworkEvents": _device_network,
    "DeviceFileEvents": _device_file,
    "DeviceLogonEvents": _device_logon,
    "SigninLogs": _signin,
    "AADNonInteractiveUserSignInLogs": _signin,
    "EmailEvents": _email,
    "SecurityAlert": _alert,
    "SecurityIncident": _alert,
    "DeviceEvents": _dns,
}


def normalize(record: Dict[str, Any]) -> Optional[NormalizedEvent]:
    table = str(record.get("Type") or record.get("TableName") or "") or _guess_table(record)
    handler = _TABLES.get(table)
    if handler is None:
        return None
    return handler(record)


register("sentinel_defender", matches, normalize, priority=10)
