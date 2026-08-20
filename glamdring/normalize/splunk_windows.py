"""Normalizador de Splunk: WinEventLog Security, Sysmon y CIM generico.

Splunk entrega el resultado de una busqueda como una lista de diccionarios con
``_time`` y ``_raw`` mas los campos extraidos. Aqui se traduce el EventCode
(4624, 4688, Sysmon 1/3/11...) a la clase OCSF correspondiente.

Los nombres de campo de WinEventLog varian segun la version del TA de Windows
(``Account_Name`` vs ``TargetUserName``, ``New_Process_Name`` vs ``NewProcessName``),
por eso todo pasa por ``first()`` con varios candidatos.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..mitre import infer_from_cmdline, technique
from ..models import (
    CLASS_ACCOUNT,
    CLASS_AUTHENTICATION,
    CLASS_DNS,
    CLASS_FILE,
    CLASS_NETWORK,
    CLASS_PROCESS,
    ActorRef,
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
    parse_time,
    register,
    to_int,
)

# Tipos de logon de Windows que nos interesan.
#   2  interactivo local        3  red (SMB, share)        10 RDP
#   5  servicio                 4  batch                   9  new credentials
LOGON_TYPE_LABELS = {
    2: "interactivo", 3: "red", 4: "batch", 5: "servicio",
    7: "desbloqueo", 8: "red texto claro", 9: "nuevas credenciales",
    10: "RDP", 11: "cacheado",
}

# Logon remotos: los que pueden significar movimiento lateral.
REMOTE_LOGON_TYPES = {3, 8, 9, 10}


def matches(record: Dict[str, Any]) -> bool:
    """Reconoce un registro de Splunk por su combinacion de campos propia."""
    if not isinstance(record, dict):
        return False
    # Un registro que ya viene marcado por el parser de texto (CEF/LEEF/syslog)
    # no es de Splunk aunque tenga '_raw': ese campo lo pone nuestro parser.
    if record.get("__format__"):
        return False
    has_splunk_keys = "_time" in record or "_raw" in record
    sourcetype = str(record.get("sourcetype") or record.get("source") or "").lower()
    if has_splunk_keys and sourcetype:
        return True
    # Un export con EventCode pero sin sourcetype sigue siendo Windows.
    # Ojo: 'signature_id' no vale como pista, es el campo de cabecera de CEF.
    return bool(has_splunk_keys and first(record, "EventCode", "EventID"))


def _sysmon_hashes(value: Optional[str]) -> Dict[str, str]:
    """'SHA256=ABC,MD5=DEF' -> {'sha256': 'abc', 'md5': 'def'}."""
    out: Dict[str, str] = {}
    if not value:
        return out
    for chunk in str(value).split(","):
        if "=" in chunk:
            key, _, val = chunk.partition("=")
            out[key.strip().lower()] = val.strip().lower()
    return out


def _base_event(record: Dict[str, Any], class_name: str, activity: str, severity: int) -> NormalizedEvent:
    """Esqueleto comun: tiempo, host que reporta y trazabilidad."""
    device_name = canon_host(first(record, "ComputerName", "Computer", "host", "dvc", "dest"))
    return NormalizedEvent(
        uid=make_uid("splunk", record),
        time=parse_time(first(record, "_time", "time", "TimeCreated", "EventTime")),
        source="splunk",
        origin=str(record.get("sourcetype") or record.get("source") or "splunk"),
        class_name=class_name,
        activity=activity,
        severity=severity,
        status="unknown",
        message=str(first(record, "Message", "name", "signature", "_raw") or "")[:400],
        device=HostRef(hostname=device_name) if device_name else None,
        raw=record,
    )


# ---------------------------------------------------------------------------
# Windows Security
# ---------------------------------------------------------------------------


def _logon(record: Dict[str, Any], success: bool) -> NormalizedEvent:
    """4624 (logon correcto) / 4625 (fallido)."""
    event = _base_event(
        record,
        CLASS_AUTHENTICATION,
        "logon" if success else "logon_failed",
        2 if success else 3,
    )
    event.status = "success" if success else "failure"

    user = first(record, "Account_Name", "TargetUserName", "user", "Target_Account_Name")
    domain = first(record, "Account_Domain", "TargetDomainName", "Target_Domain_Name")
    event.actor = ActorRef(user=str(user) if user else None,
                           domain=str(domain) if domain else None,
                           sid=str(first(record, "Security_ID", "TargetUserSid") or "") or None,
                           session_id=str(first(record, "Logon_ID", "TargetLogonId") or "") or None)

    src_ip = first(record, "Source_Network_Address", "IpAddress", "src_ip", "src")
    src_host = first(record, "Workstation_Name", "WorkstationName", "src_host")
    if src_ip or src_host:
        event.src = HostRef(
            ip=str(src_ip) if src_ip and is_ip(str(src_ip)) else None,
            hostname=canon_host(src_host) if src_host else None,
            port=to_int(first(record, "Source_Port", "IpPort")),
        )

    logon_type = to_int(first(record, "Logon_Type", "LogonType"))
    if logon_type is not None:
        event.raw = dict(record)
        event.raw["_logon_type_label"] = LOGON_TYPE_LABELS.get(logon_type, str(logon_type))
        # Un logon de red o RDP correcto es candidato a movimiento lateral; el
        # extractor decide, pero la pista se marca aqui.
        if success and logon_type in REMOTE_LOGON_TYPES:
            event.activity = "logon_remote"
            tech = technique("T1021.001" if logon_type == 10 else "T1021.002")
            if tech:
                event.mitre = [tech]

    if not success:
        tech = technique("T1110.001")
        if tech:
            event.mitre = [tech]

    return event


def _process_create(record: Dict[str, Any]) -> NormalizedEvent:
    """4688 (Windows) y Sysmon EventCode 1: creacion de proceso."""
    event = _base_event(record, CLASS_PROCESS, "launch", 2)
    event.status = "success"

    image = first(record, "New_Process_Name", "NewProcessName", "Image", "process_path", "process")
    parent = first(record, "Creator_Process_Name", "ParentProcessName", "ParentImage",
                   "Parent_Process_Name", "parent_process")
    cmdline = first(record, "Process_Command_Line", "CommandLine", "process", "cmdline")

    event.process = ProcRef(
        name=basename(image),
        path=str(image) if image else None,
        cmdline=str(cmdline) if cmdline else None,
        pid=to_int(first(record, "New_Process_ID", "NewProcessId", "ProcessId", "process_id")),
        parent_name=basename(parent),
        parent_path=str(parent) if parent else None,
        parent_pid=to_int(first(record, "Creator_Process_ID", "ParentProcessId")),
        integrity=str(first(record, "Mandatory_Label", "IntegrityLevel") or "") or None,
    )

    user = first(record, "Account_Name", "User", "SubjectUserName", "user")
    if user:
        event.actor = ActorRef(user=str(user),
                               domain=str(first(record, "Account_Domain", "SubjectDomainName") or "") or None)

    hashes = _sysmon_hashes(first(record, "Hashes", "hash"))
    if hashes:
        event.file = FileRef(name=basename(image), path=str(image) if image else None,
                             sha256=hashes.get("sha256"), md5=hashes.get("md5"))

    event.mitre = infer_from_cmdline(event.process.cmdline)
    # Una linea de comandos que dispara tecnicas conocidas no es un evento
    # informativo: sube la severidad para que sobreviva a los filtros.
    if event.mitre:
        event.severity = max(event.severity, 3)
    return event


def _network_connect(record: Dict[str, Any]) -> NormalizedEvent:
    """Sysmon EventCode 3 y sourcetypes de red del CIM."""
    event = _base_event(record, CLASS_NETWORK, "connect", 2)
    event.status = "success"

    dst_ip = first(record, "DestinationIp", "dest_ip", "dest", "destination_ip")
    dst_host = first(record, "DestinationHostname", "dest_host", "destination_host")
    event.dst = HostRef(
        ip=str(dst_ip) if dst_ip and is_ip(str(dst_ip)) else None,
        hostname=canon_host(dst_host) if dst_host and not is_ip(str(dst_host)) else None,
        port=to_int(first(record, "DestinationPort", "dest_port", "destination_port")),
    )
    domain = canon_domain(dst_host)
    if domain:
        event.domain = domain

    src_ip = first(record, "SourceIp", "src_ip", "src")
    if src_ip:
        event.src = HostRef(ip=str(src_ip) if is_ip(str(src_ip)) else None,
                            port=to_int(first(record, "SourcePort", "src_port")))
        # En una conexion saliente el origen ES la maquina que reporta, asi que
        # aqui aprendemos su IP. Es lo que despues permite fundir el nodo
        # 'ip:10.4.2.11' con 'host:wks-0421' en el grafo.
        if event.device and is_ip(str(src_ip)):
            event.device.ip = str(src_ip)

    image = first(record, "Image", "process_path", "process_name")
    if image:
        event.process = ProcRef(name=basename(image), path=str(image))

    user = first(record, "User", "user", "Account_Name")
    if user:
        event.actor = ActorRef(user=str(user))

    action = str(first(record, "action", "Action") or "").lower()
    if action in ("blocked", "block", "denied", "deny", "dropped"):
        event.activity = "blocked"
        event.status = "failure"

    # Destino publico = posible C2. Interno = trafico normal.
    if event.dst and event.dst.ip and not _is_private(event.dst.ip):
        event.severity = max(event.severity, 3)
    return event


def _file_create(record: Dict[str, Any]) -> NormalizedEvent:
    """Sysmon EventCode 11."""
    event = _base_event(record, CLASS_FILE, "create", 2)
    event.status = "success"

    target = first(record, "TargetFilename", "file_path", "file_name")
    hashes = _sysmon_hashes(first(record, "Hashes", "hash"))
    event.file = FileRef(
        name=basename(target),
        path=str(target) if target else None,
        sha256=hashes.get("sha256"),
        md5=hashes.get("md5"),
    )
    image = first(record, "Image", "process_path")
    if image:
        event.process = ProcRef(name=basename(image), path=str(image))
    user = first(record, "User", "user")
    if user:
        event.actor = ActorRef(user=str(user))
    return event


def _dns_query(record: Dict[str, Any]) -> NormalizedEvent:
    """Sysmon EventCode 22."""
    event = _base_event(record, CLASS_DNS, "query", 1)
    event.status = "success"
    event.domain = canon_domain(first(record, "QueryName", "query", "domain"))
    image = first(record, "Image", "process_path")
    if image:
        event.process = ProcRef(name=basename(image), path=str(image))
    answer = first(record, "QueryResults", "answer")
    if answer:
        for chunk in str(answer).split(";"):
            candidate = chunk.strip().lstrip("type:").strip()
            if is_ip(candidate):
                event.dst = HostRef(ip=candidate)
                break
    return event


def _account_created(record: Dict[str, Any]) -> NormalizedEvent:
    """4720: cuenta de usuario creada."""
    event = _base_event(record, CLASS_ACCOUNT, "create_account", 4)
    event.status = "success"
    target = first(record, "New_Account_Name", "TargetUserName", "Account_Name")
    event.actor = ActorRef(user=str(target) if target else None)
    tech = technique("T1136")
    if tech:
        event.mitre = [tech]
    return event


def _is_private(ip: str) -> bool:
    from .base import is_private_ip

    return is_private_ip(ip)


# EventCode -> constructor
_HANDLERS = {
    "4624": lambda r: _logon(r, True),
    "4625": lambda r: _logon(r, False),
    "4648": lambda r: _logon(r, True),
    "4688": _process_create,
    "4720": _account_created,
    "1": _process_create,      # Sysmon
    "3": _network_connect,     # Sysmon
    "11": _file_create,        # Sysmon
    "22": _dns_query,          # Sysmon
}


def normalize(record: Dict[str, Any]) -> Optional[NormalizedEvent]:
    sourcetype = str(record.get("sourcetype") or record.get("source") or "").lower()
    code = str(first(record, "EventCode", "EventID", "signature_id") or "").strip()

    # Los EventCode bajos (1, 3, 11, 22) solo son de Sysmon; en un sourcetype
    # que no sea Sysmon significarian otra cosa.
    if code in ("1", "3", "11", "22") and "sysmon" not in sourcetype:
        code = ""

    handler = _HANDLERS.get(code)
    if handler is not None:
        return handler(record)

    # Sin EventCode reconocido, se decide por el sourcetype.
    if any(key in sourcetype for key in ("firewall", "proxy", "netflow", "stream:", "pan:", "cisco")):
        return _network_connect(record)
    if "dns" in sourcetype:
        return _dns_query(record)

    # Ultimo recurso: si trae campos de red del CIM, es un evento de red.
    if first(record, "dest_ip", "dest", "DestinationIp"):
        return _network_connect(record)
    if first(record, "process", "process_name", "Image"):
        return _process_create(record)
    if first(record, "user", "Account_Name"):
        return _logon(record, True)
    return None


register("splunk_windows", matches, normalize, priority=10)
