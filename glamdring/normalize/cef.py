"""Normalizador de CEF, LEEF y syslog, mas el generico de ultimo recurso.

Estos formatos son texto plano, asi que aqui hay dos capas:

1. ``parse_line()`` convierte una linea en diccionario. Marca el resultado con
   ``__format__`` para que el normalizador sepa de donde viene.
2. El normalizador traduce ese diccionario a ``NormalizedEvent``.

El normalizador ``generic`` va con la prioridad mas alta (se evalua el ultimo) y
nunca devuelve None: es la red de seguridad para cualquier JSON que no encaje en
ningun fabricante conocido. Prefiere un nodo pobre a perder el evento.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from ..mitre import infer_from_cmdline
from ..models import (
    CLASS_AUTHENTICATION,
    CLASS_FILE,
    CLASS_FINDING,
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
    is_private_ip,
    parse_severity,
    parse_time,
    register,
    to_int,
)

# ---------------------------------------------------------------------------
# Parseo de texto
# ---------------------------------------------------------------------------

_CEF_HEADER = re.compile(r"CEF:(?P<version>\d+)\|(?P<rest>.*)", re.S)
_LEEF_HEADER = re.compile(r"LEEF:(?P<version>[\d.]+)\|(?P<rest>.*)", re.S)
_SYSLOG_PRI = re.compile(r"^<(?P<pri>\d{1,3})>(?P<rest>.*)", re.S)

# Nombres largos para las abreviaturas de CEF, para que el inspector sea legible.
CEF_KEY_ALIASES = {
    "src": "src_ip", "dst": "dest_ip", "spt": "src_port", "dpt": "dest_port",
    "suser": "src_user", "duser": "dest_user", "shost": "src_host", "dhost": "dest_host",
    "act": "action", "msg": "message", "proto": "protocol", "app": "application",
    "fname": "file_name", "filePath": "file_path", "fileHash": "file_hash",
    "request": "url", "requestMethod": "http_method", "dntdom": "dest_domain",
    "sntdom": "src_domain", "cs1": "cs1", "cn1": "cn1", "deviceProcessName": "process_name",
    "sproc": "process_name", "dproc": "dest_process_name", "outcome": "outcome",
    "rt": "time", "start": "time", "end": "end_time", "cat": "category",
    # LEEF nombra el tiempo del dispositivo asi; sin este alias los eventos LEEF
    # se quedaban sin fecha y caian a la hora actual.
    "devTime": "time", "devTimeFormat": "time_format", "usrName": "src_user",
    "srcPort": "src_port", "dstPort": "dest_port", "identSrc": "src_ip",
}


def _split_escaped(text: str, sep: str) -> list:
    """Parte por ``sep`` respetando el escape con barra invertida de CEF."""
    parts, buf, escaped = [], [], False
    for char in text:
        if escaped:
            buf.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == sep:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(char)
    parts.append("".join(buf))
    return parts


def _parse_extensions(text: str) -> Dict[str, str]:
    """Extrae los ``clave=valor`` del cuerpo de CEF.

    El valor llega hasta la siguiente ``clave=``, porque en CEF los valores
    pueden llevar espacios sin comillas (``msg=algo con espacios src=1.2.3.4``).
    """
    out: Dict[str, str] = {}
    if not text:
        return out
    positions = [(m.start(), m.end(), m.group(1)) for m in re.finditer(r"(?:^|\s)([A-Za-z][A-Za-z0-9_.\[\]]*)=", text)]
    for index, (_start, value_start, key) in enumerate(positions):
        value_end = positions[index + 1][0] if index + 1 < len(positions) else len(text)
        value = text[value_start:value_end].strip()
        out[key] = value.replace("\\=", "=").replace("\\\\", "\\").replace("\\n", "\n")
    return out


def parse_cef(line: str) -> Optional[Dict[str, Any]]:
    match = _CEF_HEADER.search(line)
    if not match:
        return None
    fields = _split_escaped(match.group("rest"), "|")
    if len(fields) < 7:
        return None
    record: Dict[str, Any] = {
        "__format__": "cef",
        "device_vendor": fields[0],
        "device_product": fields[1],
        "device_version": fields[2],
        "signature_id": fields[3],
        "name": fields[4],
        "cef_severity": fields[5],
    }
    for key, value in _parse_extensions("|".join(fields[6:])).items():
        record[CEF_KEY_ALIASES.get(key, key)] = value
    record["_raw"] = line.strip()
    return record


def parse_leef(line: str) -> Optional[Dict[str, Any]]:
    match = _LEEF_HEADER.search(line)
    if not match:
        return None
    fields = _split_escaped(match.group("rest"), "|")
    if len(fields) < 5:
        return None
    version = match.group("version")
    # LEEF 2.0 declara el delimitador en el sexto campo del cabecero.
    delimiter = "\t"
    body_index = 4
    if version.startswith("2") and len(fields) >= 6:
        declared = fields[4]
        if declared:
            delimiter = chr(int(declared[1:], 16)) if declared.startswith("x") else declared
        body_index = 5

    record: Dict[str, Any] = {
        "__format__": "leef",
        "device_vendor": fields[0],
        "device_product": fields[1],
        "device_version": fields[2],
        "signature_id": fields[3],
    }
    body = delimiter.join(fields[body_index:]) if len(fields) > body_index else ""
    for pair in body.split(delimiter):
        if "=" in pair:
            key, _, value = pair.partition("=")
            record[CEF_KEY_ALIASES.get(key.strip(), key.strip())] = value.strip()
    record["_raw"] = line.strip()
    return record


def parse_syslog(line: str) -> Optional[Dict[str, Any]]:
    """RFC5424 y RFC3164. Si el mensaje contiene CEF/LEEF, gana el interior."""
    text = line.strip()
    if not text:
        return None

    severity_num = None
    match = _SYSLOG_PRI.match(text)
    if match:
        pri = int(match.group("pri"))
        severity_num = pri % 8  # 0 emergencia .. 7 debug
        text = match.group("rest")

    inner = parse_cef(text) or parse_leef(text)
    if inner is not None:
        if severity_num is not None:
            inner.setdefault("syslog_severity", severity_num)
        return inner

    record: Dict[str, Any] = {"__format__": "syslog", "_raw": line.strip()}
    if severity_num is not None:
        record["syslog_severity"] = severity_num

    # RFC5424: "1 2026-08-20T10:00:00Z host app procid msgid ..."
    rfc5424 = re.match(
        r"^1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s*(?P<msg>.*)$",
        text, re.S,
    )
    if rfc5424:
        record.update({
            "time": rfc5424.group("ts"),
            "host": rfc5424.group("host"),
            "application": rfc5424.group("app"),
            "process_id": rfc5424.group("procid"),
            "message": rfc5424.group("msg").strip(),
        })
        return record

    # RFC3164: "Aug 20 10:00:00 host tag: mensaje"
    rfc3164 = re.match(
        r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<tag>[^:\[]+)(\[\d+\])?:\s*(?P<msg>.*)$",
        text, re.S,
    )
    if rfc3164:
        record.update({
            "time": rfc3164.group("ts"),
            "host": rfc3164.group("host"),
            "application": rfc3164.group("tag"),
            "message": rfc3164.group("msg").strip(),
        })
        return record

    record["message"] = text
    return record


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Punto de entrada unico para una linea de texto suelta."""
    if not line or not line.strip():
        return None
    return parse_cef(line) or parse_leef(line) or parse_syslog(line)


# ---------------------------------------------------------------------------
# Normalizador generico (sirve para CEF, LEEF, syslog y JSON desconocido)
# ---------------------------------------------------------------------------

# "password" y "ssh" estan aqui porque syslog no dice "authentication": dice
# "Failed password for invalid user X" o "Accepted password ... ssh2".
_AUTH_HINTS = ("logon", "login", "auth", "signin", "sign-in", "credential", "kerberos",
               "session opened", "password", "ssh", "sudo", "pam_")
_NET_HINTS = ("connect", "traffic", "firewall", "flow", "proxy", "http", "dns", "tcp", "udp", "vpn")
_FILE_HINTS = ("file", "download", "upload", "malware", "quarantine")
_PROC_HINTS = ("process", "execut", "command", "script")
_FAIL_HINTS = ("fail", "denied", "deny", "block", "reject", "invalid", "unauthorized", "error")


def matches(record: Dict[str, Any]) -> bool:
    return isinstance(record, dict)  # el generico acepta cualquier cosa


def normalize(record: Dict[str, Any]) -> Optional[NormalizedEvent]:
    blob = " ".join(
        str(record.get(key) or "")
        for key in ("name", "message", "action", "category", "signature", "event_type", "_raw")
    ).lower()

    if any(hint in blob for hint in _AUTH_HINTS):
        class_name = CLASS_AUTHENTICATION
    elif any(hint in blob for hint in _PROC_HINTS) or first(record, "process_name", "cmdline", "command_line"):
        class_name = CLASS_PROCESS
    elif any(hint in blob for hint in _FILE_HINTS) or first(record, "file_name", "file_path", "file_hash"):
        class_name = CLASS_FILE
    elif any(hint in blob for hint in _NET_HINTS) or first(record, "src_ip", "dest_ip", "url"):
        class_name = CLASS_NETWORK
    else:
        class_name = CLASS_FINDING

    failure = any(hint in blob for hint in _FAIL_HINTS)
    outcome = str(first(record, "outcome", "action", "result") or "").lower()
    if outcome in ("success", "allow", "allowed", "accept", "permitted"):
        failure = False

    severity_raw = first(record, "cef_severity", "severity", "priority")
    if severity_raw is not None:
        severity = parse_severity(severity_raw, scale_max=10)
    elif "syslog_severity" in record:
        # Syslog es al reves: 0 es lo mas grave.
        severity = max(0, min(5, 5 - int(record["syslog_severity"]) // 2))
    else:
        severity = 3 if failure else 2

    fmt = str(record.get("__format__") or "generic")
    event = NormalizedEvent(
        uid=make_uid(fmt, record),
        time=parse_time(first(record, "time", "timestamp", "@timestamp", "rt", "_time", "start")),
        source="generic",
        origin=str(first(record, "device_product", "application", "__format__") or fmt),
        class_name=class_name,
        activity="unknown",
        severity=severity,
        status="failure" if failure else "success",
        message=str(first(record, "name", "message", "_raw") or "")[:400],
        raw=record,
    )

    src_ip = first(record, "src_ip", "source_ip", "sourceip", "client_ip")
    dst_ip = first(record, "dest_ip", "destination_ip", "destinationip", "server_ip")
    src_host = first(record, "src_host", "source_host", "src_hostname")
    dst_host = first(record, "dest_host", "destination_host", "dest_hostname")

    if src_ip or src_host:
        event.src = HostRef(
            ip=str(src_ip) if src_ip and is_ip(str(src_ip)) else None,
            hostname=canon_host(src_host) if src_host else None,
            port=to_int(first(record, "src_port", "source_port")),
        )
    if dst_ip or dst_host:
        event.dst = HostRef(
            ip=str(dst_ip) if dst_ip and is_ip(str(dst_ip)) else None,
            hostname=canon_host(dst_host) if dst_host and not is_ip(str(dst_host)) else None,
            port=to_int(first(record, "dest_port", "destination_port")),
        )

    device = canon_host(first(record, "host", "hostname", "dvchost", "device_host", "computer"))
    if device:
        event.device = HostRef(hostname=device)

    user = first(record, "src_user", "user", "username", "duser", "account", "user_name")
    if user:
        event.actor = ActorRef(user=str(user), domain=str(first(record, "src_domain", "domain") or "") or None)

    url = first(record, "url", "request", "uri")
    if url:
        event.url = str(url)
        event.domain = canon_domain(str(url).split("//")[-1].split("/")[0].split(":")[0])
    else:
        domain = canon_domain(first(record, "domain", "dest_domain", "query"))
        if domain:
            event.domain = domain

    process_name = first(record, "process_name", "process", "image")
    cmdline = first(record, "cmdline", "command_line", "commandline")
    if process_name or cmdline:
        event.process = ProcRef(
            name=basename(process_name) if process_name else None,
            path=str(process_name) if process_name else None,
            cmdline=str(cmdline) if cmdline else None,
        )
        event.mitre = infer_from_cmdline(event.process.cmdline)

    file_name = first(record, "file_name", "filename", "file_path")
    file_hash = first(record, "file_hash", "sha256", "hash")
    if file_name or file_hash:
        event.file = FileRef(
            name=basename(file_name) if file_name else None,
            path=str(first(record, "file_path", "filepath") or file_name or "") or None,
            sha256=str(file_hash).lower() if file_hash and len(str(file_hash)) == 64 else None,
            md5=str(file_hash).lower() if file_hash and len(str(file_hash)) == 32 else None,
        )

    if class_name == CLASS_AUTHENTICATION:
        event.activity = "logon_failed" if failure else "logon"
    elif class_name == CLASS_NETWORK:
        event.activity = "blocked" if failure else "connect"
        if event.dst and event.dst.ip and not is_private_ip(event.dst.ip):
            event.severity = max(event.severity, 3)
    elif class_name == CLASS_PROCESS:
        event.activity = "launch"
    elif class_name == CLASS_FILE:
        event.activity = "delete" if "delet" in blob else "create"
    else:
        event.activity = "alert"

    return event


# Prioridad alta = se evalua el ultimo, cuando ningun fabricante lo ha reclamado.
register("generic", matches, normalize, priority=99)
