"""Normalizador de IBM QRadar: resultados Ariel y ofensas.

Ariel devuelve nombres de columna en minusculas y sin separadores
(``sourceip``, ``destinationport``, ``starttime``), y el tiempo en milisegundos
desde epoch. La severidad hay que derivarla de ``magnitude`` (1-10), que ya
combina credibilidad, relevancia y severidad del evento.

``categoryname`` es la taxonomia propia de QRadar y es lo mas fiable para saber
si un evento es de autenticacion, de red o de fichero, porque un mismo QID puede
venir de cientos de log sources distintos.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Dict, Optional

from ..mitre import infer_from_cmdline, techniques
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

_QRADAR_MARKERS = ("qid", "starttime", "logsourcename", "magnitude", "categoryname", "devicetype")


def matches(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    lowered = {str(k).lower() for k in record.keys()}
    hits = sum(1 for marker in _QRADAR_MARKERS if marker in lowered)
    if hits >= 2:
        return True
    # Una ofensa tiene esta forma tan concreta que vale con detectarla.
    return "offense_type" in lowered or ("offense_source" in lowered and "magnitude" in lowered)


def _lower_keys(record: Dict[str, Any]) -> Dict[str, Any]:
    """Ariel es inconsistente con mayusculas segun la version de la API."""
    return {str(k).lower(): v for k, v in record.items()}


def _decode_payload(value: Any) -> str:
    """El payload viene en base64 en la API de Ariel; si no lo es, se deja igual."""
    if not value:
        return ""
    text = str(value)
    if len(text) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", text or "x"):
        try:
            decoded = base64.b64decode(text, validate=True).decode("utf-8", errors="replace")
            # Solo lo aceptamos si el resultado parece texto imprimible.
            if sum(1 for c in decoded if c.isprintable() or c in "\r\n\t") > len(decoded) * 0.8:
                return decoded
        except (binascii.Error, ValueError):
            pass
    return text


# Palabras de la taxonomia de QRadar que nos dicen la clase de evento.
_AUTH_WORDS = ("authentication", "logon", "login", "session opened", "credential")
_NET_WORDS = ("firewall", "flow", "network", "traffic", "proxy", "session", "vpn", "dns")
_FILE_WORDS = ("file", "malware", "virus", "antivirus")
_PROC_WORDS = ("process", "exploit", "application")


# Fabricantes y categorias de producto que aparecen como nombre de log source.
# No es exhaustivo ni pretende serlo: cubre lo que se ve a diario y falla del
# lado seguro (si no lo reconoce, se queda con el nombre como host).
_PRODUCT_MARKERS = (
    "trendmicro", "trend micro", "paloalto", "palo alto", "bluecoat", "blue coat",
    "infoblox", "fortinet", "fortigate", "checkpoint", "check point", "sophos",
    "symantec", "mcafee", "kaspersky", "crowdstrike", "sentinelone", "cylance",
    "zscaler", "netskope", "cisco", "juniper", "f5", "imperva", "barracuda",
    "websense", "forcepoint", "carbonblack", "carbon black", "defender",
    "-proxy", "-av", "-ids", "-ips", "-waf", "-dns", "-dhcp", "-vpn",
    "firewall", "antivirus", "endpoint protection",
)


def looks_like_product(name: str) -> bool:
    """True si el nombre parece un producto de seguridad y no una maquina."""
    lowered = str(name).strip().lower()
    return any(marker in lowered for marker in _PRODUCT_MARKERS)


def _classify(record: Dict[str, Any]) -> str:
    category = str(first(record, "categoryname", "highlevelcategory", "category") or "").lower()
    name = str(first(record, "qidname", "eventname", "qid_name") or "").lower()
    blob = f"{category} {name}"
    if any(word in blob for word in _AUTH_WORDS):
        return CLASS_AUTHENTICATION
    if any(word in blob for word in _FILE_WORDS):
        return CLASS_FILE
    if any(word in blob for word in _PROC_WORDS):
        return CLASS_PROCESS
    if any(word in blob for word in _NET_WORDS):
        return CLASS_NETWORK
    if first(record, "sourceip", "destinationip"):
        return CLASS_NETWORK
    return CLASS_FINDING


def _is_failure(record: Dict[str, Any]) -> bool:
    blob = " ".join(str(first(record, k) or "") for k in ("categoryname", "qidname", "eventname")).lower()
    return any(word in blob for word in ("fail", "denied", "deny", "block", "reject", "invalid", "unauthorized"))


def normalize(record: Dict[str, Any]) -> Optional[NormalizedEvent]:
    data = _lower_keys(record)

    # Ofensa: es una alerta, no un evento suelto.
    if "offense_type" in data or "offense_source" in data:
        return _offense(record, data)

    class_name = _classify(data)
    failure = _is_failure(data)
    magnitude = first(data, "magnitude", "severity")
    severity = parse_severity(magnitude, scale_max=10) if magnitude is not None else 2

    event = NormalizedEvent(
        uid=make_uid("qradar", record),
        time=parse_time(first(data, "starttime", "devicetime", "endtime", "time")),
        source="qradar",
        origin=str(first(data, "logsourcename", "devicetype", "qid") or "qradar"),
        class_name=class_name,
        activity="unknown",
        severity=severity,
        status="failure" if failure else "success",
        message=str(first(data, "qidname", "eventname", "message") or "")[:400],
        raw=record,
    )

    source_ip = first(data, "sourceip", "src_ip", "source_ip")
    dest_ip = first(data, "destinationip", "dst_ip", "destination_ip")
    if source_ip and is_ip(str(source_ip)):
        event.src = HostRef(ip=str(source_ip), port=to_int(first(data, "sourceport", "source_port")))
    if dest_ip and is_ip(str(dest_ip)):
        event.dst = HostRef(ip=str(dest_ip), port=to_int(first(data, "destinationport", "destination_port")))

    device_name = canon_host(first(data, "hostname", "identityhostname"))
    if not device_name:
        candidate = first(data, "logsourcename")
        # 'logsourcename' unas veces es la maquina que reporta (SRV-DC01) y otras
        # el producto que lo hace (TrendMicro-AV, Bluecoat-Proxy). Convertir un
        # nombre de producto en un host llena el grafo de maquinas que no existen,
        # asi que solo se acepta si no huele a producto. El valor sigue estando
        # en 'origin', asi que el analista no pierde el dato.
        if candidate and not looks_like_product(str(candidate)):
            device_name = canon_host(candidate)
    if device_name:
        event.device = HostRef(hostname=device_name)

    user = first(data, "username", "user", "identityusername")
    if user:
        event.actor = ActorRef(user=str(user))

    payload = _decode_payload(first(data, "payload", "utf8_payload"))
    if payload:
        event.raw = dict(record)
        event.raw["_payload_decoded"] = payload[:2000]

    if class_name == CLASS_AUTHENTICATION:
        event.activity = "logon_failed" if failure else "logon"
        if failure:
            event.mitre = techniques("T1110")
    elif class_name == CLASS_NETWORK:
        event.activity = "blocked" if failure else "connect"
        domain = canon_domain(first(data, "url", "domainname", "hostname"))
        if domain:
            event.domain = domain
        # Salida a Internet desde una IP interna: candidato a C2/exfiltracion.
        if event.dst and event.dst.ip and not is_private_ip(event.dst.ip):
            if event.src and event.src.ip and is_private_ip(event.src.ip):
                event.severity = max(event.severity, 3)
                if not failure:
                    event.mitre = techniques("T1071.001")
    elif class_name == CLASS_PROCESS:
        event.activity = "launch"
        cmdline = first(data, "commandline", "process_command_line") or payload
        image = first(data, "processname", "process", "image")
        event.process = ProcRef(
            name=basename(image) if image else None,
            path=str(image) if image else None,
            cmdline=str(cmdline)[:2000] if cmdline else None,
        )
        event.mitre = infer_from_cmdline(event.process.cmdline)
    elif class_name == CLASS_FILE:
        event.activity = "create"
        filename = first(data, "filename", "file", "filepath")
        event.file = FileRef(
            name=basename(filename) if filename else None,
            path=str(filename) if filename else None,
            sha256=str(first(data, "sha256", "filehash") or "").lower() or None,
            md5=str(first(data, "md5") or "").lower() or None,
        )

    return event


def _offense(record: Dict[str, Any], data: Dict[str, Any]) -> NormalizedEvent:
    """Una ofensa de QRadar equivale a una alerta correlada."""
    event = NormalizedEvent(
        uid=make_uid("qradar", record),
        time=parse_time(first(data, "start_time", "starttime", "last_updated_time")),
        source="qradar",
        origin="offense",
        class_name=CLASS_FINDING,
        activity="alert",
        severity=parse_severity(first(data, "magnitude", "severity"), scale_max=10),
        status="unknown",
        message=str(first(data, "description", "offense_source") or "Ofensa QRadar")[:400],
        raw=record,
    )
    offense_source = first(data, "offense_source")
    if offense_source:
        text = str(offense_source)
        if is_ip(text):
            event.src = HostRef(ip=text)
        else:
            event.device = HostRef(hostname=canon_host(text))
    categories = first(data, "categories")
    if categories:
        event.mitre = techniques(str(categories))
    return event


register("qradar", matches, normalize, priority=10)
