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

from ..mitre import infer_from_cmdline, technique
from ..models import (
    CLASS_AUTHENTICATION,
    CLASS_DNS,
    CLASS_FILE,
    CLASS_FINDING,
    CLASS_NETWORK,
    CLASS_PROCESS,
    ActorRef,
    FileRef,
    HostRef,
    NetRef,
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
    # LEEF llama 'sev' a la severidad. Sin este alias, first(record,
    # "cef_severity", "severity", "priority") no encontraba nada y el evento
    # caia al "3 si fallo, 2 si no": un sev=8 -trafico de mando y control-
    # acababa con severidad 2, o sea que el evento MAS GRAVE del fichero era el
    # mas facil de esconder con un filtro por severidad.
    "sev": "severity",
    # Bytes en cada sentido. Son claves estandar de CEF y se tiraban enteras: la
    # asimetria entre lo que entra y lo que sale es la firma de la exfiltracion,
    # y sin ella una transferencia de 700 MiB queda igual que abrir una web.
    "in": "bytes_in", "out": "bytes_out",
    "bytesIn": "bytes_in", "bytesOut": "bytes_out",
    "dvc": "device_ip", "deviceExternalId": "device_id",
    "dntdom_": "dest_domain", "destinationDnsDomain": "dest_domain",
    "sourceDnsDomain": "src_domain", "dvcpid": "process_id",
    "reason": "reason", "cs2": "cs2", "cs3": "cs3", "cs4": "cs4",
    "cn2": "cn2", "cn3": "cn3",
}

# Los campos personalizados de CEF vienen en pareja: 'cs1=Malware' mas
# 'cs1Label=category'. El valor solo se puede interpretar sabiendo la etiqueta,
# y sin resolverla se pierden cosas como la categoria de URL del proxy o los
# bytes que el fabricante mete en un cnN.
_ETIQUETAS_CONOCIDAS = {
    "urlcategory": "url_category", "category": "url_category",
    "bytesout": "bytes_out", "bytesin": "bytes_in",
    "rule": "rule", "policy": "rule", "policyname": "rule",
    "threatname": "threat_name", "malwarename": "threat_name",
    "action": "action", "filetype": "file_type",
}


def _resolver_etiquetas(record: Dict[str, Any]) -> None:
    """Convierte 'cs1=X' + 'cs1Label=urlCategory' en 'url_category=X'.

    Se hace aqui y no en el normalizador para que el inspector ensene el nombre
    de verdad del campo en vez de 'cs1', que no le dice nada a nadie.
    """
    for clave in [k for k in record if k.endswith("Label")]:
        base = clave[:-5]
        if base not in record:
            continue
        etiqueta = str(record[clave]).strip().lower().replace(" ", "")
        destino = _ETIQUETAS_CONOCIDAS.get(etiqueta)
        if destino:
            record.setdefault(destino, record[base])
        else:
            # Etiqueta que no conocemos: se conserva con su nombre tal cual, que
            # sigue siendo mas util que 'cs4'.
            record.setdefault(etiqueta, record[base])


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
    _resolver_etiquetas(record)
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
    _resolver_etiquetas(record)
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
        _extraer_del_texto(record)
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
        _extraer_del_texto(record)
        return record

    record["message"] = text
    _extraer_del_texto(record)
    return record


# Lo que un demonio de Unix cuenta EN PROSA y no en campos. No es un lujo: en un
# syslog de sshd no hay 'user=' ni 'src_ip=', hay una frase. Sin volver a
# leerla, el usuario y la IP se quedaban dentro de la cadena y el evento llegaba
# al grafo sin nadie y sin origen.
#
# El caso que se perdia entero: dos intentos fallidos seguidos de un acceso
# correcto desde la MISMA IP. Es el patron mas reconocible que existe -fuerza
# bruta que acaba entrando- y no dibujaba una sola arista.
_PATRONES_TEXTO = (
    # sshd: "Failed password for invalid user administrator from 10.4.2.11 port 51882 ssh2"
    (re.compile(r"(?:Failed|Invalid)\s+(?:password|publickey)?\s*for\s+(?:invalid user\s+)?"
                r"(?P<user>[^\s]+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)"
                r"(?:\s+port\s+(?P<port>\d+))?", re.I),
     {"outcome": "failure", "event_type": "ssh_auth"}),
    # sshd: "Accepted password for jlopez from 10.4.2.11 port 51902 ssh2"
    (re.compile(r"Accepted\s+(?P<method>\w+)\s+for\s+(?P<user>[^\s]+)\s+from\s+"
                r"(?P<ip>[0-9a-fA-F:.]+)(?:\s+port\s+(?P<port>\d+))?", re.I),
     {"outcome": "success", "event_type": "ssh_auth"}),
    # "Invalid user svc_backup from 10.4.2.11"
    (re.compile(r"Invalid\s+user\s+(?P<user>[^\s]+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)", re.I),
     {"outcome": "failure", "event_type": "ssh_auth"}),
    # PAM: "session opened for user root by jlopez(uid=1001)"
    (re.compile(r"session opened for user\s+(?P<user>[^\s(]+)", re.I),
     {"outcome": "success", "event_type": "session"}),
    # sudo: "jlopez : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash"
    (re.compile(r"(?P<user>[^\s:]+)\s*:\s*TTY=\S+.*?USER=(?P<target>\S+)\s*;\s*"
                r"COMMAND=(?P<cmd>.+)$", re.I),
     {"outcome": "success", "event_type": "sudo"}),
)


def _extraer_del_texto(record: Dict[str, Any]) -> None:
    """Saca usuario, IP y comando de un mensaje de syslog en prosa.

    Los campos se anaden con setdefault: lo que ya venia estructurado manda
    siempre sobre lo que se deduce de una frase.
    """
    texto = str(record.get("message") or record.get("_raw") or "")
    if not texto:
        return
    for patron, extra in _PATRONES_TEXTO:
        encontrado = patron.search(texto)
        if not encontrado:
            continue
        campos = encontrado.groupdict()
        if campos.get("user"):
            record.setdefault("user", campos["user"])
        if campos.get("ip") and is_ip(campos["ip"]):
            record.setdefault("src_ip", campos["ip"])
        if campos.get("port"):
            record.setdefault("src_port", campos["port"])
        if campos.get("cmd"):
            record.setdefault("cmdline", campos["cmd"].strip())
        if campos.get("target"):
            record.setdefault("dest_user", campos["target"])
        for clave, valor in extra.items():
            record.setdefault(clave, valor)
        # Que via se uso. Un acceso por SSH viene de OTRA maquina, y eso decide
        # si es un logon o un logon remoto.
        if extra.get("event_type") == "ssh_auth":
            record.setdefault("application", record.get("application") or "sshd")
        return


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Punto de entrada unico para una linea de texto suelta."""
    if not line or not line.strip():
        return None
    return parse_cef(line) or parse_leef(line) or parse_syslog(line)


# ---------------------------------------------------------------------------
# Normalizador generico (sirve para CEF, LEEF, syslog y JSON desconocido)
# ---------------------------------------------------------------------------

# LA ESCALERA DE PALABRAS CLASIFICABA AL REVES, y no por poco.
#
# El orden era AUTH, PROC, FILE, NET, y las listas se pisaban entre si:
#
#   - _FILE_HINTS llevaba "malware", asi que una peticion DNS de Umbrella con
#     cs1=Malware casaba como FICHERO antes de llegar a red: la resolucion de un
#     dominio salia como "creacion de fichero", sin dominio y sin una sola
#     arista. En el relato se leia "jlopez creo un fichero en cdn-update-svc".
#
#   - _PROC_HINTS llevaba "command", que casa con "command-and-control": el
#     trafico de mando y control de PAN-OS salia como "lanzamiento de proceso" y
#     se perdia la conexion 10.4.2.11 -> 45.132.88.17, que es justo el hallazgo.
#
# Ahora se mira PRIMERO la evidencia que no admite interpretacion -hay un nombre
# consultado, hay un hash de fichero, hay una linea de comandos- y solo despues
# las palabras. Y las palabras que causaban los choques ya no estan: "malware" y
# "quarantine" indican una DETECCION, no una operacion de fichero, y "command"
# se ha ido entera.
_AUTH_HINTS = ("logon", "login", "signin", "sign-in", "credential", "kerberos",
               "session opened", "password", "ssh", "sudo", "pam_",
               "authentication", "authorized")
_NET_HINTS = ("connect", "traffic", "firewall", "flow", "proxy", "http", "tcp",
              "udp", "vpn", "session", "tunnel", "request")
_FILE_HINTS = ("file", "download", "upload", "attachment")
_PROC_HINTS = ("process", "execut", "script", "spawn")
_DNS_HINTS = ("dns", "umbrella", "resolver", "nameserver", "query")
_FAIL_HINTS = ("fail", "denied", "deny", "block", "reject", "invalid",
               "unauthorized", "error")

# Que un producto de deteccion diga que ha encontrado algo. OJO: se mira el
# NOMBRE del evento y la ACCION, nunca la categoria. La diferencia importa: una
# peticion DNS clasificada en la categoria "Malware" NO es una deteccion de
# malware, es una peticion DNS. Confundirlas era el fallo.
_DETECCION_HINTS = ("malware detected", "virus detected", "threat detected",
                    "trojan", "ransomware detected", "quarantine", "infected",
                    "malware found", "av detection")
_ACCIONES_DE_AV = ("quarantine", "quarantine_failed", "quarantined", "cleaned",
                   "not_cleaned", "not cleaned", "deleted_by_av", "disinfect")

# Formas de decir "esto lo permiti".
_EXITO = ("success", "allow", "allowed", "accept", "accepted", "permitted",
          "permit", "pass", "ok")


def matches(record: Dict[str, Any]) -> bool:
    return isinstance(record, dict)  # el generico acepta cualquier cosa


def _es_deteccion(record: Dict[str, Any], blob: str) -> bool:
    """Un AV o EDR diciendo que ha encontrado un artefacto malicioso."""
    if first(record, "threat_name", "malware_name", "virus_name"):
        return True
    accion = str(first(record, "action", "outcome") or "").strip().lower()
    if any(a in accion for a in _ACCIONES_DE_AV):
        return True
    nombre = str(first(record, "name", "signature") or "").lower()
    return any(h in nombre for h in _DETECCION_HINTS) or any(h in blob for h in _DETECCION_HINTS)


def _es_dns(record: Dict[str, Any], blob: str) -> bool:
    """Una resolucion de nombre, que no es lo mismo que una conexion."""
    if first(record, "query", "dns_query", "query_name"):
        return True
    producto = str(first(record, "device_product", "application") or "").lower()
    nombre = str(first(record, "name", "signature") or "").lower()
    if "dns" in producto or "dns" in nombre or "umbrella" in producto:
        return True
    # Un destino con nombre de dominio y SIN url ni puerto es una resolucion,
    # no una conexion: no hay a donde conectarse todavia.
    destino = str(first(record, "dest_host", "dest_domain") or "")
    if destino and "." in destino and not is_ip(destino):
        return not first(record, "url", "dest_port", "dest_ip")
    return False


def _clasificar(record: Dict[str, Any], blob: str):
    """Devuelve (clase OCSF, actividad del vocabulario cerrado)."""
    if _es_deteccion(record, blob):
        return CLASS_FINDING, "malware_detect"
    if _es_dns(record, blob):
        return CLASS_DNS, "dns_query"

    tipo = str(record.get("event_type") or "").lower()
    if tipo in ("ssh_auth", "session", "sudo") or any(h in blob for h in _AUTH_HINTS):
        return CLASS_AUTHENTICATION, "logon"
    if first(record, "process_name", "cmdline", "command_line") or \
            any(h in blob for h in _PROC_HINTS):
        return CLASS_PROCESS, "process_launch"
    if first(record, "file_name", "file_path", "file_hash") or \
            any(h in blob for h in _FILE_HINTS):
        return CLASS_FILE, "file_create"
    if first(record, "src_ip", "dest_ip", "url") or any(h in blob for h in _NET_HINTS):
        return CLASS_NETWORK, "network_connect"
    return CLASS_FINDING, "alert"


def normalize(record: Dict[str, Any]) -> Optional[NormalizedEvent]:
    blob = " ".join(
        str(record.get(key) or "")
        for key in ("name", "message", "action", "category", "signature", "event_type", "_raw")
    ).lower()

    class_name, activity = _clasificar(record, blob)

    # El desenlace. Lo que diga un campo explicito manda sobre lo que se deduzca
    # de las palabras del mensaje.
    outcome = str(first(record, "outcome", "action", "result") or "").strip().lower()
    if any(e == outcome or outcome.startswith(e) for e in _EXITO):
        failure = False
    elif outcome:
        failure = any(hint in outcome for hint in _FAIL_HINTS)
    else:
        failure = any(hint in blob for hint in _FAIL_HINTS)

    # Una deteccion de antivirus con la contencion FALLIDA es un fallo aunque el
    # producto lo cuente como una accion suya. 'quarantine_failed' significa que
    # el fichero sigue ahi.
    if activity == "malware_detect":
        failure = "fail" in outcome or "not" in outcome or failure

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
        activity=activity,
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
        # Y si no, del destino, SIEMPRE QUE parezca un dominio. Umbrella pone el
        # nombre consultado en dhost -> dest_host, y sin esta caida el evento se
        # quedaba sin dominio: unificar la clasificacion DNS habria producido un
        # nodo de dominio... inexistente. Era la mitad del arreglo que faltaba.
        if not domain and dst_host and "." in str(dst_host) and not is_ip(str(dst_host)):
            domain = canon_domain(str(dst_host))
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

    # Los bytes, la regla que actuo y la categoria del destino. Se tiraban los
    # tres, y el primero es el que convierte "una conexion" en "una fuga".
    entrada = to_int(first(record, "bytes_in", "rcvd", "received"))
    salida = to_int(first(record, "bytes_out", "sent"))
    protocolo = first(record, "protocol", "proto", "transport")
    regla = first(record, "rule", "policy", "rule_name")
    categoria = first(record, "url_category", "category")
    if any((entrada, salida, protocolo, regla, categoria)):
        event.net = NetRef(
            bytes_in=entrada, bytes_out=salida,
            protocol=str(protocolo).lower() if protocolo else None,
            rule=str(regla) if regla else None,
            category=str(categoria) if categoria else None,
        )

    _afinar(event, record, blob, failure)
    return event


# Categorias de destino que un proxy marca y que si son una senal por si solas.
_CATEGORIAS_GRAVES = ("anonymizer", "malware", "phishing", "command", "botnet",
                      "spyware", "newly registered", "cryptomining", "proxy avoidance")


def _afinar(event: NormalizedEvent, record: Dict[str, Any], blob: str, failure: bool) -> None:
    """Ajustes por actividad, una vez el evento ya esta montado."""
    if event.class_name == CLASS_AUTHENTICATION:
        # Un acceso por SSH viene de OTRA maquina por definicion. Es un logon
        # remoto, no un inicio de sesion local, y esa diferencia es la que
        # dibuja la arista de movimiento lateral.
        via = str(first(record, "application", "event_type") or "").lower()
        if not failure and event.src and event.src.ip and ("ssh" in via or "ssh" in blob):
            event.activity = "logon_remote"
            event.severity = max(event.severity, 3)
        if failure:
            tech = technique("T1110.001")
            if tech:
                event.mitre = [tech]

    elif event.class_name == CLASS_FINDING and event.activity == "malware_detect":
        # Una deteccion sin contener es lo mas grave que puede contar un AV.
        event.severity = max(event.severity, 5 if failure else 4)
        tech = technique("T1204.002")
        if tech and not event.mitre:
            event.mitre = [tech]

    elif event.class_name == CLASS_NETWORK:
        # ANTES: cualquier destino publico subia a severidad 3, o sea que el
        # trafico de Windows Update pesaba igual que una baliza de C2. Un
        # destino publico no es una senal; casi todo el trafico de una oficina
        # lo es. Lo que SI es senal: la categoria que le puso el proxy, o mucho
        # subido hacia fuera.
        categoria = str((event.net.category if event.net else "") or "").lower()
        if any(c in categoria for c in _CATEGORIAS_GRAVES):
            event.severity = max(event.severity, 4)
        if event.net and event.net.bytes_out and event.net.bytes_out > 100 * 1024 * 1024:
            event.severity = max(event.severity, 4)
            tech = technique("T1041")
            if tech and not event.mitre:
                event.mitre = [tech]

    elif event.class_name == CLASS_FILE:
        if "delet" in blob:
            event.activity = "file_delete"
        elif "modif" in blob:
            event.activity = "file_modify"
        elif "upload" in blob:
            event.activity = "file_upload"
        elif "download" in blob:
            event.activity = "file_download"


# Prioridad alta = se evalua el ultimo, cuando ningun fabricante lo ha reclamado.
register("generic", matches, normalize, priority=99)
