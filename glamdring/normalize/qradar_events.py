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
#
# EL ORDEN Y EL REPARTO IMPORTAN, y estaban mal las dos cosas:
#
# - _FILE_WORDS llevaba "malware", "virus" y "antivirus", y se comprobaba antes
#   que la red. Con eso, 'Malware Detected Not Cleaned' (categoria 'Virus
#   Detected', magnitud 9, log source TrendMicro-AV) salia como CREACION DE
#   FICHERO CON EXITO, y el relato lo redactaba como "jlopez creo m.exe". El
#   antivirus estaba diciendo que no habia podido limpiarlo.
#
# - 'dns' estaba dentro de _NET_WORDS, asi que una resolucion salia como
#   conexion. La misma resolucion del mismo dominio se clasificaba de tres
#   formas distintas segun quien la contara: 'query' en Splunk, 'connect' aqui y
#   'create' en CEF. Eso es literalmente lo que impide correlacionar dos SIEM.
_AUTH_WORDS = ("authentication", "logon", "login", "session opened", "credential",
               "kerberos", "password")
_DNS_WORDS = ("dns", "domain name", "name resolution")
_DETECT_WORDS = ("malware", "virus", "antivirus", "trojan", "ransomware",
                 "spyware", "infected", "quarantine")
_NET_WORDS = ("firewall", "flow", "network", "traffic", "proxy", "session", "vpn",
              "web session", "transfer")
_FILE_WORDS = ("file", "attachment")
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


def _classify(record: Dict[str, Any]):
    """Devuelve (clase OCSF, actividad del vocabulario cerrado)."""
    category = str(first(record, "categoryname", "highlevelcategory", "category") or "").lower()
    name = str(first(record, "qidname", "eventname", "qid_name") or "").lower()
    blob = f"{category} {name}"

    # La deteccion PRIMERO. Un antivirus diciendo que encontro algo no es una
    # operacion de fichero por mucho que mencione un fichero.
    if any(word in blob for word in _DETECT_WORDS):
        return CLASS_FINDING, "malware_detect"
    # Y el DNS antes que la red, porque una resolucion no es una conexion.
    if any(word in blob for word in _DNS_WORDS) or first(record, "domainname", "dnsquery"):
        return CLASS_DNS, "dns_query"
    if any(word in blob for word in _AUTH_WORDS):
        return CLASS_AUTHENTICATION, "logon"
    if any(word in blob for word in _PROC_WORDS):
        return CLASS_PROCESS, "process_launch"
    if any(word in blob for word in _FILE_WORDS):
        return CLASS_FILE, "file_create"
    if any(word in blob for word in _NET_WORDS):
        return CLASS_NETWORK, "network_connect"
    if first(record, "sourceip", "destinationip"):
        return CLASS_NETWORK, "network_connect"
    return CLASS_FINDING, "alert"


def _is_failure(record: Dict[str, Any]) -> bool:
    blob = " ".join(str(first(record, k) or "") for k in ("categoryname", "qidname", "eventname")).lower()
    return any(word in blob for word in ("fail", "denied", "deny", "block", "reject", "invalid", "unauthorized"))


def normalize(record: Dict[str, Any]) -> Optional[NormalizedEvent]:
    data = _lower_keys(record)

    # Ofensa: es una alerta, no un evento suelto.
    if "offense_type" in data or "offense_source" in data:
        return _offense(record, data)

    class_name, activity = _classify(data)
    failure = _is_failure(data)
    magnitude = first(data, "magnitude", "severity")
    severity = parse_severity(magnitude, scale_max=10) if magnitude is not None else 2

    event = NormalizedEvent(
        uid=make_uid("qradar", record),
        time=parse_time(first(data, "starttime", "devicetime", "endtime", "time")),
        source="qradar",
        origin=str(first(data, "logsourcename", "devicetype", "qid") or "qradar"),
        class_name=class_name,
        activity=activity,
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
        # LA IP DEL EQUIPO QUE REPORTA, cuando se puede saber. Un evento de
        # autenticacion lo registra la maquina CONTRA la que se autentica, asi
        # que en 'Successful Network Logon' reportado por SRV-DC01 el
        # destinationip es la IP de ese mismo SRV-DC01.
        #
        # Sin este dato, el grafo tenia 'host:srv-dc01' y 'ip:10.4.1.5' como dos
        # nodos distintos para la misma maquina, y el del nombre se quedaba
        # SUELTO, sin una sola arista: build.py solo funde una IP en un host que
        # declare esa IP en sus propiedades, y aqui se construia el HostRef sin
        # ella.
        #
        # Se limita a autenticacion y a IP privada a proposito: para un log
        # source de perimetro el destino es otra maquina, no el propio
        # dispositivo, y ahi la fusion seria falsa.
        if class_name == CLASS_AUTHENTICATION and event.dst and event.dst.ip                 and is_private_ip(event.dst.ip):
            event.device.ip = event.dst.ip

    user = first(data, "username", "user", "identityusername")
    if user:
        event.actor = ActorRef(user=str(user))

    payload = _decode_payload(first(data, "payload", "utf8_payload"))
    if payload:
        event.raw = dict(record)
        event.raw["_payload_decoded"] = payload[:2000]

    # QRADAR AGRUPA. Un 'Multiple Login Failures for Single Username' llega con
    # eventcount=14: catorce intentos en una sola fila. Se tiraba, asi que en el
    # grafo esa arista contaba 1 y una fuerza bruta parecia un despiste.
    agrupados = to_int(first(data, "eventcount", "event_count"))
    if agrupados and agrupados > 1:
        event.occurrences = agrupados

    # Los bytes que se movieron. Se tiraban, y son el dato que separa una
    # exfiltracion de abrir una pagina: 'Large Outbound Transfer' con 734 MB
    # salientes quedaba byte a byte identico a una navegacion normal.
    enviados = to_int(first(data, "bytessent", "bytes_sent", "sentbytes"))
    recibidos = to_int(first(data, "bytesreceived", "bytes_received", "receivedbytes"))
    protocolo = first(data, "protocolname", "protocol")
    if enviados or recibidos or protocolo:
        event.net = NetRef(bytes_in=recibidos, bytes_out=enviados,
                           protocol=str(protocolo).lower() if protocolo else None)

    if class_name == CLASS_AUTHENTICATION:
        # El desenlace va en status, no en el nombre de la actividad.
        if failure:
            event.mitre = techniques("T1110")
        elif event.src and event.dst and event.src.ip != event.dst.ip:
            # 'Successful Network Logon' con origen y destino distintos es un
            # inicio de sesion desde otra maquina, que es lo que dibuja la
            # arista de movimiento lateral.
            event.activity = "logon_remote"
            event.severity = max(event.severity, 3)
            event.mitre = techniques("T1021.002")

    elif class_name == CLASS_DNS:
        event.domain = canon_domain(first(data, "domainname", "dnsquery", "url", "hostname"))
        # EL RESOLUTOR NO ES LA RESPUESTA. En un evento DNS el destinationip es
        # el servidor que resuelve -aqui el InfoBlox interno-, no la IP a la que
        # apunta el dominio. Dejarlo en `dst` hacia que el grafo dibujara
        # "cdn-update-svc.com resuelve a 10.4.0.10": el dominio malicioso
        # apuntando al DNS de la propia empresa. Una arista falsa en un grafo
        # forense es peor que una arista de menos.
        if event.dst and event.dst.ip:
            event.raw = dict(record)
            event.raw["_dns_resolver"] = event.dst.ip
            event.dst = None
        respuesta = first(data, "dnsanswer", "answer", "resolvedip")
        if respuesta and is_ip(str(respuesta)):
            event.dst = HostRef(ip=str(respuesta))

    elif class_name == CLASS_NETWORK:
        domain = canon_domain(first(data, "url", "domainname", "hostname"))
        if domain:
            event.domain = domain
        # ANTES: cualquier salida a Internet desde una IP interna subia a
        # severidad 3 y se le colgaba T1071.001. Eso es casi todo el trafico de
        # una oficina, asi que el trafico normal pesaba lo mismo que una baliza
        # de mando y control. Lo que si es senal es el VOLUMEN.
        if event.net and event.net.bytes_out and event.net.bytes_out > 100 * 1024 * 1024:
            event.severity = max(event.severity, 4)
            # T1041 afirmaria que el canal es de mando y control, y de un
            # volumen grande saliendo no se deduce eso. T1048 se queda en
            # lo que el evento si demuestra: salida masiva de datos.
            event.mitre = techniques("T1048")

    elif class_name == CLASS_PROCESS:
        cmdline = first(data, "commandline", "process_command_line") or payload
        image = first(data, "processname", "process", "image")
        event.process = ProcRef(
            name=basename(image) if image else None,
            path=str(image) if image else None,
            cmdline=str(cmdline)[:2000] if cmdline else None,
        )
        event.mitre = infer_from_cmdline(event.process.cmdline)

    elif class_name == CLASS_FILE:
        filename = first(data, "filename", "file", "filepath")
        event.file = FileRef(
            name=basename(filename) if filename else None,
            path=str(filename) if filename else None,
            sha256=str(first(data, "sha256", "filehash") or "").lower() or None,
            md5=str(first(data, "md5") or "").lower() or None,
        )

    elif activity == "malware_detect":
        # El fichero encontrado se conserva, pero como algo que la alerta
        # NOMBRA, no como algo que alguien escribio.
        filename = first(data, "filename", "file", "filepath")
        if filename:
            event.file = FileRef(
                name=basename(filename), path=str(filename),
                sha256=str(first(data, "sha256", "filehash") or "").lower() or None,
                md5=str(first(data, "md5") or "").lower() or None,
            )
        # 'Not Cleaned' significa que el fichero sigue ahi. Es lo mas grave que
        # puede contar un antivirus y no puede salir como exito.
        nombre = str(first(data, "qidname", "eventname") or "").lower()
        if "not cleaned" in nombre or "failed" in nombre or failure:
            event.status = "failure"
            event.severity = max(event.severity, 5)
        else:
            event.severity = max(event.severity, 4)

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
    # EL offense_type DICE QUE ES EL offense_source, y hay que leerlo.
    #
    # Antes se leia offense_type solo para decidir que esto era una ofensa, y
    # despues el valor se interpretaba a ojo: si parecia una IP iba a `src` y si
    # no, a `device`. Con una ofensa agrupada por usuario -que es de las mas
    # comunes- eso convertia 'jlopez' en un HOST INVENTADO llamado jlopez, y el
    # grafo enseñaba una maquina que no existe en ninguna parte.
    origen = first(data, "offense_source")
    tipo = str(first(data, "offense_type", "offense_type_name") or "").strip().lower()
    if origen:
        texto = str(origen)
        if "username" in tipo or "user" == tipo:
            event.actor = ActorRef(user=texto)
        elif "hostname" in tipo or "host" in tipo:
            event.device = HostRef(hostname=canon_host(texto))
        elif is_ip(texto):
            # Sin tipo utilizable, la forma del valor es la unica pista honesta.
            event.src = HostRef(ip=texto)
        elif "@" in texto:
            event.actor = ActorRef(user=texto)
        else:
            event.device = HostRef(hostname=canon_host(texto))
    # Las categorias de una ofensa son texto de la taxonomia de QRadar
    # ("Malware Detected", "Suspicious Activity"), NO identificadores de ATT&CK.
    # Pasarlas por techniques() producia Technique(id='MALWARE DETECTED'), que
    # llegaba al grafo y al informe. Una tecnica inventada en un informe que
    # alguien firma es peor que ninguna: quien lo lea la buscara en el catalogo
    # de MITRE, no la encontrara, y a partir de ahi no se fia de las demas.
    #
    # techniques() ya solo acepta lo que tenga forma de id, asi que aqui se
    # conservan como lo que son: el texto de la categoria.
    categories = first(data, "categories")
    if categories:
        event.raw = dict(record)
        event.raw["_offense_categories"] = categories
        # Si la ofensa trae ids de verdad en su descripcion, esos si valen.
        event.mitre = techniques(str(first(data, "description") or ""))
    return event


register("qradar", matches, normalize, priority=10)
