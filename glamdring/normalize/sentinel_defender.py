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
    CLASS_REGISTRY,
    ActorRef,
    EmailRef,
    FileRef,
    HostRef,
    NormalizedEvent,
    ProcRef,
    RegistryRef,
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
    """Deduce la tabla por la huella de campos cuando no viene ``Type``.

    EL ORDEN ES LO DELICADO AQUI. `RemoteIP` se comprobaba antes que
    `LogonType`, y las tablas de logon de Defender traen LAS DOS COSAS: un
    inicio de sesion de red lleva la IP desde la que se conecta el usuario. Con
    ese orden, un logon al que le faltara `Type` -que es justo cuando se usa
    esta funcion- se convertia en una conexion de red y perdia la cuenta que
    inicio sesion, que es el dato del evento.

    Ahora se mira primero lo que solo existe en una tabla. `LogonType` y
    `AccountName` juntos no aparecen en DeviceNetworkEvents.
    """
    if "AlertName" in record or "AlertSeverity" in record:
        return "SecurityAlert"
    if "LogonType" in record or "AccountName" in record and "ActionType" in record \
            and "logon" in str(record.get("ActionType") or "").lower():
        return "DeviceLogonEvents"
    if "RegistryKey" in record or "RegistryValueName" in record:
        return "DeviceRegistryEvents"
    if "ProcessCommandLine" in record or "FolderPath" in record:
        return "DeviceProcessEvents"
    if "UserPrincipalName" in record and "ResultType" in record:
        return "SigninLogs"
    if "SenderFromAddress" in record or "RecipientEmailAddress" in record:
        return "EmailEvents"
    if "SHA256" in record and "FileName" in record:
        return "DeviceFileEvents"
    if "RemoteUrl" in record or "RemoteIP" in record:
        return "DeviceNetworkEvents"
    return ""


_MENSAJES_POR_TABLA = {
    "SigninLogs": "Inicio de sesion en Entra ID",
    "AADNonInteractiveUserSignInLogs": "Inicio de sesion no interactivo",
    "DeviceLogonEvents": "Inicio de sesion en el equipo",
    "EmailEvents": "Correo entregado",
    "DeviceNetworkEvents": "Conexion de red",
    "DeviceFileEvents": "Actividad de fichero",
    "DeviceProcessEvents": "Creacion de proceso",
    "DeviceRegistryEvents": "Cambio en el registro",
    "IdentityLogonEvents": "Autenticacion de identidad",
    "CloudAppEvents": "Actividad en aplicacion cloud",
}


def _base(record: Dict[str, Any], table: str, class_name: str, activity: str, severity: int) -> NormalizedEvent:
    device = canon_host(first(record, "DeviceName", "Computer", "HostName"))
    # UN EVENTO SIN MENSAJE ES UN NODO QUE NO SE PUEDE INTERPRETAR. Varias
    # tablas de Defender no traen AlertName ni ActionType -SigninLogs,
    # DeviceLogonEvents, EmailEvents- y salian con el mensaje en blanco: en el
    # inspector aparecia un evento sin una sola linea que dijera que era.
    # Se cae al nombre de la tabla, que al menos lo situa.
    mensaje = str(first(record, "AlertName", "Description", "ActionType", "Title") or "")[:400]
    if not mensaje:
        mensaje = _MENSAJES_POR_TABLA.get(table, table or "Evento de Microsoft")
    return NormalizedEvent(
        uid=make_uid("sentinel", record),
        time=parse_time(first(record, "TimeGenerated", "Timestamp", "EventTime")),
        source="sentinel",
        origin=table or "sentinel",
        class_name=class_name,
        activity=activity,
        severity=severity,
        status="unknown",
        message=mensaje,
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
    event = _base(record, "DeviceProcessEvents", CLASS_PROCESS, "process_launch", 2)
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
    event = _base(record, "DeviceNetworkEvents", CLASS_NETWORK, "network_connect", 2)
    action = str(first(record, "ActionType") or "").lower()
    # El desenlace va en status y solo ahi: 'blocked' salio del vocabulario.
    event.status = "failure" if "fail" in action or "block" in action else "success"

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
    action = str(first(record, "ActionType") or "FileCreated").lower()
    if "delete" in action:
        activity = "file_delete"
    elif "modif" in action or "rename" in action:
        activity = "file_modify"
    else:
        activity = "file_create"
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

    # TRES DESENLACES, NO DOS. Defender emite 'LogonSuccess', 'LogonFailed' y
    # tambien 'LogonAttempted', que significa que vio el intento y no sabe como
    # acabo. Antes cualquier cosa que no dijera "success" caia en el else y
    # salia con status de FALLO, exactamente igual que un LogonFailed
    # confirmado: la herramienta afirmaba un fallo de autenticacion que Defender
    # no habia afirmado.
    if "success" in action:
        estado, severidad = "success", 2
    elif "fail" in action:
        estado, severidad = "failure", 3
    else:
        estado, severidad = "unknown", 2

    event = _base(record, "DeviceLogonEvents", CLASS_AUTHENTICATION, "logon", severidad)
    event.status = estado
    user = first(record, "AccountName", "AccountUpn")
    event.actor = ActorRef(user=str(user) if user else None,
                           domain=str(first(record, "AccountDomain") or "") or None)
    remote_ip = first(record, "RemoteIP")
    remote_device = first(record, "RemoteDeviceName")
    if remote_ip or remote_device:
        event.src = HostRef(ip=str(remote_ip) if remote_ip and is_ip(str(remote_ip)) else None,
                            hostname=canon_host(remote_device) if remote_device else None)

    # 'CachedRemoteInteractive' es un RDP con credenciales cacheadas: viene de
    # otra maquina igual que un RemoteInteractive, y se quedaba fuera de la
    # lista por no estar escrito exactamente asi.
    logon_type = str(first(record, "LogonType") or "").lower()
    remotos = ("network", "remoteinteractive", "cachedremoteinteractive",
               "networkcleartext", "newcredentials")
    if estado == "success" and logon_type in remotos:
        event.activity = "logon_remote"
        event.severity = max(event.severity, 3)
        event.mitre = techniques("T1021.001" if "remoteinteractive" in logon_type
                                 else "T1021.002")
    return event


def _signin(record: Dict[str, Any]) -> NormalizedEvent:
    result = to_int(first(record, "ResultType"))
    success = result == 0
    event = _base(record, "SigninLogs", CLASS_AUTHENTICATION,
                  "logon", 2 if success else 3)
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
    event = _base(record, "EmailEvents", CLASS_EMAIL, "email_deliver", 3)
    # Los dos campos a la vez: un correo con DeliveryAction=Delivered y
    # ThreatTypes=Phish es justo el caso peligroso, porque llego a la bandeja.
    verdict = " ".join(str(record.get(k) or "") for k in ("DeliveryAction", "ThreatTypes")).lower()
    event.status = "failure" if "block" in verdict else "success"
    # 'Junked' y 'Replaced' son un TERCER desenlace: el correo llego, pero
    # neutralizado. No es exito ni fallo, y meterlo en cualquiera de los dos
    # cubos miente en un sentido o en el otro.
    if "junk" in verdict or "replaced" in verdict:
        event.activity = "email_quarantine"
        event.status = "unknown"
        event.severity = max(1, event.severity - 1)
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
    # La tabla de verdad, no siempre 'SecurityAlert': un SecurityIncident se
    # etiquetaba como si fuera una alerta suelta, y son cosas distintas -uno
    # agrupa a los otros-. El origen es lo que el analista mira para saber de
    # donde vino cada nodo.
    """SecurityAlert / SecurityIncident: la alerta y todo lo que toca."""
    tabla = str(record.get("Type") or record.get("TableName") or "SecurityAlert")
    event = _base(record, tabla, CLASS_FINDING, "alert",
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


# DeviceEvents es el cajon de sastre de Defender: ahi cae todo lo que no tiene
# tabla propia. Estaba mapeada ENTERA a "consulta DNS con severidad 1", asi que
# una deteccion de antivirus, un borrado del registro de auditoria o una
# modificacion de token salian como una peticion de DNS informativa y se caian
# de la cronologia del informe al primer filtro por severidad.
#
# La tabla no es un tipo de evento: lo que dice que paso es ActionType.
_ACCIONES_DEVICE_EVENTS = {
    "dnsqueryresponse": (CLASS_DNS, "dns_query", 2),
    "antivirusdetection": (CLASS_FINDING, "malware_detect", 5),
    "antivirusreport": (CLASS_FINDING, "malware_detect", 4),
    "antivirusdetectionfailed": (CLASS_FINDING, "malware_detect", 5),
    "securitylogcleared": (CLASS_FINDING, "log_clear", 5),
    "auditpolicychanged": (CLASS_FINDING, "alert", 4),
    "processprimarytokenmodified": (CLASS_PROCESS, "process_inject", 4),
    "createremotethreadapicall": (CLASS_PROCESS, "process_inject", 4),
    "readprocessmemoryapicall": (CLASS_PROCESS, "process_access", 4),
    "openprocessapicall": (CLASS_PROCESS, "process_access", 3),
    "shelllinkcreatefileevent": (CLASS_FILE, "file_create", 3),
    "namedpipeevent": (CLASS_PROCESS, "process_launch", 2),
    "servicesinstalled": (CLASS_REGISTRY, "registry_set", 4),
    "scheduledtaskcreated": (CLASS_REGISTRY, "registry_set", 4),
    "usbdrivemounted": (CLASS_FILE, "file_read", 3),
    "powershellcommand": (CLASS_PROCESS, "process_launch", 3),
}


def _device_events(record: Dict[str, Any]) -> NormalizedEvent:
    """La tabla cajon de sastre. Lo que paso lo dice ActionType, no la tabla."""
    accion = str(first(record, "ActionType") or "").strip().lower()
    clase, actividad, severidad = _ACCIONES_DEVICE_EVENTS.get(
        accion, (CLASS_FINDING, "alert", 3))

    event = _base(record, "DeviceEvents", clase, actividad, severidad)
    event.status = "success"
    event.process = _initiating_process(record)
    usuario = first(record, "InitiatingProcessAccountName", "AccountName")
    if usuario:
        event.actor = ActorRef(user=str(usuario))

    if clase == CLASS_DNS:
        event.domain = canon_domain(first(record, "RemoteUrl", "AdditionalFields"))
    elif actividad == "malware_detect":
        nombre = first(record, "FileName")
        if nombre:
            event.file = FileRef(
                name=basename(nombre),
                path=str(first(record, "FolderPath") or nombre),
                sha256=str(first(record, "SHA256") or "").lower() or None,
            )
        # Una deteccion que no se pudo contener sigue siendo un fichero vivo.
        if "failed" in accion:
            event.status = "failure"
    elif actividad == "log_clear":
        event.message = event.message or "Se vacio el registro de auditoria"
        event.mitre = techniques("T1070.001")
    elif clase == CLASS_REGISTRY:
        clave = first(record, "RegistryKey", "AdditionalFields")
        event.registry = RegistryRef(key=str(clave) if clave else None,
                                     value=str(first(record, "RegistryValueName") or "") or None,
                                     data=str(first(record, "RegistryValueData") or "") or None)
        if not event.registry.key:
            # Sin la clave no hay nada que dibujar: se cuenta como alerta antes
            # que emitir un evento de registro vacio.
            event.class_name = CLASS_FINDING
            event.activity = "alert"

    # El mensaje NO puede quedarse vacio: un nodo sin texto en el inspector es
    # un nodo que el analista no puede interpretar.
    if not event.message:
        event.message = accion or "Evento de dispositivo"
    return event


def _device_registry(record: Dict[str, Any]) -> NormalizedEvent:
    """DeviceRegistryEvents: la persistencia por claves de arranque."""
    accion = str(first(record, "ActionType") or "").lower()
    borrado = "delete" in accion or "remove" in accion
    event = _base(record, "DeviceRegistryEvents", CLASS_REGISTRY,
                  "registry_delete" if borrado else "registry_set", 3)
    event.status = "success"
    clave = first(record, "RegistryKey", "PreviousRegistryKey")
    event.registry = RegistryRef(
        key=str(clave) if clave else None,
        value=str(first(record, "RegistryValueName") or "") or None,
        data=str(first(record, "RegistryValueData") or "") or None,
    )
    event.process = _initiating_process(record)
    usuario = first(record, "InitiatingProcessAccountName")
    if usuario:
        event.actor = ActorRef(user=str(usuario))
    bajo = str(clave or "").lower()
    if "currentversion\\run" in bajo or "currentcontrolset\\services" in bajo:
        event.severity = max(event.severity, 4)
        event.mitre = techniques("T1547.001")
    if not event.message:
        event.message = accion or "Cambio en el registro"
    return event


def _image_load(record: Dict[str, Any]) -> NormalizedEvent:
    """DeviceImageLoadEvents: carga de DLL."""
    event = _base(record, "DeviceImageLoadEvents", CLASS_PROCESS, "module_load", 1)
    event.status = "success"
    event.process = _initiating_process(record)
    nombre = first(record, "FileName")
    if nombre:
        event.file = FileRef(name=basename(nombre),
                             path=str(first(record, "FolderPath") or nombre),
                             sha256=str(first(record, "SHA256") or "").lower() or None)
    if not event.message:
        event.message = f"Carga de {basename(nombre) or 'modulo'}"
    return event


def _identity_logon(record: Dict[str, Any]) -> NormalizedEvent:
    """IdentityLogonEvents: autenticacion vista desde Defender for Identity."""
    accion = str(first(record, "ActionType") or "").lower()
    correcto = "success" in accion
    event = _base(record, "IdentityLogonEvents", CLASS_AUTHENTICATION,
                  "auth_ticket" if "kerberos" in str(first(record, "Protocol") or "").lower()
                  else "logon", 2 if correcto else 3)
    event.status = "success" if correcto else ("failure" if "fail" in accion else "unknown")
    usuario = first(record, "AccountName", "AccountUpn")
    if usuario:
        event.actor = ActorRef(user=str(usuario),
                               domain=str(first(record, "AccountDomain") or "") or None)
    ip = first(record, "IPAddress", "DeviceName")
    if ip and is_ip(str(ip)):
        event.src = HostRef(ip=str(ip))
    if not event.message:
        event.message = accion or "Autenticacion de identidad"
    return event


def _cloud_app(record: Dict[str, Any]) -> NormalizedEvent:
    """CloudAppEvents: lo que se hace dentro de una aplicacion cloud.

    Es la tabla que mas se parece a lo que traeran Netskope y Zscaler, asi que
    ya usa el vocabulario de la fase 3: subir, descargar y compartir.
    """
    accion = str(first(record, "ActionType") or "").lower()
    if "upload" in accion:
        clase, actividad, severidad = CLASS_FILE, "file_upload", 3
    elif "download" in accion:
        clase, actividad, severidad = CLASS_FILE, "file_download", 2
    elif "share" in accion or "anonymouslink" in accion:
        clase, actividad, severidad = CLASS_FILE, "file_share", 4
    elif "mailitemsaccessed" in accion:
        clase, actividad, severidad = CLASS_EMAIL, "email_access", 4
    else:
        clase, actividad, severidad = CLASS_FINDING, "alert", 2

    event = _base(record, "CloudAppEvents", clase, actividad, severidad)
    event.status = "success"
    app = first(record, "Application", "AppName")
    if app:
        event.app = str(app)
    usuario = first(record, "AccountDisplayName", "AccountId", "UserPrincipalName")
    if usuario:
        event.actor = ActorRef(user=str(usuario))
    nombre = first(record, "ObjectName", "FileName")
    if nombre and clase == CLASS_FILE:
        event.file = FileRef(name=basename(nombre), path=str(nombre))
    ip = first(record, "IPAddress")
    if ip and is_ip(str(ip)):
        event.src = HostRef(ip=str(ip))
    if not event.message:
        event.message = accion or "Actividad en aplicacion cloud"
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
    "DeviceEvents": _device_events,
    # Tablas que matches() ya reclamaba y no tenian handler: acababan devolviendo
    # None, se las quedaba el normalizador generico y salian como "alerta con
    # status de exito", sin mensaje y sin equipo. Seis tablas de Defender
    # entrando al grafo como ruido indistinguible.
    "DeviceRegistryEvents": _device_registry,
    "DeviceImageLoadEvents": _image_load,
    "IdentityLogonEvents": _identity_logon,
    "IdentityDirectoryEvents": _identity_logon,
    "CloudAppEvents": _cloud_app,
    "OfficeActivity": _cloud_app,
}


def normalize(record: Dict[str, Any]) -> Optional[NormalizedEvent]:
    table = str(record.get("Type") or record.get("TableName") or "") or _guess_table(record)
    handler = _TABLES.get(table)
    if handler is None:
        return None
    return handler(record)


register("sentinel_defender", matches, normalize, priority=10)
