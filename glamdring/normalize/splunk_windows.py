"""Normalizador de Splunk: WinEventLog Security, Sysmon y CIM generico.

Splunk entrega el resultado de una busqueda como una lista de diccionarios con
``_time`` y ``_raw`` mas los campos extraidos. Aqui se traduce el EventCode
(4624, 4688, Sysmon 1/3/11...) a la clase OCSF correspondiente.

Los nombres de campo de WinEventLog varian segun la version del TA de Windows
(``Account_Name`` vs ``TargetUserName``, ``New_Process_Name`` vs ``NewProcessName``),
por eso todo pasa por ``first()`` con varios candidatos.

DOS COSAS QUE ESTE FICHERO YA NO HACE, porque hacian dano de verdad:

1. **Ya no hay red de arrastre que lo clasifique todo como inicio de sesion.**
   Antes, cualquier registro con ``Account_Name`` y sin EventCode conocido salia
   como logon correcto. Comprobado: 4104, 7045, 4672, 4648, 1102, 4698, 4726,
   4740, 5140 y 4103 salian los diez como ``logon`` / ``success``. Entre ellos el
   1102, que es el borrado del registro de auditoria.

2. **Ya no se decide si algo es Sysmon buscando la palabra 'sysmon' en el
   sourcetype.** Ese valor lo pone el cliente. Con un nombre distinto
   -'XmlWinEventLog', o lo que le apetezca al que monto el TA- Sysmon 11 caia en
   el constructor de proceso y le pegaba el SHA256 del fichero CREADO a
   ``certutil.exe``: si el analista pivotaba ese hash, el grafo le estaba
   afirmando que el binario malicioso era un ejecutable firmado de Microsoft.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..mitre import infer_from_cmdline, technique
from ..models import (
    CLASS_ACCOUNT,
    CLASS_AUTHENTICATION,
    CLASS_DNS,
    CLASS_FILE,
    CLASS_FINDING,
    CLASS_NETWORK,
    CLASS_PROCESS,
    CLASS_REGISTRY,
    ActorRef,
    FileRef,
    HostRef,
    NetRef,
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

# Carpetas desde las que un ejecutable no tiene por que estar corriendo. No es
# prueba de nada, pero es la diferencia entre un fichero y un fichero que merece
# que alguien lo mire.
_CARPETAS_SOSPECHOSAS = ("\\temp\\", "\\appdata\\", "\\programdata\\",
                         "\\users\\public\\", "\\windows\\tasks\\", "/tmp/")

# Claves de registro que sirven para arrancar con la sesion. Escribir aqui es la
# forma clasica de persistencia en Windows.
_CLAVES_DE_ARRANQUE = ("\\currentversion\\run", "\\currentversion\\runonce",
                       "\\currentcontrolset\\services", "\\winlogon\\shell",
                       "\\currentversion\\explorer\\shell folders")


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


def _ruta_sospechosa(ruta: Optional[str]) -> bool:
    if not ruta:
        return False
    bajo = str(ruta).lower().replace("/", "\\")
    return any(trozo.replace("/", "\\") in bajo for trozo in _CARPETAS_SOSPECHOSAS)


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


def _actor(record: Dict[str, Any], *campos: str) -> Optional[ActorRef]:
    user = first(record, *campos)
    if not user:
        return None
    return ActorRef(user=str(user),
                    domain=str(first(record, "Account_Domain", "SubjectDomainName",
                                     "TargetDomainName") or "") or None)


# ---------------------------------------------------------------------------
# Windows Security: autenticacion
# ---------------------------------------------------------------------------


def _logon(record: Dict[str, Any], success: bool) -> NormalizedEvent:
    """4624 (logon correcto) / 4625 (fallido).

    El desenlace va en ``status`` y solo ahi: ya no existe una actividad
    'logon_failed'. Tener el mismo dato en dos sitios es tener dos sitios donde
    puede discrepar, y ademas rompe la correlacion entre SIEM, que es justo lo
    que esta herramienta existe para hacer.
    """
    event = _base_event(record, CLASS_AUTHENTICATION, "logon", 2 if success else 3)
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
            event.severity = max(event.severity, 3)
            tech = technique("T1021.001" if logon_type == 10 else "T1021.002")
            if tech:
                event.mitre = [tech]

    if not success:
        tech = technique("T1110.001")
        if tech:
            event.mitre = [tech]

    return event


def _logoff(record: Dict[str, Any]) -> NormalizedEvent:
    """4634 / 4647: cierre de sesion.

    NO estaba cubierto, y eso hacia mucho dano por una razon poco obvia: 4634
    trae ``Logon_Type`` igual que un 4624, asi que la red de arrastre lo metia
    en ``_logon`` y ademas entraba en la rama del tipo de logon. Un cierre de
    sesion de red salia como ``logon_remote`` con ``T1021.002`` inventado.

    Y 4634 es tipicamente el evento MAS NUMEROSO de un log de seguridad de
    Windows: uno por cada 4624. Veinte desconexiones rutinarias de un recurso
    compartido dejaban veintiun nodos marcados como victima de movimiento
    lateral. El analista abria el grafo, lo veia todo rojo, y cuando hubiera un
    salto lateral de verdad no lo iba a distinguir del fondo. Encima el informe
    exportado afirmaba T1021.002 sobre veinte personas inocentes.

    Severidad 1 y sin tecnica: cerrar sesion es lo mas rutinario que hay.
    """
    event = _base_event(record, CLASS_AUTHENTICATION, "logoff", 1)
    event.status = "success"
    event.actor = _actor(record, "Account_Name", "TargetUserName", "user")
    logon_type = to_int(first(record, "Logon_Type", "LogonType"))
    if logon_type is not None:
        event.raw = dict(record)
        event.raw["_logon_type_label"] = LOGON_TYPE_LABELS.get(logon_type, str(logon_type))
    return event


def _logon_explicit(record: Dict[str, Any]) -> NormalizedEvent:
    """4648: autenticacion con credenciales distintas a las de la sesion.

    Antes se aplanaba a un logon local y se tiraban los dos campos que lo hacen
    util: QUE cuenta se uso y CONTRA que servidor. Sin eso, un runas o un PsExec
    -que es como se mueve un atacante teniendo ya una credencial- queda igual
    que abrir sesion en tu propio equipo.
    """
    event = _base_event(record, CLASS_AUTHENTICATION, "logon_explicit", 3)
    event.status = "success"

    # El actor es la cuenta USADA, no la que estaba en la sesion.
    usada = first(record, "Target_Account_Name", "TargetUserName", "Account_Name")
    event.actor = ActorRef(user=str(usada) if usada else None,
                           domain=str(first(record, "Target_Domain_Name",
                                            "TargetDomainName") or "") or None)

    destino = first(record, "Target_Server_Name", "TargetServerName", "TargetInfo")
    if destino:
        event.dst = HostRef(hostname=canon_host(destino))

    src_ip = first(record, "Source_Network_Address", "IpAddress")
    if src_ip and is_ip(str(src_ip)):
        event.src = HostRef(ip=str(src_ip))

    proceso = first(record, "Process_Name", "ProcessName")
    if proceso:
        event.process = ProcRef(name=basename(proceso), path=str(proceso))

    tech = technique("T1078")
    if tech:
        event.mitre = [tech]
    return event


def _auth_ticket(record: Dict[str, Any]) -> NormalizedEvent:
    """4768 / 4769: peticion de ticket Kerberos (TGT y TGS)."""
    event = _base_event(record, CLASS_AUTHENTICATION, "auth_ticket", 2)
    codigo = str(first(record, "Result_Code", "Status") or "").strip()
    # 0x0 es correcto. Cualquier otro codigo es un fallo con motivo.
    event.status = "failure" if codigo and codigo not in ("0x0", "0", "0x00") else "success"
    event.actor = _actor(record, "Account_Name", "TargetUserName")
    servicio = first(record, "Service_Name", "ServiceName")
    if servicio:
        event.app = str(servicio)
    src_ip = first(record, "Client_Address", "IpAddress")
    if src_ip:
        limpia = str(src_ip).lstrip(":").replace("::ffff:", "")
        if is_ip(limpia):
            event.src = HostRef(ip=limpia)
    # Un TGS pedido con cifrado debil es kerberoasting.
    if str(first(record, "Ticket_Encryption_Type", "TicketEncryptionType") or "").lower() in ("0x17", "0x18"):
        tech = technique("T1558.003")
        if tech:
            event.mitre = [tech]
            event.severity = max(event.severity, 4)
    return event


# ---------------------------------------------------------------------------
# Windows Security: cuentas
# ---------------------------------------------------------------------------


def _account_change(record: Dict[str, Any], activity: str, severity: int,
                    tecnica: str = "") -> NormalizedEvent:
    event = _base_event(record, CLASS_ACCOUNT, activity, severity)
    event.status = "success"
    target = first(record, "New_Account_Name", "Target_Account_Name",
                   "TargetUserName", "Account_Name")
    event.actor = ActorRef(user=str(target) if target else None)
    if tecnica:
        tech = technique(tecnica)
        if tech:
            event.mitre = [tech]
    return event


def _group_member_add(record: Dict[str, Any]) -> NormalizedEvent:
    """4728 / 4732 / 4756: una cuenta entra en un grupo.

    Va aparte de ``account_modify`` porque no es un cambio de cuenta mas: meter a
    alguien en Domain Admins es escalada de privilegios, y el grupo merece ser un
    nodo para poder ver de un vistazo quien acabo dentro.
    """
    event = _base_event(record, CLASS_ACCOUNT, "group_member_add", 4)
    event.status = "success"
    miembro = first(record, "Member_Name", "MemberName", "Account_Name")
    if miembro:
        # El Member_Name suele venir como DN completo: CN=jlopez,OU=...
        texto = str(miembro)
        if texto.upper().startswith("CN="):
            texto = texto[3:].split(",")[0]
        event.actor = ActorRef(user=texto)
    grupo = first(record, "Group_Name", "TargetUserName", "GroupName")
    if grupo:
        event.raw = dict(record)
        event.raw["_group_name"] = str(grupo)
        # Los grupos que dan el dominio entero.
        if str(grupo).lower().replace(" ", "") in ("domainadmins", "enterpriseadmins",
                                                    "schemaadmins", "administrators",
                                                    "administradores", "admonsdeldominio"):
            event.severity = 5
    tech = technique("T1098")
    if tech:
        event.mitre = [tech]
    return event


def _log_clear(record: Dict[str, Any]) -> NormalizedEvent:
    """1102: se ha vaciado el registro de auditoria.

    Antes salia como inicio de sesion correcto con severidad 2. Es de los
    eventos mas graves que puede emitir Windows: casi nunca es legitimo, y
    cuando lo es se sabe de antemano. Severidad 5 y sin discusion.
    """
    event = _base_event(record, CLASS_FINDING, "log_clear", 5)
    event.status = "success"
    event.actor = _actor(record, "Account_Name", "SubjectUserName", "user")
    event.message = event.message or "Se vacio el registro de auditoria de seguridad"
    tech = technique("T1070.001")
    if tech:
        event.mitre = [tech]
    return event


def _service_install(record: Dict[str, Any]) -> NormalizedEvent:
    """7045: servicio nuevo instalado. Persistencia de manual."""
    event = _base_event(record, CLASS_REGISTRY, "registry_set", 4)
    event.status = "success"
    nombre = first(record, "Service_Name", "ServiceName")
    binario = first(record, "Service_File_Name", "ImagePath", "ServiceFileName")
    event.registry = RegistryRef(
        key=f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{nombre}" if nombre else None,
        value=str(nombre) if nombre else None,
        data=str(binario) if binario else None,
    )
    event.actor = _actor(record, "Account_Name", "SubjectUserName")
    if binario:
        event.file = FileRef(name=basename(binario), path=str(binario))
        if _ruta_sospechosa(binario):
            # Un servicio que arranca algo desde Temp no es un servicio normal.
            event.severity = 5
    tech = technique("T1543.003")
    if tech:
        event.mitre = [tech]
    return event


def _powershell_script(record: Dict[str, Any]) -> NormalizedEvent:
    """4104 / 4103: bloque de script de PowerShell ejecutado.

    Es donde aparece el codigo de verdad, ya descodificado por el propio
    PowerShell. Antes salia como inicio de sesion correcto: el contenido, que es
    lo unico que importa aqui, se perdia entero.
    """
    event = _base_event(record, CLASS_PROCESS, "process_launch", 3)
    event.status = "success"
    texto = str(first(record, "ScriptBlockText", "Message", "Payload", "_raw") or "")
    event.process = ProcRef(name="powershell.exe",
                            path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                            cmdline=texto[:2000] or None)
    event.actor = _actor(record, "Account_Name", "User", "UserId")
    event.message = texto[:400] or event.message
    event.mitre = infer_from_cmdline(texto)
    if event.mitre:
        event.severity = max(event.severity, 4)
    return event


# ---------------------------------------------------------------------------
# Procesos, ficheros, red, registro
# ---------------------------------------------------------------------------


def _process_create(record: Dict[str, Any]) -> NormalizedEvent:
    """4688 (Windows) y Sysmon EventCode 1: creacion de proceso."""
    event = _base_event(record, CLASS_PROCESS, "process_launch", 2)
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

    # El hash de un Sysmon 1 SI es el del propio Image: el proceso que arranca.
    hashes = _sysmon_hashes(first(record, "Hashes", "hash"))
    if hashes:
        event.file = FileRef(name=basename(image), path=str(image) if image else None,
                             sha256=hashes.get("sha256"), md5=hashes.get("md5"))

    event.mitre = infer_from_cmdline(event.process.cmdline)
    # Una linea de comandos que dispara tecnicas conocidas no es un evento
    # informativo: sube la severidad para que sobreviva a los filtros.
    if event.mitre:
        event.severity = max(event.severity, 4)
    if _ruta_sospechosa(image):
        event.severity = max(event.severity, 4)
    return event


def _process_terminate(record: Dict[str, Any]) -> NormalizedEvent:
    """Sysmon 5: fin de proceso."""
    event = _base_event(record, CLASS_PROCESS, "process_terminate", 1)
    event.status = "success"
    image = first(record, "Image", "process_path")
    if image:
        event.process = ProcRef(name=basename(image), path=str(image))
    event.actor = _actor(record, "User", "user")
    return event


def _process_pair(record: Dict[str, Any], activity: str) -> NormalizedEvent:
    """Sysmon 8 (CreateRemoteThread) y 10 (ProcessAccess).

    Antes estos dos se RECLAMABAN y se devolvian a None: cero nodos y cero
    aristas. O sea que mimikatz abriendo un handle sobre lsass.exe -la firma mas
    reconocible que existe de un volcado de credenciales- simplemente no existia
    en el grafo. El analista miraba la pantalla y no habia nada que ver.

    Son los dos unicos hechos con DOS procesos en el mismo evento: quien inyecta
    y en quien, quien abre el handle y sobre quien.
    """
    severidad = 4
    event = _base_event(record, CLASS_PROCESS, activity, severidad)
    event.status = "success"

    origen = first(record, "SourceImage", "Image")
    destino = first(record, "TargetImage")
    if origen:
        event.process = ProcRef(name=basename(origen), path=str(origen),
                                pid=to_int(first(record, "SourceProcessId", "SourceProcessGUID")))
    if destino:
        event.target_process = ProcRef(name=basename(destino), path=str(destino),
                                       pid=to_int(first(record, "TargetProcessId")))
    event.actor = _actor(record, "User", "user")

    concedido = str(first(record, "GrantedAccess") or "").lower()
    es_lsass = "lsass.exe" in str(destino or "").lower()
    if activity == "process_access" and es_lsass:
        # 0x1010 / 0x1410 sobre lsass es lectura de memoria: volcado de
        # credenciales. Es el caso que hay que ver desde la otra punta de la
        # sala.
        tech = technique("T1003.001")
        event.severity = 5 if concedido in ("0x1410", "0x1010", "0x143a", "0x1438") else 4
    else:
        tech = technique("T1055")
    if tech:
        event.mitre = [tech]
    return event


def _module_load(record: Dict[str, Any]) -> NormalizedEvent:
    """Sysmon 7: carga de imagen o DLL."""
    event = _base_event(record, CLASS_PROCESS, "module_load", 1)
    event.status = "success"
    image = first(record, "Image", "process_path")
    if image:
        event.process = ProcRef(name=basename(image), path=str(image))
    cargado = first(record, "ImageLoaded", "loaded_image")
    hashes = _sysmon_hashes(first(record, "Hashes", "hash"))
    if cargado:
        event.file = FileRef(name=basename(cargado), path=str(cargado),
                             sha256=hashes.get("sha256"), md5=hashes.get("md5"))
        if _ruta_sospechosa(cargado):
            event.severity = 4
    firmado = str(first(record, "Signed") or "").lower()
    if firmado == "false" and _ruta_sospechosa(cargado):
        tech = technique("T1574.002")
        if tech:
            event.mitre = [tech]
    return event


def _network_connect(record: Dict[str, Any]) -> NormalizedEvent:
    """Sysmon EventCode 3 y sourcetypes de red del CIM."""
    event = _base_event(record, CLASS_NETWORK, "network_connect", 2)
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

    # Los bytes que se movieron, si el registro los trae. Sin esto una
    # transferencia de 700 MiB queda byte a byte igual que abrir una web.
    entrada = to_int(first(record, "bytes_in", "BytesReceived", "rcvd", "bytes_received"))
    salida = to_int(first(record, "bytes_out", "BytesSent", "sent", "bytes_sent"))
    protocolo = first(record, "Protocol", "protocol", "transport")
    if entrada or salida or protocolo:
        event.net = NetRef(bytes_in=entrada, bytes_out=salida,
                           protocol=str(protocolo).lower() if protocolo else None)

    action = str(first(record, "action", "Action") or "").lower()
    if action in ("blocked", "block", "denied", "deny", "dropped"):
        # El desenlace va SOLO en status. 'blocked' como actividad era el mismo
        # dato en dos sitios.
        event.status = "failure"

    # LA ESCALA ESTABA INVERTIDA. Antes cualquier destino publico subia a
    # severidad 3, asi que el trafico de Windows Update pesaba lo mismo que una
    # baliza de mando y control, y mas que un salto lateral. Un destino publico
    # por si solo no es una senal: casi todo el trafico de una oficina lo es.
    #
    # Lo que si es senal es la combinacion: un proceso corriendo desde una
    # carpeta rara que ademas sale a Internet.
    if event.dst and event.dst.ip and not _is_private(event.dst.ip):
        if _ruta_sospechosa(image):
            event.severity = max(event.severity, 4)
        elif salida and salida > 100 * 1024 * 1024:
            # Mucho subido hacia fuera. La asimetria es la firma de la fuga.
            event.severity = max(event.severity, 4)
    return event


def _file_activity(record: Dict[str, Any], activity: str, severity: int = 2) -> NormalizedEvent:
    """Sysmon 11 (creado), 23 (borrado), 2 (timestomp) y 15 (flujo alternativo).

    El hash de estos eventos es el del fichero TOCADO, no el del proceso que lo
    toca. Antes, cuando el despacho fallaba y esto acababa en el constructor de
    procesos, ese hash se le pegaba al Image: el grafo afirmaba que el binario
    malicioso era certutil.exe.
    """
    event = _base_event(record, CLASS_FILE, activity, severity)
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

    if _ruta_sospechosa(target):
        event.severity = max(event.severity, 3)
    if activity == "file_delete":
        tech = technique("T1070.004")
        if tech:
            event.mitre = [tech]
    elif activity == "file_modify":
        # Sysmon 2 es cambio de fecha de creacion: timestomping, y no hay motivo
        # legitimo para hacerlo.
        tech = technique("T1070.006")
        if tech:
            event.mitre = [tech]
            event.severity = max(event.severity, 4)
    return event


def _registry_activity(record: Dict[str, Any]) -> NormalizedEvent:
    """Sysmon 12 (crear/borrar clave) y 13 (escribir valor).

    Antes salian como 'launch' con status correcto y SIN el objeto tocado: o
    sea, se veia que algo habia pasado pero no que clave. Escribir en Run es la
    forma clasica de persistencia en Windows, y es un hallazgo entero.
    """
    tipo = str(first(record, "EventType", "event_type") or "").lower()
    borrado = "delete" in tipo
    event = _base_event(record, CLASS_REGISTRY,
                        "registry_delete" if borrado else "registry_set", 3)
    event.status = "success"

    clave = first(record, "TargetObject", "registry_key", "Object_Name")
    event.registry = RegistryRef(
        key=str(clave) if clave else None,
        value=str(first(record, "Details", "registry_value_name") or "") or None,
        data=str(first(record, "Details", "registry_value_data") or "") or None,
    )
    image = first(record, "Image", "process_path")
    if image:
        event.process = ProcRef(name=basename(image), path=str(image))
    event.actor = _actor(record, "User", "user")

    bajo = str(clave or "").lower().replace("/", "\\")
    if any(trozo in bajo for trozo in _CLAVES_DE_ARRANQUE):
        event.severity = max(event.severity, 4)
        tech = technique("T1547.001")
        if tech:
            event.mitre = [tech]
    return event


def _dns_query(record: Dict[str, Any]) -> NormalizedEvent:
    """Sysmon EventCode 22 y telemetria DNS del CIM."""
    event = _base_event(record, CLASS_DNS, "dns_query", 2)
    event.status = "success"
    event.domain = canon_domain(first(record, "QueryName", "query", "domain",
                                      "dns_query", "name"))
    image = first(record, "Image", "process_path")
    if image:
        event.process = ProcRef(name=basename(image), path=str(image))
        if _ruta_sospechosa(image):
            # Un binario en Temp resolviendo un nombre es otra cosa que Chrome
            # resolviendo el mismo nombre.
            event.severity = max(event.severity, 4)
    user = first(record, "User", "user")
    if user:
        event.actor = ActorRef(user=str(user))

    # La IP RESPONDIDA, nunca el servidor que responde. Confundirlos dibuja una
    # arista mentirosa: el dominio malicioso apareciendo como si resolviera al
    # DNS interno de la propia empresa.
    answer = first(record, "QueryResults", "answer", "dns_answer")
    if answer:
        for chunk in str(answer).split(";"):
            candidate = chunk.strip().lstrip("type:").strip()
            if is_ip(candidate):
                event.dst = HostRef(ip=candidate)
                break
    return event


def _is_private(ip: str) -> bool:
    from .base import is_private_ip

    return is_private_ip(ip)


# ---------------------------------------------------------------------------
# Despacho
# ---------------------------------------------------------------------------

# EventCode -> constructor. Windows Security y System.
_HANDLERS = {
    # Autenticacion
    "4624": lambda r: _logon(r, True),
    "4625": lambda r: _logon(r, False),
    "4634": _logoff,
    "4647": _logoff,
    "4648": _logon_explicit,
    "4768": _auth_ticket,
    "4769": _auth_ticket,
    # Cuentas
    "4720": lambda r: _account_change(r, "account_create", 4, "T1136"),
    "4722": lambda r: _account_change(r, "account_modify", 3),
    "4724": lambda r: _account_change(r, "account_modify", 4, "T1098"),
    "4725": lambda r: _account_change(r, "account_modify", 3),
    "4726": lambda r: _account_change(r, "account_delete", 4),
    "4738": lambda r: _account_change(r, "account_modify", 3),
    "4740": lambda r: _account_change(r, "account_modify", 3),
    "4728": _group_member_add,
    "4732": _group_member_add,
    "4756": _group_member_add,
    # Procesos
    "4688": _process_create,
    # PowerShell
    "4103": _powershell_script,
    "4104": _powershell_script,
    # Servicios y borrado de auditoria
    "7045": _service_install,
    "1102": _log_clear,
}

# EventCode -> constructor, SOLO para Sysmon. Van aparte porque son numeros
# bajos que en otro canal de Windows significan cosas distintas.
_SYSMON = {
    "1": _process_create,
    "2": lambda r: _file_activity(r, "file_modify", 3),
    "3": _network_connect,
    "5": _process_terminate,
    "7": _module_load,
    "8": lambda r: _process_pair(r, "process_inject"),
    "10": lambda r: _process_pair(r, "process_access"),
    "11": lambda r: _file_activity(r, "file_create", 2),
    "12": _registry_activity,
    "13": _registry_activity,
    "15": lambda r: _file_activity(r, "file_create", 3),
    "22": _dns_query,
    "23": lambda r: _file_activity(r, "file_delete", 3),
}

# Campos que solo aparecen en un canal de Sysmon. Es la forma FIABLE de saber
# que un EventCode 11 es Sysmon: mirar la forma del registro en vez de buscar la
# palabra 'sysmon' en un sourcetype que pone el cliente.
_HUELLA_SYSMON = ("SourceImage", "TargetImage", "TargetFilename", "QueryName",
                  "ImageLoaded", "TargetObject", "RuleName", "UtcTime",
                  "ProcessGuid", "SourceProcessGuid")


def _es_sysmon(record: Dict[str, Any], sourcetype: str) -> bool:
    """Decide si un EventCode bajo viene de Sysmon.

    Antes esto era ``'sysmon' in sourcetype``, y el sourcetype lo fija quien
    monta el TA en cada cliente. Con 'XmlWinEventLog' -que es de lo mas comun-
    la comprobacion fallaba y el evento caia en la red de arrastre.

    Ahora se mira PRIMERO la forma del registro, que no depende de como haya
    decidido llamarlo nadie: los campos de _HUELLA_SYSMON no existen en ningun
    otro canal de Windows. El sourcetype se sigue aceptando como pista, pero ya
    no es la unica.
    """
    if "sysmon" in sourcetype:
        return True
    return any(campo in record for campo in _HUELLA_SYSMON)


def normalize(record: Dict[str, Any]) -> Optional[NormalizedEvent]:
    sourcetype = str(record.get("sourcetype") or record.get("source") or "").lower()
    code = str(first(record, "EventCode", "EventID", "signature_id") or "").strip()

    if code in _SYSMON and _es_sysmon(record, sourcetype):
        return _SYSMON[code](record)

    handler = _HANDLERS.get(code)
    if handler is not None:
        return handler(record)

    # Sin EventCode reconocido, se decide por el sourcetype.
    #
    # 'dns' PRIMERO. Antes 'stream:' y 'cisco' se comprobaban antes, y como los
    # sourcetypes de DNS de Splunk Stream y de Cisco Umbrella son 'stream:dns' y
    # 'cisco:umbrella:dns', su telemetria DNS entera se clasificaba como red y
    # perdia el dominio consultado, que es el IOC mas pivotable del log.
    if "dns" in sourcetype:
        return _dns_query(record)
    if any(key in sourcetype for key in ("firewall", "proxy", "netflow", "stream:", "pan:", "cisco")):
        return _network_connect(record)

    # Ultimo recurso POR FORMA DEL REGISTRO, no por tener un campo de usuario.
    #
    # La red anterior mandaba a "inicio de sesion correcto" cualquier registro
    # con Account_Name. Medido, salian los diez asi: 4104, 7045, 4672, 4648,
    # 1102, 4698, 4726, 4740, 5140 y 4103. Entre ellos el borrado del registro
    # de auditoria, presentado como una jornada normal.
    if first(record, "QueryName", "dns_query"):
        return _dns_query(record)
    if first(record, "TargetFilename"):
        return _file_activity(record, "file_create", 2)
    if first(record, "dest_ip", "dest", "DestinationIp"):
        return _network_connect(record)
    if first(record, "process", "process_name", "Image"):
        return _process_create(record)

    # Y si no se sabe, SE DICE. 'unknown' no es un valor de trabajo: es la senal
    # de que hace falta un normalizador para este tipo de evento. Se conserva el
    # registro entero en raw para poder escribirlo.
    event = _base_event(record, CLASS_FINDING, "unknown", 1)
    event.actor = _actor(record, "Account_Name", "TargetUserName", "user", "User")
    return event


register("splunk_windows", matches, normalize, priority=10)
