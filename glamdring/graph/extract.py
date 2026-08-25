"""De un ``NormalizedEvent`` a entidades y relaciones.

Aqui vive el criterio de "que merece ser un nodo". La tentacion es convertir
todos los campos en nodos, y el resultado es una bola de pelo ilegible. Las
reglas son deliberadamente conservadoras:

* Solo se crea un nodo si tiene identidad estable (un usuario, un host, un hash).
  Un puerto o un id de sesion son propiedades, no nodos.
* Las cuentas de maquina y de servicio de Windows se descartan en ``canon_user``:
  aparecen en todos los eventos y unirian todo el grafo por el sitio equivocado.
* Un mismo evento puede generar varias aristas, pero siempre entre entidades que
  el propio evento demuestra que estan relacionadas. Nada de inferir.
* **Un nodo creado y sin ninguna arista es un fallo**, no un detalle. En el grafo
  3D flota suelto, ocupa sitio, se confunde con una maquina aislada y no cuenta
  nada. Si se crea, se conecta; y si no se puede conectar, no se crea.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..models import (
    CLASS_ACCOUNT,
    CLASS_AUTHENTICATION,
    CLASS_DNS,
    CLASS_EMAIL,
    CLASS_FILE,
    CLASS_FINDING,
    CLASS_NETWORK,
    CLASS_PROCESS,
    CLASS_REGISTRY,
    NormalizedEvent,
)
from ..normalize.base import (
    canon_domain,
    canon_host,
    canon_path,
    canon_user,
    is_ip,
    is_private_ip,
)


@dataclass
class EntitySpec:
    """Una entidad tal y como la ve un evento concreto."""

    type: str
    value: str  # ya canonicalizado
    label: str
    props: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value}"


@dataclass
class RelSpec:
    """Una relacion dirigida entre dos claves de entidad."""

    source: str
    target: str
    type: str
    props: Dict[str, Any] = field(default_factory=dict)


class _Collector:
    """Acumula entidades y relaciones de un evento evitando duplicados."""

    def __init__(self) -> None:
        self.entities: Dict[str, EntitySpec] = {}
        self.relations: List[RelSpec] = []

    def add(self, entity_type: str, value: Optional[str], label: Optional[str] = None,
            **props: Any) -> Optional[str]:
        """Registra una entidad y devuelve su clave, o None si no hay valor."""
        if not value:
            return None
        spec = EntitySpec(
            type=entity_type,
            value=str(value),
            label=str(label or value),
            props={k: v for k, v in props.items() if v not in (None, "")},
        )
        existing = self.entities.get(spec.key)
        if existing is None:
            self.entities[spec.key] = spec
        else:
            # Un evento puede aportar propiedades en dos sitios (p.ej. la IP del
            # host en src y en device): se fusionan sin pisar lo ya conocido.
            for k, v in spec.props.items():
                existing.props.setdefault(k, v)
            if len(spec.label) > len(existing.label):
                existing.label = spec.label
        return spec.key

    def link(self, source: Optional[str], target: Optional[str], rel_type: str, **props: Any) -> None:
        if not source or not target or source == target:
            return
        self.relations.append(
            RelSpec(source=source, target=target, type=rel_type,
                    props={k: v for k, v in props.items() if v not in (None, "")})
        )


# ---------------------------------------------------------------------------
# Constructores de entidad a partir de los sub-objetos del evento
# ---------------------------------------------------------------------------


def _add_user(collector: _Collector, event: NormalizedEvent) -> Optional[str]:
    if not event.actor:
        return None
    name = canon_user(event.actor.user)
    if not name:
        return None
    return collector.add(
        "user", name,
        label=event.actor.user or name,
        domain=event.actor.domain,
        sid=event.actor.sid,
    )


def _add_endpoint(collector: _Collector, ref: Any, role: str = "") -> Optional[str]:
    """Un extremo de red se convierte en 'host' si tiene nombre, si no en 'ip'.

    Es intencionado: el hostname es la identidad estable de una maquina; la IP
    cambia. Cuando hay ambos, la IP queda como propiedad del host, no como nodo
    aparte, para no partir la misma maquina en dos.
    """
    if ref is None:
        return None
    hostname = canon_host(getattr(ref, "hostname", None))
    ip = getattr(ref, "ip", None)
    if hostname and not is_ip(hostname):
        return collector.add("host", hostname, label=hostname, ip=ip,
                             os=getattr(ref, "os", None), role=role or None)
    if ip and is_ip(str(ip)):
        return collector.add("ip", str(ip), label=str(ip),
                             private=is_private_ip(str(ip)), role=role or None)
    if hostname:
        return collector.add("host", hostname, label=hostname, role=role or None)
    return None


def _add_device(collector: _Collector, event: NormalizedEvent) -> Optional[str]:
    """El equipo que reporto el evento: casi siempre el 'donde ocurrio'."""
    return _add_endpoint(collector, event.device, role="device")


def _anchor(collector: _Collector, event: NormalizedEvent) -> Optional[str]:
    """La maquina a la que se ancla lo que pasa dentro de ella.

    ``device`` primero y ``src`` despues. Ese respaldo NO es un detalle: sin el,
    cualquier fuente que reporte por producto en vez de por maquina -QRadar con
    un logsourcename de fabricante, un EDR- deja el evento sin host, y entonces
    todos sus procesos se anclaban al literal '?' y se fundian entre si.

    Medido antes del arreglo, con dos eventos de proceso de dos maquinas
    distintas: un unico nodo 'process:?|c:\\windows\\temp\\svc.exe' con dos
    eventos, y NINGUN nodo de maquina en el grafo. El analista concluia que era
    una sola ejecucion y no veia que el mismo binario corria en dos equipos, que
    es justo la senal de propagacion.
    """
    return _add_device(collector, event) or _add_endpoint(collector, event.src, role="src")


def _host_part(event: NormalizedEvent, host_key: Optional[str]) -> str:
    """El trozo de la clave de proceso que representa la maquina.

    Sin maquina conocida se usa un discriminante POR EVENTO y no un '?'
    compartido. Fundir procesos de maquinas desconocidas es afirmar que son la
    misma, y no lo sabemos: dos equipos sin identificar son dos equipos, no uno.
    Repetir un proceso en el mismo equipo desconocido tampoco se funde, que es
    lo honesto cuando no se sabe si es el mismo equipo.
    """
    if host_key:
        return host_key.split(":", 1)[1]
    return f"?{event.uid[:8]}"


def _add_process(collector: _Collector, event: NormalizedEvent,
                 host_key: Optional[str], ref: Any = None,
                 role: str = "") -> Optional[str]:
    """El proceso se identifica por ruta, y se ancla a su host.

    Sin anclar al host, 'powershell.exe' seria un unico nodo compartido por
    todas las maquinas del dominio y el grafo seria inservible.
    """
    proc = ref if ref is not None else event.process
    if not proc or proc.is_empty():
        return None
    path = canon_path(proc.path or proc.name)
    if not path:
        return None
    return collector.add(
        "process", f"{_host_part(event, host_key)}|{path}",
        label=proc.name or path,
        path=proc.path,
        cmdline=proc.cmdline,
        pid=proc.pid,
        integrity=proc.integrity,
        role=role or None,
        hostUnknown=True if not host_key else None,
    )


def _add_parent_process(collector: _Collector, event: NormalizedEvent,
                        host_key: Optional[str]) -> Optional[str]:
    if not event.process:
        return None
    path = canon_path(event.process.parent_path or event.process.parent_name)
    if not path:
        return None
    return collector.add(
        "process", f"{_host_part(event, host_key)}|{path}",
        label=event.process.parent_name or path,
        path=event.process.parent_path,
        pid=event.process.parent_pid,
    )


def _add_file(collector: _Collector, event: NormalizedEvent) -> Tuple[Optional[str], Optional[str]]:
    """Devuelve (clave del fichero, clave del hash)."""
    if not event.file or event.file.is_empty():
        return None, None
    file_key = None
    path = canon_path(event.file.path or event.file.name)
    if path:
        file_key = collector.add("file", path, label=event.file.name or path,
                                 path=event.file.path, size=event.file.size)
    digest = event.file.sha256 or event.file.md5
    hash_key = None
    if digest:
        hash_key = collector.add("hash", str(digest).lower(),
                                 label=f"{str(digest)[:12]}...",
                                 algo="sha256" if event.file.sha256 else "md5",
                                 full=str(digest).lower())
    return file_key, hash_key


def _add_app(collector: _Collector, event: NormalizedEvent) -> Optional[str]:
    """La aplicacion cloud contra la que se actua (Office 365, Mega, Dropbox)."""
    if not event.app:
        return None
    return collector.add("service", str(event.app).strip().lower(),
                         label=str(event.app), cloud=True)


def _add_network_target(collector: _Collector, event: NormalizedEvent) -> Optional[str]:
    """Destino de una conexion: dominio si lo hay, si no la IP."""
    domain = canon_domain(event.domain)
    if domain:
        return collector.add("domain", domain, label=domain, url=event.url)
    return _add_endpoint(collector, event.dst, role="dst")


def _net_props(event: NormalizedEvent) -> Dict[str, Any]:
    """Lo que se movio por la conexion, para colgarlo de la arista.

    Los bytes van en la arista y no en un tipo de actividad nuevo: 700 MiB
    salientes no son otra clase de hecho, son el mismo hecho con un dato mas. Lo
    que no puede ser es que ese dato se pierda al normalizar, porque es lo unico
    que separa una exfiltracion de abrir una pagina web.
    """
    props: Dict[str, Any] = {"port": event.dst.port if event.dst else None}
    if event.net:
        props.update({
            "bytesIn": event.net.bytes_in,
            "bytesOut": event.net.bytes_out,
            "protocol": event.net.protocol,
            "rule": event.net.rule,
            "category": event.net.category,
        })
    return props


# ---------------------------------------------------------------------------
# Reglas por clase de evento
# ---------------------------------------------------------------------------

# Ya no se mira `activity == "blocked"`: el desenlace vive en `status` y solo
# ahi. Tener el mismo dato en dos sitios es tener dos sitios donde puede
# discrepar.
def _failed(event: NormalizedEvent) -> bool:
    return event.status == "failure"


def _authentication(collector: _Collector, event: NormalizedEvent) -> None:
    user_key = _add_user(collector, event)
    device_key = _add_device(collector, event)
    src_key = _add_endpoint(collector, event.src, role="src")
    app_key = _add_app(collector, event)
    dst_key = app_key or _add_endpoint(collector, event.dst, role="dst") or device_key

    target = dst_key or device_key
    rel = "failed_auth" if _failed(event) else "authenticated"
    collector.link(user_key, target, rel, logon_type=event.raw.get("_logon_type_label"))

    if src_key and target and src_key != target:
        # 'lateral' SOLO en un inicio de sesion remoto correcto. Un logoff trae
        # el mismo Logon_Type y antes entraba por aqui: veinte desconexiones
        # rutinarias de un recurso compartido pintaban veintiun nodos como
        # victima de movimiento lateral, y cuando hubiera un salto de verdad no
        # se habria distinguido del fondo.
        if event.activity == "logon_remote" and not _failed(event):
            collector.link(src_key, target, "lateral",
                           logon_type=event.raw.get("_logon_type_label"))
        else:
            collector.link(src_key, target, "connected")


def _process_activity(collector: _Collector, event: NormalizedEvent) -> None:
    host_key = _anchor(collector, event)
    user_key = _add_user(collector, event)
    process_key = _add_process(collector, event, host_key)
    file_key, hash_key = _add_file(collector, event)

    # Inyeccion y acceso a handle son los dos unicos hechos con DOS procesos en
    # el mismo evento: quien inyecta y en quien. Sin el segundo nodo, un volcado
    # de LSASS con mimikatz no se distingue de un proceso cualquiera.
    if event.activity in ("process_inject", "process_access") and event.target_process:
        target_key = _add_process(collector, event, host_key,
                                  ref=event.target_process, role="target")
        rel = "injected_into" if event.activity == "process_inject" else "accessed"
        collector.link(process_key, target_key, rel)
        collector.link(target_key, host_key, "ran_on")
        collector.link(user_key, process_key, "executed")
        collector.link(process_key, host_key, "ran_on")
        if hash_key and process_key:
            collector.link(process_key, hash_key, "has_hash")
        return

    if event.activity == "module_load":
        collector.link(process_key, file_key, "loaded")
        collector.link(file_key, hash_key, "has_hash")
        collector.link(process_key, host_key, "ran_on")
        collector.link(user_key, process_key, "executed")
        return

    parent_key = _add_parent_process(collector, event, host_key)
    collector.link(parent_key, process_key, "spawned")
    collector.link(user_key, process_key, "executed")
    collector.link(process_key, host_key, "ran_on")
    if not parent_key:
        # Sin padre conocido, al menos el host queda unido al usuario.
        collector.link(user_key, host_key, "authenticated")
    if hash_key and process_key:
        collector.link(process_key, hash_key, "has_hash")


def _network_activity(collector: _Collector, event: NormalizedEvent) -> None:
    device_key = _add_device(collector, event)
    src_key = _add_endpoint(collector, event.src, role="src") or device_key
    target_key = _add_network_target(collector, event) or _add_app(collector, event)
    user_key = _add_user(collector, event)
    process_key = _add_process(collector, event, device_key or src_key)

    origin = process_key or src_key or device_key
    if event.activity in ("tunnel_open", "tunnel_close"):
        collector.link(user_key or origin, target_key or _add_app(collector, event),
                       "tunneled_to", **_net_props(event))
    else:
        rel = "blocked" if _failed(event) else "connected"
        collector.link(origin, target_key, rel, **_net_props(event))

    if process_key:
        collector.link(process_key, device_key, "ran_on")
        collector.link(user_key, process_key, "executed")
    else:
        collector.link(user_key, src_key, "authenticated")

    # EL CORTAFUEGOS QUE SOLO MIRA. En telemetria de perimetro el 'device' es el
    # propio cortafuegos y el 'src' es el equipo interno, asi que device_key se
    # creaba y no se enlazaba con nada: sobre perimeter.cef el FortiGate salia
    # con grado 0, flotando suelto en el grafo 3D con pinta de equipo aislado.
    #
    # Se enlaza en vez de dejar de crearlo porque el dato SI vale: por donde
    # salio el trafico es lo unico que aporta el perimetro cuando el EDR no
    # cubre esa maquina.
    if device_key and device_key != src_key and device_key != target_key:
        collector.link(device_key, src_key or target_key, "observed")

    # Si conocemos dominio e IP del destino, la resolucion es informacion util.
    if event.domain and event.dst and event.dst.ip and is_ip(str(event.dst.ip)):
        domain_key = f"domain:{canon_domain(event.domain)}"
        ip_key = collector.add("ip", str(event.dst.ip), label=str(event.dst.ip),
                               private=is_private_ip(str(event.dst.ip)))
        collector.link(domain_key, ip_key, "resolved")


# Que verbo dibuja cada actividad de fichero. Antes eran dos casos y todo lo
# demas caia en 'wrote', que convertia una DETECCION de antivirus en "jlopez
# creo m.exe": el evento decia que Defender encontro el fichero, no que nadie
# lo escribiera.
_FILE_REL = {
    "file_create": "wrote",
    "file_modify": "modified",
    "file_delete": "deleted",
    "file_read": "read",
    "file_upload": "uploaded_to",
    "file_download": "downloaded_from",
    "file_share": "shared_with",
}


def _file_activity(collector: _Collector, event: NormalizedEvent) -> None:
    host_key = _anchor(collector, event)
    user_key = _add_user(collector, event)
    process_key = _add_process(collector, event, host_key)
    file_key, hash_key = _add_file(collector, event)
    app_key = _add_app(collector, event)

    rel = _FILE_REL.get(event.activity, "wrote")
    quien = process_key or user_key or host_key

    if event.activity in ("file_upload", "file_download", "file_share") and app_key:
        # En un movimiento a la nube el destino es la aplicacion, no el disco.
        # Es lo que separa "subio 4 GB a Internet" de "subio 4 GB a Mega".
        collector.link(quien, app_key, rel, **_net_props(event))
        collector.link(file_key, app_key, "stored_on")
    else:
        collector.link(quien, file_key, rel)

    collector.link(file_key, hash_key, "has_hash")

    # SIEMPRE la maquina donde esta el fichero. Antes el host se creaba y no se
    # enlazaba nunca: un volcador de credenciales con cuarentena FALLIDA en el
    # controlador de dominio dejaba host:srv-dc01 con grado 0, y quien pinchaba
    # el fichero no veia en que maquina estaba.
    collector.link(file_key, host_key, "stored_on")
    if process_key:
        collector.link(process_key, host_key, "ran_on")


def _registry_activity(collector: _Collector, event: NormalizedEvent) -> None:
    """Claves de registro: la forma clasica de persistencia en Windows.

    La ontologia ya admitia el tipo de nodo 'registry' y nadie lo creaba, asi
    que Sysmon 12/13 -escribir en Run para arrancar con la sesion- salia como
    'launch' y sin decir QUE clave se habia tocado.
    """
    host_key = _anchor(collector, event)
    user_key = _add_user(collector, event)
    process_key = _add_process(collector, event, host_key)
    if not event.registry or event.registry.is_empty():
        return
    clave = str(event.registry.key)
    # 'valueName' y no 'value': add() ya usa 'value' para el valor de la propia
    # entidad, y pasarlo como propiedad choca con el parametro.
    key_node = collector.add("registry", clave.lower(), label=clave,
                             valueName=event.registry.value, data=event.registry.data)
    rel = "deleted" if event.activity == "registry_delete" else "persisted"
    collector.link(process_key or user_key or host_key, key_node, rel)
    collector.link(key_node, host_key, "stored_on")
    if process_key:
        collector.link(process_key, host_key, "ran_on")


def _dns_activity(collector: _Collector, event: NormalizedEvent) -> None:
    host_key = _anchor(collector, event)
    process_key = _add_process(collector, event, host_key)
    domain_key = (collector.add("domain", canon_domain(event.domain), label=event.domain)
                  if event.domain else None)
    # El respaldo a la maquina de origen es lo que evita el dominio huerfano: en
    # un log de perimetro no hay ni proceso ni 'device', pero 'src' SI trae el
    # equipo que pregunto. Sin esto, unificar el DNS producia un nodo de dominio
    # bonito y desconectado, que es solo media mejora.
    collector.link(process_key or host_key, domain_key, "connected")

    # La IP RESPONDIDA, nunca el resolutor. Poner aqui el servidor DNS interno
    # dibujaba una arista mentirosa: el dominio malicioso apareciendo como si
    # resolviera al InfoBlox de la propia empresa.
    if event.dst and event.dst.ip and domain_key and is_ip(str(event.dst.ip)):
        ip_key = collector.add("ip", str(event.dst.ip), label=str(event.dst.ip),
                               private=is_private_ip(str(event.dst.ip)))
        collector.link(domain_key, ip_key, "resolved")


def _email_activity(collector: _Collector, event: NormalizedEvent) -> None:
    if not event.email:
        return
    sender = event.email.sender
    recipient = event.email.recipient
    sender_key = collector.add("mailbox", str(sender).lower(), label=str(sender)) if sender else None
    recipient_key = collector.add("mailbox", str(recipient).lower(), label=str(recipient)) if recipient else None
    collector.link(sender_key, recipient_key, "sent_to", subject=event.email.subject)

    # El buzon destino se ata a su usuario para que el correo enlace con el resto
    # del incidente (el mismo jlopez que luego hace login).
    if recipient and "@" in str(recipient):
        user_key = collector.add("user", canon_user(recipient), label=str(recipient))
        collector.link(user_key, recipient_key, "owns")

    if event.activity == "email_access":
        collector.link(_add_user(collector, event), recipient_key, "read")

    url = event.email.url or event.url
    domain = canon_domain(url.split("//")[-1].split("/")[0]) if url else canon_domain(event.domain)
    if domain:
        domain_key = collector.add("domain", domain, label=domain, url=url)
        collector.link(recipient_key, domain_key, "contains_url")


def _account_change(collector: _Collector, event: NormalizedEvent) -> None:
    host_key = _anchor(collector, event)
    user_key = _add_user(collector, event)

    # Meter a alguien en Domain Admins no es "un cambio de cuenta mas": es
    # escalada de privilegios, y merece su propio nodo y su propia arista.
    grupo = event.raw.get("_group_name")
    if event.activity == "group_member_add" and grupo:
        group_key = collector.add("group", str(grupo).strip().lower(), label=str(grupo))
        collector.link(user_key, group_key, "member_of")
        collector.link(group_key, host_key, "stored_on")
        return

    collector.link(user_key, host_key, "persisted")


def _finding(collector: _Collector, event: NormalizedEvent) -> None:
    """Una alerta se cuelga de todo lo que menciona."""
    alert_label = event.message or "Alerta"
    alert_key = collector.add(
        "alert", f"{event.source}|{event.uid}",
        label=alert_label[:70],
        severity=event.severity,
        techniques=[t.id for t in event.mitre] or None,
        origin=event.origin,
    )

    touched: List[Optional[str]] = [
        _add_device(collector, event),
        _add_user(collector, event),
        _add_endpoint(collector, event.src, role="src"),
        _add_network_target(collector, event),
    ]
    file_key, hash_key = _add_file(collector, event)
    touched.extend([file_key, hash_key])
    # La alerta nombra el fichero y su hash: dejar constancia de que van juntos
    # es lo que luego permite fundir el 'm.exe' de la alerta con el
    # 'C:\\Windows\\Temp\\m.exe' que vio Sysmon.
    collector.link(file_key, hash_key, "has_hash")

    # Entidades sueltas que el normalizador de Sentinel dejo aparcadas.
    for extra in event.raw.get("_extra_entities", []) or []:
        if isinstance(extra, dict):
            touched.append(collector.add(str(extra.get("type")), str(extra.get("value"))))

    for key in touched:
        if key and key != alert_key:
            collector.link(alert_key, key, "affects")


_RULES = {
    CLASS_AUTHENTICATION: _authentication,
    CLASS_PROCESS: _process_activity,
    CLASS_NETWORK: _network_activity,
    CLASS_FILE: _file_activity,
    CLASS_REGISTRY: _registry_activity,
    CLASS_DNS: _dns_activity,
    CLASS_EMAIL: _email_activity,
    CLASS_ACCOUNT: _account_change,
    CLASS_FINDING: _finding,
}


def extract(event: NormalizedEvent) -> Tuple[List[EntitySpec], List[RelSpec]]:
    """Punto de entrada: evento normalizado -> (entidades, relaciones)."""
    collector = _Collector()
    rule = _RULES.get(event.class_name)
    if rule is not None:
        rule(collector, event)
    else:
        _finding(collector, event)
    return list(collector.entities.values()), collector.relations
