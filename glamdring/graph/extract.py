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


def _add_process(collector: _Collector, event: NormalizedEvent, host_key: Optional[str]) -> Optional[str]:
    """El proceso se identifica por ruta, y se ancla a su host.

    Sin anclar al host, 'powershell.exe' seria un unico nodo compartido por
    todas las maquinas del dominio y el grafo seria inservible.
    """
    if not event.process or event.process.is_empty():
        return None
    path = canon_path(event.process.path or event.process.name)
    if not path:
        return None
    host_part = host_key.split(":", 1)[1] if host_key else "?"
    return collector.add(
        "process", f"{host_part}|{path}",
        label=event.process.name or path,
        path=event.process.path,
        cmdline=event.process.cmdline,
        pid=event.process.pid,
        integrity=event.process.integrity,
    )


def _add_parent_process(collector: _Collector, event: NormalizedEvent,
                        host_key: Optional[str]) -> Optional[str]:
    if not event.process:
        return None
    path = canon_path(event.process.parent_path or event.process.parent_name)
    if not path:
        return None
    host_part = host_key.split(":", 1)[1] if host_key else "?"
    return collector.add(
        "process", f"{host_part}|{path}",
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


def _add_network_target(collector: _Collector, event: NormalizedEvent) -> Optional[str]:
    """Destino de una conexion: dominio si lo hay, si no la IP."""
    domain = canon_domain(event.domain)
    if domain:
        return collector.add("domain", domain, label=domain, url=event.url)
    return _add_endpoint(collector, event.dst, role="dst")


# ---------------------------------------------------------------------------
# Reglas por clase de evento
# ---------------------------------------------------------------------------


def _authentication(collector: _Collector, event: NormalizedEvent) -> None:
    user_key = _add_user(collector, event)
    device_key = _add_device(collector, event)
    src_key = _add_endpoint(collector, event.src, role="src")
    # Una autenticacion cloud no va contra una maquina sino contra una aplicacion.
    app_key = None
    if event.app:
        app_key = collector.add("service", str(event.app).strip().lower(),
                                label=str(event.app), cloud=True)
    dst_key = app_key or _add_endpoint(collector, event.dst, role="dst") or device_key

    target = dst_key or device_key
    failed = event.status == "failure" or event.activity == "logon_failed"
    rel = "failed_auth" if failed else "authenticated"
    collector.link(user_key, target, rel, logon_type=event.raw.get("_logon_type_label"))

    if src_key and target and src_key != target:
        if event.activity == "logon_remote" and not failed:
            # Origen y destino identificados en un logon remoto correcto: esto es
            # exactamente la firma del movimiento lateral.
            collector.link(src_key, target, "lateral", logon_type=event.raw.get("_logon_type_label"))
        else:
            collector.link(src_key, target, "connected")


def _process_activity(collector: _Collector, event: NormalizedEvent) -> None:
    device_key = _add_device(collector, event)
    user_key = _add_user(collector, event)
    process_key = _add_process(collector, event, device_key)
    parent_key = _add_parent_process(collector, event, device_key)
    file_key, hash_key = _add_file(collector, event)

    collector.link(parent_key, process_key, "spawned")
    collector.link(user_key, process_key, "executed")
    collector.link(process_key, device_key, "ran_on")
    if not parent_key:
        # Sin padre conocido, al menos el host queda unido al usuario.
        collector.link(user_key, device_key, "authenticated")
    if hash_key and process_key:
        collector.link(process_key, hash_key, "has_hash")


def _network_activity(collector: _Collector, event: NormalizedEvent) -> None:
    device_key = _add_device(collector, event)
    src_key = _add_endpoint(collector, event.src, role="src") or device_key
    target_key = _add_network_target(collector, event)
    user_key = _add_user(collector, event)
    process_key = _add_process(collector, event, device_key or src_key)

    origin = process_key or src_key or device_key
    rel = "blocked" if event.activity == "blocked" or event.status == "failure" else "connected"
    collector.link(origin, target_key, rel, port=event.dst.port if event.dst else None)

    if process_key:
        collector.link(process_key, device_key, "ran_on")
        collector.link(user_key, process_key, "executed")
    else:
        collector.link(user_key, src_key, "authenticated")

    # Si conocemos dominio e IP del destino, la resolucion es informacion util.
    if event.domain and event.dst and event.dst.ip and is_ip(str(event.dst.ip)):
        domain_key = f"domain:{canon_domain(event.domain)}"
        ip_key = collector.add("ip", str(event.dst.ip), label=str(event.dst.ip),
                               private=is_private_ip(str(event.dst.ip)))
        collector.link(domain_key, ip_key, "resolved")


def _file_activity(collector: _Collector, event: NormalizedEvent) -> None:
    device_key = _add_device(collector, event)
    user_key = _add_user(collector, event)
    process_key = _add_process(collector, event, device_key)
    file_key, hash_key = _add_file(collector, event)

    rel = {"delete": "deleted", "read": "read"}.get(event.activity, "wrote")
    collector.link(process_key or user_key or device_key, file_key, rel)
    collector.link(file_key, hash_key, "has_hash")
    if process_key:
        collector.link(process_key, device_key, "ran_on")


def _dns_activity(collector: _Collector, event: NormalizedEvent) -> None:
    device_key = _add_device(collector, event)
    process_key = _add_process(collector, event, device_key)
    domain_key = collector.add("domain", canon_domain(event.domain), label=event.domain) if event.domain else None
    collector.link(process_key or device_key, domain_key, "connected")
    if event.dst and event.dst.ip and domain_key:
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

    url = event.email.url or event.url
    domain = canon_domain(url.split("//")[-1].split("/")[0]) if url else canon_domain(event.domain)
    if domain:
        domain_key = collector.add("domain", domain, label=domain, url=url)
        collector.link(recipient_key, domain_key, "contains_url")


def _account_change(collector: _Collector, event: NormalizedEvent) -> None:
    device_key = _add_device(collector, event)
    user_key = _add_user(collector, event)
    collector.link(user_key, device_key, "persisted")


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
