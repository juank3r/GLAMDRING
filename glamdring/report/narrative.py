"""Convierte eventos normalizados en frases en español.

Es determinista y con plantillas, sin modelo de lenguaje detrás. En un informe
de incidente eso no es una limitación sino un requisito: la misma evidencia
tiene que producir siempre exactamente el mismo texto, y cada frase tiene que
poder rastrearse hasta el log que la generó.

El objetivo no es prosa bonita sino que alguien que no vivió el incidente pueda
leer veinte líneas y entender qué pasó y en qué orden.
"""

from __future__ import annotations

from typing import List, Optional

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
from ..normalize.base import canon_user

# Cuánto de la línea de comandos se enseña en la narración. Completa se come el
# informe; cortada demasiado se pierde justo lo que la hacía sospechosa.
CMDLINE_CHARS = 160


def _user(event: NormalizedEvent) -> str:
    if event.actor and event.actor.user:
        return canon_user(event.actor.user) or str(event.actor.user)
    return "un usuario desconocido"


def _host(event: NormalizedEvent) -> str:
    for ref in (event.device, event.dst, event.src):
        if ref is None:
            continue
        if ref.hostname:
            return ref.hostname
        if ref.ip:
            return ref.ip
    return "un equipo sin identificar"


def _origin(event: NormalizedEvent) -> str:
    if event.src and event.src.hostname:
        return event.src.hostname
    if event.src and event.src.ip:
        return event.src.ip
    return ""


def _target(event: NormalizedEvent) -> str:
    if event.domain:
        return event.domain
    if event.app:
        return event.app
    if event.dst and event.dst.hostname:
        return event.dst.hostname
    if event.dst and event.dst.ip:
        port = f":{event.dst.port}" if event.dst.port else ""
        return f"{event.dst.ip}{port}"
    return "un destino desconocido"


def _cmdline(event: NormalizedEvent) -> str:
    if not event.process or not event.process.cmdline:
        return ""
    text = " ".join(str(event.process.cmdline).split())
    if len(text) > CMDLINE_CHARS:
        text = text[:CMDLINE_CHARS].rstrip() + "…"
    return text


def techniques(event: NormalizedEvent) -> str:
    """'T1059.001 (PowerShell)' para colgarlo al final de la frase."""
    parts = []
    for item in event.mitre:
        parts.append(f"{item.id} ({item.name})" if item.name else item.id)
    return ", ".join(parts)


def describe(event: NormalizedEvent) -> str:
    """Una frase que cuenta qué hizo este evento."""
    if event.class_name == CLASS_FINDING:
        return f"Se disparó la alerta «{event.message}» sobre {_host(event)}."

    if event.class_name == CLASS_AUTHENTICATION:
        origin = _origin(event)
        desde = f" desde {origin}" if origin and origin != _host(event) else ""
        destino = _target(event) if event.app else _host(event)
        if event.status == "failure":
            return f"Falló un intento de autenticación de {_user(event)} contra {destino}{desde}."
        if event.activity == "logon_remote":
            return (f"{_user(event)} inició sesión remota en {destino}{desde}, "
                    f"que es la firma del movimiento lateral.")
        return f"{_user(event)} se autenticó correctamente en {destino}{desde}."

    if event.class_name == CLASS_PROCESS:
        name = (event.process.name if event.process else None) or "un proceso"
        parent = event.process.parent_name if event.process else None
        lanzado = f", lanzado por {parent}" if parent else ""
        cmdline = _cmdline(event)
        detalle = f" con la línea de comandos «{cmdline}»" if cmdline else ""
        return f"{_user(event)} ejecutó {name} en {_host(event)}{lanzado}{detalle}."

    if event.class_name == CLASS_NETWORK:
        if event.activity == "blocked" or event.status == "failure":
            return f"Se bloqueó una conexión de {_host(event)} hacia {_target(event)}."
        proceso = ""
        if event.process and event.process.name:
            proceso = f" mediante {event.process.name}"
        return f"{_host(event)} se conectó a {_target(event)}{proceso}."

    if event.class_name == CLASS_FILE:
        name = (event.file.name if event.file else None) or "un fichero"
        autor = event.process.name if event.process and event.process.name else _user(event)
        verbo = {"delete": "borró", "modify": "modificó", "read": "leyó"}.get(event.activity, "creó")
        ruta = f" en {event.file.path}" if event.file and event.file.path else ""
        return f"{autor} {verbo} {name}{ruta} en {_host(event)}."

    if event.class_name == CLASS_DNS:
        return f"{_host(event)} resolvió el dominio {event.domain or 'desconocido'}."

    if event.class_name == CLASS_EMAIL:
        remitente = (event.email.sender if event.email else None) or "un remitente desconocido"
        destinatario = (event.email.recipient if event.email else None) or "un buzón interno"
        asunto = f" con el asunto «{event.email.subject}»" if event.email and event.email.subject else ""
        return f"{remitente} envió un correo a {destinatario}{asunto}."

    if event.class_name == CLASS_ACCOUNT:
        return f"Se creó o modificó la cuenta {_user(event)} en {_host(event)}."

    return event.message or f"Evento {event.activity} en {_host(event)}."


def is_key_event(event: NormalizedEvent) -> bool:
    """Decide si el evento merece una línea en la cronología del informe.

    Un incidente real trae miles de eventos y casi todos son ruido de fondo. Se
    conservan los que tienen técnica ATT&CK asignada, los graves, los fallos de
    autenticación, las alertas y el correo: lo que un analista subrayaría.
    """
    if event.mitre or event.severity >= 4:
        return True
    if event.class_name in (CLASS_FINDING, CLASS_EMAIL, CLASS_ACCOUNT):
        return True
    if event.status == "failure":
        return True
    if event.class_name == CLASS_AUTHENTICATION and event.activity == "logon_remote":
        return True
    return False


def summarize_events(events: List[NormalizedEvent], limit: int = 60) -> List[dict]:
    """Cronología: eventos clave ordenados en el tiempo, sin repeticiones.

    Los eventos que producen la misma frase se agrupan en una sola entrada con
    su número de repeticiones. Catorce fallos de login idénticos son un hecho,
    no catorce hechos, y escribirlos catorce veces esconde lo que vino después.
    """
    key_events = sorted((e for e in events if is_key_event(e)), key=lambda e: e.time)

    entries: List[dict] = []
    last_text: Optional[str] = None
    for event in key_events:
        text = describe(event)
        if text == last_text and entries:
            entries[-1]["count"] += 1
            entries[-1]["uids"].append(event.uid)
            entries[-1]["until"] = event.time.isoformat()
            entries[-1]["severity"] = max(entries[-1]["severity"], event.severity)
            continue
        entries.append({
            "time": event.time.isoformat(),
            "until": None,
            "text": text,
            "count": 1,
            "severity": event.severity,
            "source": event.source,
            "techniques": [t.id for t in event.mitre],
            "tactics": [t.tactic for t in event.mitre if t.tactic],
            "uids": [event.uid],
        })
        last_text = text

    if len(entries) > limit:
        # Si hay que recortar, se conservan los más graves pero se devuelven en
        # orden cronológico: un informe que salta en el tiempo no se entiende.
        entries = sorted(
            sorted(entries, key=lambda e: (-e["severity"], e["time"]))[:limit],
            key=lambda e: e["time"],
        )
    return entries
