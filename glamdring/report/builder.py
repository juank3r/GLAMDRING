"""Monta el informe del incidente a partir del grafo y de los eventos.

Produce una estructura intermedia que despues renderizan ``html.py``,
``markdown.py`` y ``stix.py``. Tener ese paso intermedio evita el clasico
problema de que el HTML y el Markdown acaben contando cosas distintas porque
cada uno recalcula lo suyo.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from ..graph import ontology
from ..graph.enrich import ROLE_HOSTILE, ROLE_SUSPICIOUS, ROLE_VICTIM
from ..models import GraphDoc, NormalizedEvent
from ..normalize.base import is_private_ip
from . import narrative

# Que hacer ante cada tactica detectada. Son las acciones de contencion de
# primera hora, no un plan de respuesta completo.
RECOMMENDATIONS: Dict[str, Dict[str, Any]] = {
    "initial-access": {
        "priority": 2,
        "text": "Revisar el vector de entrada (correo, portal expuesto o credencial valida) y "
                "bloquear el remitente y la URL en el correo y en el proxy.",
    },
    "execution": {
        "priority": 2,
        "text": "Recoger las lineas de comandos completas de los procesos implicados y buscar "
                "esa misma ejecucion en el resto del parque.",
    },
    "persistence": {
        "priority": 1,
        "text": "Buscar y eliminar los mecanismos de persistencia (tareas programadas, servicios, "
                "claves Run) antes de reiniciar el equipo, o volveran a activarse.",
    },
    "privilege-escalation": {
        "priority": 1,
        "text": "Revisar que cuentas obtuvieron privilegios y cuando; auditar los grupos "
                "administrativos del dominio.",
    },
    "defense-evasion": {
        "priority": 1,
        "text": "Comprobar si se manipularon el antivirus o los registros de eventos: la "
                "telemetria posterior a ese momento puede estar incompleta.",
    },
    "credential-access": {
        "priority": 0,
        "text": "Asumir comprometidas TODAS las credenciales del equipo afectado. Rotar "
                "contrasenas, revocar tickets Kerberos y forzar el cambio de krbtgt si el "
                "volcado fue en un controlador de dominio.",
    },
    "discovery": {
        "priority": 3,
        "text": "Revisar que informacion del dominio pudo enumerarse para anticipar los "
                "siguientes objetivos del atacante.",
    },
    "lateral-movement": {
        "priority": 0,
        "text": "Aislar de la red los equipos origen y destino del movimiento lateral y revisar "
                "las sesiones abiertas de las cuentas implicadas.",
    },
    "collection": {
        "priority": 1,
        "text": "Identificar que datos se recopilaron y si estan sujetos a notificacion "
                "regulatoria.",
    },
    "command-and-control": {
        "priority": 0,
        "text": "Bloquear en el perimetro las IP y dominios de mando y control, y buscar esas "
                "mismas conexiones en el resto de la organizacion.",
    },
    "exfiltration": {
        "priority": 0,
        "text": "Cuantificar el volumen transferido y activar el procedimiento de notificacion "
                "de brecha si hubo salida de datos.",
    },
    "impact": {
        "priority": 0,
        "text": "Verificar la integridad de las copias de seguridad antes de restaurar, y que "
                "no fueron accesibles desde los equipos comprometidos.",
    },
    "reconnaissance": {
        "priority": 3,
        "text": "Revisar la exposicion externa que permitio el reconocimiento previo.",
    },
    "resource-development": {
        "priority": 3,
        "text": "Documentar la infraestructura del atacante para compartirla con el sector.",
    },
}


# Que hacer cuando la deteccion apunta a un despliegue de ransomware en curso.
# Van aparte de las recomendaciones por tactica porque la urgencia es otra: aqui
# el reloj corre.
RANSOMWARE_ACTIONS: Dict[str, Dict[str, Any]] = {
    "inhibit": {
        "priority": 0,
        "text": "Se estan borrando instantaneas y copias de seguridad. El cifrado "
                "suele ir MINUTOS despues. Aisla ya los equipos afectados de la red "
                "y protege las copias fuera de linea antes de nada mas.",
    },
    "impact": {
        "priority": 0,
        "text": "Hay nota de rescate: el cifrado ya ha empezado. Deja de contener y "
                "pasa a limitar el alcance; conserva una imagen forense de un equipo "
                "cifrado antes de restaurar nada.",
    },
    "exfiltration": {
        "priority": 0,
        "text": "Los datos salieron antes de cifrar. Aunque se restaure sin pagar, "
                "hay brecha de datos: activa el procedimiento de notificacion.",
    },
    "foothold": {
        "priority": 1,
        "text": "Se ha instalado una herramienta de acceso remoto. Busca esa misma "
                "herramienta en el resto del parque: es como vuelven despues.",
    },
}


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _duration_text(start: Optional[datetime], end: Optional[datetime]) -> Optional[str]:
    if not start or not end or end <= start:
        return None
    seconds = int((end - start).total_seconds())
    if seconds < 60:
        return f"{seconds} segundos"
    if seconds < 3600:
        return f"{seconds // 60} minutos"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} horas"
    return f"{seconds / 86400:.1f} dias"


def collect_iocs(graph: GraphDoc) -> Dict[str, List[Dict[str, Any]]]:
    """Indicadores extraibles del grafo, listos para bloquear.

    Solo salen los que apuntan hacia fuera: una IP RFC1918 en una lista de
    bloqueo del perimetro no sirve de nada y, peor, invita a bloquear la propia
    red. Por eso las internas se descartan explicitamente.
    """
    buckets: Dict[str, List[Dict[str, Any]]] = {
        "ip": [], "domain": [], "url": [], "hash": [], "file": [], "mailbox": [],
    }

    for node in graph.nodes:
        role = str(node.props.get("role") or "")
        value = node.label
        entry = {
            "value": value,
            "role": role,
            "risk": node.risk,
            "severity": node.max_severity,
            "firstSeen": _iso(node.first_seen),
            "lastSeen": _iso(node.last_seen),
            "sources": node.sources,
        }

        if node.type == "ip":
            if is_private_ip(value):
                continue  # una IP interna no es un indicador para el perimetro
            buckets["ip"].append(entry)
        elif node.type == "domain":
            buckets["domain"].append(entry)
        elif node.type == "url":
            buckets["url"].append(entry)
        elif node.type == "hash":
            entry["value"] = str(node.props.get("full") or value)
            entry["algo"] = node.props.get("algo", "sha256")
            buckets["hash"].append(entry)
        elif node.type == "file" and role in (ROLE_HOSTILE, ROLE_SUSPICIOUS):
            entry["value"] = str(node.props.get("path") or node.id.split(":", 1)[-1])
            buckets["file"].append(entry)
        elif node.type == "mailbox" and role == ROLE_HOSTILE:
            buckets["mailbox"].append(entry)

    for key in buckets:
        buckets[key].sort(key=lambda item: (-item["risk"], item["value"]))
    return buckets


def killchain(graph: GraphDoc, entries: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Tacticas detectadas, en orden de la cadena, con su evidencia."""
    seen: Dict[str, Dict[str, Any]] = {}

    for node in graph.nodes:
        for tactic in node.tactics:
            stage = seen.setdefault(tactic, {
                "tactic": tactic,
                "label": ontology.TACTIC_LABELS.get(tactic, tactic),
                "rank": ontology.tactic_rank(tactic),
                "entities": [],
                "evidence": [],
                "firstSeen": None,
            })
            if len(stage["entities"]) < 12:
                stage["entities"].append({"id": node.id, "label": node.label, "type": node.type})
            if node.first_seen and (stage["firstSeen"] is None or _iso(node.first_seen) < stage["firstSeen"]):
                stage["firstSeen"] = _iso(node.first_seen)

    for entry in entries:
        for tactic in entry.get("tactics", []):
            stage = seen.get(tactic)
            if stage is not None and len(stage["evidence"]) < 6:
                stage["evidence"].append({"time": entry["time"], "text": entry["text"]})

    return sorted(seen.values(), key=lambda stage: (stage["rank"], stage["tactic"]))


def recommendations(stages: Sequence[Dict[str, Any]],
                    threat: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Acciones de contencion derivadas de las tacticas y de lo detectado."""
    out = []
    for stage in stages:
        template = RECOMMENDATIONS.get(stage["tactic"])
        if template is None:
            continue
        out.append({
            "tactic": stage["tactic"],
            "label": stage["label"],
            "priority": template["priority"],
            "text": template["text"],
        })

    # Las acciones de ransomware se anaden solo si hay evidencia de esa etapa,
    # y se marcan como urgentes para que salgan las primeras.
    for etapa in (threat or {}).get("detection", {}).get("stages", []):
        if not etapa.get("reached"):
            continue
        accion = RANSOMWARE_ACTIONS.get(etapa["id"])
        if accion is None:
            continue
        out.append({
            "tactic": etapa["id"],
            "label": f"URGENTE - {etapa['label']}",
            "priority": accion["priority"],
            "text": accion["text"],
        })

    return sorted(out, key=lambda item: (item["priority"], item["label"]))


def build(
    graph: GraphDoc,
    events: Sequence[NormalizedEvent],
    title: str = "",
    image: Optional[str] = None,
    analyst: str = "",
) -> Dict[str, Any]:
    """Estructura completa del informe."""
    times = [event.time for event in events]
    start, end = (min(times), max(times)) if times else (None, None)

    by_role: Dict[str, int] = {}
    for node in graph.nodes:
        role = str(node.props.get("role") or "neutral")
        by_role[role] = by_role.get(role, 0) + 1

    entries = narrative.summarize_events(list(events))
    stages = killchain(graph, entries)
    iocs = collect_iocs(graph)
    threat_block = _threat_section(events)

    entities = [
        {
            "id": node.id,
            "label": node.label,
            "type": node.type,
            "typeLabel": ontology.entity(node.type)["label"],
            "role": str(node.props.get("role") or "neutral"),
            "roleLabel": ontology.role(str(node.props.get("role") or "neutral"))["label"],
            "risk": node.risk,
            "severity": node.max_severity,
            "events": node.event_count,
            "firstSeen": _iso(node.first_seen),
            "lastSeen": _iso(node.last_seen),
            "sources": node.sources,
            "tactics": node.tactics,
        }
        for node in sorted(graph.nodes, key=lambda n: -n.risk)
    ]

    max_severity = max((node.max_severity for node in graph.nodes), default=0)

    return {
        "title": title or _auto_title(graph),
        "generated": datetime.now(timezone.utc).isoformat(),
        "analyst": analyst,
        "window": {"from": _iso(start), "to": _iso(end),
                   "duration": _duration_text(start, end)},
        "summary": {
            "events": len(events),
            "nodes": len(graph.nodes),
            "links": len(graph.links),
            "maxSeverity": max_severity,
            "maxSeverityLabel": ontology.severity(max_severity)["label"],
            "sources": graph.meta.sources,
            "roles": by_role,
            "tactics": [stage["tactic"] for stage in stages],
            "iocCount": sum(len(items) for items in iocs.values()),
        },
        "narrative": entries,
        "killchain": stages,
        "entities": entities,
        "iocs": iocs,
        "recommendations": recommendations(stages, threat_block),
        "threat": threat_block,
        "image": image,
    }


def _threat_section(events: Sequence[NormalizedEvent]) -> Dict[str, Any]:
    """Deteccion de herramientas, comportamiento de ransomware y atribucion.

    Si el catalogo no esta disponible se devuelve un bloque vacio en lugar de
    fallar: el informe tiene que salir igual sin inteligencia de amenazas.
    """
    try:
        from ..threat import assess, attribute, catalog, explain, scan, summarize
    except ImportError:  # pragma: no cover
        return {"available": False}

    kb = catalog()
    if not kb.available:
        return {"available": False}

    findings = scan(events, kb)
    if not (findings.tools or findings.behaviours or findings.notes):
        return {"available": True, "detected": False,
                "sources": kb.meta.get("sources", [])}

    candidatos = attribute(findings, kb)
    return {
        "available": True,
        "detected": True,
        "detection": summarize(findings),
        "attribution": assess(findings, kb),
        "explanation": explain(candidatos[0], kb) if candidatos else "",
        "sources": kb.meta.get("sources", []),
    }


def _auto_title(graph: GraphDoc) -> str:
    """Titula el informe con las victimas principales del incidente.

    Un informe llamado 'Informe de incidente' no se distingue del de la semana
    pasada cuando hay cuarenta en una carpeta.
    """
    victims = [node for node in graph.nodes
               if node.props.get("role") == ROLE_VICTIM and node.type in ("host", "user")]
    victims.sort(key=lambda node: -node.risk)
    names = [node.label for node in victims[:2]]
    if not names:
        return "Informe de incidente"
    if len(names) == 1:
        return f"Incidente en {names[0]}"
    return f"Incidente en {names[0]} y {names[1]}"
