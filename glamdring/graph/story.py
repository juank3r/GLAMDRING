"""El recorrido de una entidad: que hizo, en que orden, y con que arista.

El grafo ensena el ESTADO FINAL de un incidente. Es util para ver quien toca
que, pero no para explicarselo a nadie: falta el orden. Una investigacion se
cuenta en el tiempo, no en el espacio.

Este modulo saca de una entidad la secuencia de sus actos, para que la interfaz
pueda recorrerlos con la camara: aislar lo suyo, ir paso a paso, y en cada paso
decir en castellano que paso y dejar abrir el log original.

NO SE REDACTA NADA NUEVO AQUI. Las frases salen de ``report.narrative``, que ya
las escribe para los informes. Que el recorrido en pantalla y la cronologia del
informe digan exactamente lo mismo no es casualidad ni ahorro de codigo: es que
sean la misma frase evita la version mas tonta de contradecirse.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from ..models import GraphDoc, Link, NormalizedEvent
from ..report import narrative

# Tope de pasos. Un recorrido de 400 pasos no lo mira nadie, y ademas cada paso
# es un vuelo de camara: dejarlo abierto seria un recorrido de veinte minutos.
MAX_STEPS = 120


def _link_index(links: Sequence[Link], node_id: str) -> Dict[str, Link]:
    """uid de evento -> arista del nodo por la que se cuenta.

    Un mismo evento suele generar varias aristas (un proceso que se lanza toca
    al usuario, al equipo y al proceso padre). Para el recorrido interesa la que
    sale o llega A ESTE nodo, que es de quien estamos contando la historia.
    """
    index: Dict[str, Link] = {}
    for link in links:
        if link.source != node_id and link.target != node_id:
            continue
        for uid in link.event_uids:
            # El primero gana y es estable: las aristas llegan siempre en el
            # mismo orden, asi que el recorrido no cambia entre dos llamadas.
            index.setdefault(uid, link)
    return index


def build(
    graph: GraphDoc,
    events: Sequence[NormalizedEvent],
    node_id: str,
    limit: int = MAX_STEPS,
) -> Dict[str, Any]:
    """Los actos de ``node_id`` en orden, listos para recorrer con la camara.

    ``graph`` tiene que venir ya centrado en el nodo (``build_filtered`` con
    ``focus``), porque de ahi salen las aristas que se van iluminando.
    """
    node = next((n for n in graph.nodes if n.id == node_id), None)
    if node is None:
        return {"node": node_id, "label": node_id, "steps": [], "found": False}

    by_uid = _link_index(graph.links, node_id)
    relevant = [event for event in events if event.uid in by_uid]

    steps: List[Dict[str, Any]] = []
    for event in sorted(relevant, key=lambda e: e.time):
        link = by_uid[event.uid]
        text = narrative.describe(event)
        other = link.target if link.source == node_id else link.source

        # Se colapsan las repeticiones consecutivas por la misma arista. Catorce
        # fallos de login identicos son un hecho, no catorce paradas de camara
        # en el mismo sitio diciendo lo mismo.
        if steps and steps[-1]["text"] == text and steps[-1]["linkId"] == link.id:
            last = steps[-1]
            last["count"] += 1
            last["until"] = event.time.isoformat()
            last["severity"] = max(last["severity"], event.severity)
            last["uids"].append(event.uid)
            continue

        steps.append({
            "time": event.time.isoformat(),
            "until": None,
            "text": text,
            "count": 1,
            "severity": event.severity,
            "source": event.source,
            "linkId": link.id,
            "fromId": link.source,
            "toId": link.target,
            # Con quien lo hizo. Es a donde tiene que mirar la camara, y lo que
            # se resalta mientras se lee la frase.
            "otherId": other,
            "relation": link.type,
            "outbound": link.source == node_id,
            "tactics": [t.tactic for t in event.mitre if t.tactic],
            "techniques": [t.id for t in event.mitre],
            "uids": [event.uid],
        })

    truncated = len(steps) > limit
    if truncated:
        # Se recorta por gravedad pero se devuelve en orden: un recorrido que
        # salta hacia atras en el tiempo no se entiende.
        steps = sorted(
            sorted(steps, key=lambda s: (-s["severity"], s["time"]))[:limit],
            key=lambda s: s["time"],
        )

    return {
        "node": node_id,
        "label": node.label,
        "type": node.type,
        "role": (node.props or {}).get("role", ""),
        "found": True,
        "steps": steps,
        "total": len(steps),
        "truncated": truncated,
        "from": steps[0]["time"] if steps else None,
        "to": (steps[-1]["until"] or steps[-1]["time"]) if steps else None,
    }
