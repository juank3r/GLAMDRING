"""Rutas del grafo: consulta filtrada, vecindad, timeline y logs crudos."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from ..config import SETTINGS
from ..graph import story
from ..graph.query import build_filtered, parse_moment, timeline
from ..store import STORE

router = APIRouter(prefix="/api", tags=["graph"])


def _csv(value: Optional[str]) -> Optional[List[str]]:
    """'user,host, ip' -> ['user','host','ip']. Vacio -> None (sin filtro)."""
    if not value:
        return None
    items = [part.strip() for part in value.split(",") if part.strip()]
    return items or None


@router.get("/graph")
def get_graph(
    time_from: Optional[str] = Query(default=None, alias="from",
                                     description="ISO-8601 o relativo ('-24h')"),
    time_to: Optional[str] = Query(default=None, alias="to"),
    min_severity: int = Query(default=0, ge=0, le=5, alias="minSeverity"),
    sources: Optional[str] = Query(default=None, description="splunk,sentinel,qradar,generic"),
    tactics: Optional[str] = Query(default=None, description="slugs MITRE separados por coma"),
    classes: Optional[str] = Query(default=None, description="clases OCSF separadas por coma"),
    q: Optional[str] = Query(default=None, description="busqueda de texto libre"),
    types: Optional[str] = Query(default=None, description="tipos de entidad a conservar"),
    relations: Optional[str] = Query(default=None, description="tipos de relacion a conservar"),
    focus: Optional[str] = Query(default=None, description="id de nodo sobre el que pivotar"),
    hops: int = Query(default=1, ge=1, le=5),
    max_nodes: int = Query(default=0, ge=0, alias="maxNodes"),
) -> Dict[str, Any]:
    """Grafo de la investigacion con todos los filtros aplicados en servidor."""
    graph = build_filtered(
        STORE.events,
        time_from=parse_moment(time_from),
        time_to=parse_moment(time_to),
        min_severity=min_severity,
        sources=_csv(sources),
        tactics=_csv(tactics),
        classes=_csv(classes),
        text=q,
        entity_types=_csv(types),
        relation_types=_csv(relations),
        focus=focus,
        hops=hops,
        max_nodes=max_nodes or SETTINGS.max_graph_nodes,
    )
    return graph.model_dump(by_alias=True, mode="json")


@router.get("/graph/neighbors")
def get_neighbors(
    node: str = Query(description="id de nodo, p.ej. 'host:wks-0421'"),
    hops: int = Query(default=1, ge=1, le=5),
    min_severity: int = Query(default=0, ge=0, le=5, alias="minSeverity"),
) -> Dict[str, Any]:
    """Vecindad de N saltos: el 'expandir nodo' del analista."""
    graph = build_filtered(
        STORE.events,
        min_severity=min_severity,
        focus=node,
        hops=hops,
        max_nodes=SETTINGS.max_graph_nodes,
    )
    if not graph.nodes:
        raise HTTPException(status_code=404, detail=f"El nodo '{node}' no existe en la investigacion.")
    return graph.model_dump(by_alias=True, mode="json")


@router.get("/graph/story")
def get_story(
    node: str = Query(description="id de nodo, p.ej. 'user:jlopez'"),
    hops: int = Query(default=1, ge=1, le=3),
    min_severity: int = Query(default=0, ge=0, le=5, alias="minSeverity"),
    limit: int = Query(default=story.MAX_STEPS, ge=1, le=500),
) -> Dict[str, Any]:
    """Lo que hizo una entidad, en orden, para recorrerlo con la camara.

    El grafo ensena el estado final del incidente; esto ensena como se llego a
    el. Cada paso trae la arista por la que ocurrio, con quien, la frase que lo
    cuenta y los uids para abrir el log original.
    """
    graph = build_filtered(
        STORE.events,
        min_severity=min_severity,
        focus=node,
        hops=hops,
        max_nodes=SETTINGS.max_graph_nodes,
    )
    if not graph.nodes:
        raise HTTPException(status_code=404,
                            detail=f"El nodo '{node}' no existe en la investigacion.")

    result = story.build(graph, STORE.events, node, limit=limit)
    if not result["found"]:
        raise HTTPException(status_code=404,
                            detail=f"El nodo '{node}' no existe en la investigacion.")
    # El subgrafo viaja con el recorrido: la interfaz necesita las dos cosas a la
    # vez (con que se queda en pantalla, y por donde va pasando) y pedirlas por
    # separado abriria la puerta a que no cuadren entre si.
    result["graph"] = graph.model_dump(by_alias=True, mode="json")
    return result


@router.get("/timeline")
def get_timeline(
    buckets: int = Query(default=120, ge=10, le=1000),
    min_severity: int = Query(default=0, ge=0, le=5, alias="minSeverity"),
    sources: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Histograma para el slider temporal y el replay."""
    from ..graph.query import filter_events

    events = filter_events(
        STORE.events,
        min_severity=min_severity,
        sources=_csv(sources),
        text=q,
    )
    return timeline(events, buckets=buckets).model_dump(by_alias=True, mode="json")


@router.get("/events")
def get_events(
    uids: Optional[str] = Query(default=None, description="uids separados por coma"),
    node: Optional[str] = Query(default=None, description="id de nodo cuyos eventos se quieren"),
    limit: int = Query(default=200, ge=1, le=2000),
) -> Dict[str, Any]:
    """Logs crudos detras de un nodo o una arista.

    Es la ruta que hace la herramienta defendible: todo lo que se ve en el grafo
    se puede contrastar con el registro original del SIEM.
    """
    selected = []
    if uids:
        selected = STORE.get_many(_csv(uids) or [], limit=limit)
    elif node:
        graph = build_filtered(STORE.events, focus=node, hops=1,
                               max_nodes=SETTINGS.max_graph_nodes)
        target = next((n for n in graph.nodes if n.id == node), None)
        if target is None:
            raise HTTPException(status_code=404, detail=f"El nodo '{node}' no existe.")
        selected = STORE.get_many(target.props.get("eventUids", []), limit=limit)
    else:
        raise HTTPException(status_code=400, detail="Indica 'uids' o 'node'.")

    return {
        "count": len(selected),
        "events": [event.model_dump(by_alias=True, mode="json") for event in selected],
    }


@router.get("/export")
def export_graph(
    time_from: Optional[str] = Query(default=None, alias="from"),
    time_to: Optional[str] = Query(default=None, alias="to"),
    min_severity: int = Query(default=0, ge=0, le=5, alias="minSeverity"),
) -> Dict[str, Any]:
    """Grafo completo sin recortes, para adjuntar a un informe o reimportarlo."""
    graph = build_filtered(
        STORE.events,
        time_from=parse_moment(time_from),
        time_to=parse_moment(time_to),
        min_severity=min_severity,
        max_nodes=0,
    )
    return graph.model_dump(by_alias=True, mode="json")
