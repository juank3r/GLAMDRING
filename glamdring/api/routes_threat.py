"""Rutas de inteligencia de amenazas: herramientas, ransomware y atribucion."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from ..graph.query import filter_events, parse_moment
from ..store import STORE
from ..threat import assess, attribute, catalog, explain, scan, summarize

router = APIRouter(prefix="/api", tags=["threat"])


def _csv(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    items = [part.strip() for part in value.split(",") if part.strip()]
    return items or None


@router.get("/threat")
def threat_assessment(
    time_from: Optional[str] = Query(default=None, alias="from"),
    time_to: Optional[str] = Query(default=None, alias="to"),
    min_severity: int = Query(default=0, ge=0, le=5, alias="minSeverity"),
    sources: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Valoracion completa: que herramientas hay, en que etapa esta y a quien se parece.

    Los filtros son los mismos que los del grafo, para que lo que se valora sea
    exactamente lo que el analista tiene delante.
    """
    if not len(STORE):
        raise HTTPException(status_code=409, detail="No hay eventos cargados.")

    kb = catalog()
    if not kb.available:
        raise HTTPException(
            status_code=503,
            detail=("No hay catalogo de inteligencia. Ejecuta "
                    "'python tools/fetch_threat_intel.py' para descargarlo."),
        )

    events = filter_events(
        STORE.events,
        time_from=parse_moment(time_from),
        time_to=parse_moment(time_to),
        min_severity=min_severity,
        sources=_csv(sources),
        text=q,
    )

    findings = scan(events, kb)
    resumen = summarize(findings)
    atribucion = assess(findings, kb)

    # La frase explicativa se genera aqui y no en el cliente: el matiz de "esto
    # es una hipotesis" es justo lo que no se puede perder por el camino.
    candidatos = attribute(findings, kb)
    if candidatos:
        atribucion["explanation"] = explain(candidatos[0], kb)

    return {
        "events": len(events),
        "detection": resumen,
        "attribution": atribucion,
    }


@router.get("/threat/catalog")
def threat_catalog() -> Dict[str, Any]:
    """Estado del catalogo: cuanto sabe, de cuando es y de donde salio.

    Las fuentes viajan aqui porque la licencia de la Ransomware Tool Matrix
    (CC BY 4.0) exige atribucion, y porque saber de cuando son los datos cambia
    como se lee una atribucion.
    """
    kb = catalog()
    return {
        "available": kb.available,
        **kb.stats(),
        "groups": sorted(kb.groups),
        "categories": sorted({
            tool.get("categoryLabel", "") for tool in kb.tools.values()
        } - {""}),
    }


@router.get("/threat/group/{name}")
def threat_group(name: str) -> Dict[str, Any]:
    """Perfil de un grupo: su arsenal por categoria, sus notas y sus fuentes."""
    kb = catalog()
    grupo = kb.group(name)
    if grupo is None:
        coincidencias = [g for g in kb.groups if g.lower() == name.lower()]
        if not coincidencias:
            raise HTTPException(status_code=404, detail=f"Grupo desconocido: {name}")
        grupo = kb.groups[coincidencias[0]]

    # Se anota cuanto distingue cada herramienta, que es lo que explica por que
    # el motor puntua como puntua.
    detalle = []
    for herramienta in grupo.get("tools", []):
        detalle.append({
            "name": herramienta,
            "usedByGroups": kb.tool_group_count.get(herramienta, 0),
            "weight": round(kb.discriminating_weight(herramienta), 2),
            "category": (kb.tools.get(herramienta) or {}).get("categoryLabel", ""),
        })
    detalle.sort(key=lambda item: -item["weight"])

    return {**grupo, "toolDetail": detalle}
