"""Rutas de metadatos: salud, ontologia, conectores y ficheros de ejemplo."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter

from ..config import SETTINGS
from ..connectors import FileConnector, describe_all, ping_all
from ..graph import ontology
from ..store import STORE

router = APIRouter(prefix="/api", tags=["meta"])


@router.get("/health")
def health() -> Dict[str, Any]:
    """Estado del servicio y de la investigacion en curso."""
    span = STORE.span()
    return {
        "status": "ok",
        "events": len(STORE),
        "sources": STORE.sources(),
        "span": {
            "from": span["from"].isoformat() if span["from"] else None,
            "to": span["to"].isoformat() if span["to"] else None,
        },
        "lastIngest": STORE.last_ingest.isoformat() if STORE.last_ingest else None,
        "connectors": SETTINGS.public_status(),
        "limits": {
            "maxResults": SETTINGS.max_results,
            "maxGraphNodes": SETTINGS.max_graph_nodes,
        },
    }


@router.get("/ontology")
def get_ontology() -> Dict[str, Any]:
    """Tipos, colores y formas. El frontend sobrescribe con esto su copia local."""
    return ontology.as_dict()


@router.get("/connectors")
def connectors() -> Dict[str, Any]:
    return {"connectors": describe_all()}


@router.get("/connectors/ping")
async def connectors_ping() -> Dict[str, Any]:
    """Comprueba de verdad que cada fuente responde.

    Separado de /connectors a proposito: aquel es instantaneo y se puede pedir
    en cada pintado, este habla por la red y puede tardar. Mezclarlos convertiria
    el arranque de la interfaz en una espera de varios segundos.
    """
    return {"connectors": await ping_all()}


@router.get("/samples")
def samples() -> Dict[str, Any]:
    return {"samples": FileConnector().list_samples()}


@router.get("/ingest-log")
def ingest_log() -> Dict[str, Any]:
    """Historial de ingestas: que entro, cuanto se deduplico y desde donde."""
    return {"log": STORE.ingest_log}
