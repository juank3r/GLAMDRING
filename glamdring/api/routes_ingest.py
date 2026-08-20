"""Rutas de entrada de datos: subida de ficheros, demo y consulta al SIEM."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from ..config import SAMPLES_DIR, SETTINGS
from ..connectors import ConnectorError, FileConnector, get_connector
from ..graph.query import parse_moment
from ..normalize import normalize_all
from ..store import STORE

router = APIRouter(prefix="/api", tags=["ingest"])

MAX_UPLOAD_BYTES = 200 * 1024 * 1024


class QueryRequest(BaseModel):
    """Consulta en vivo contra un SIEM."""

    connector: str = Field(description="splunk | sentinel | qradar | files")
    query: str
    time_from: Optional[str] = Field(default=None, alias="from",
                                     description="ISO-8601 o relativo ('-24h')")
    time_to: Optional[str] = Field(default=None, alias="to")
    limit: int = 10_000
    reset: bool = Field(default=False, description="vaciar la investigacion antes de ingestar")

    model_config = {"populate_by_name": True}


def _ingest_records(records: List[Dict[str, Any]], origin: str) -> Dict[str, Any]:
    """Normaliza y guarda, informando de lo que se ha quedado por el camino."""
    events = normalize_all(records)
    stats = STORE.add(events, origin=origin)
    unmatched = len(records) - len(events)
    return {
        "read": len(records),
        "normalized": len(events),
        # Registros que ningun normalizador supo interpretar. Deberia ser 0:
        # si sube, es que hace falta un normalizador nuevo.
        "unmatched": unmatched,
        **stats,
    }


@router.post("/ingest")
async def ingest(
    file: Optional[UploadFile] = File(default=None),
    text: Optional[str] = Form(default=None),
    path: Optional[str] = Form(default=None),
    format_hint: Optional[str] = Form(default=None),
    reset: bool = Form(default=False),
) -> Dict[str, Any]:
    """Ingesta desde fichero subido, texto pegado o ruta del servidor."""
    if reset:
        STORE.clear()

    connector = FileConnector()
    try:
        if file is not None:
            payload = await file.read()
            if len(payload) > MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="Fichero demasiado grande.")
            content = payload.decode("utf-8", errors="replace")
            records, fmt = connector.read_text(content, hint=format_hint or "")
            origin = f"upload:{file.filename}"
        elif text:
            records, fmt = connector.read_text(text, hint=format_hint or "")
            origin = "paste"
        elif path:
            records, fmt = connector.read_path(path)
            origin = f"path:{path}"
        else:
            raise HTTPException(status_code=400, detail="Falta 'file', 'text' o 'path'.")
    except ConnectorError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc

    result = _ingest_records(records, origin)
    result["format"] = fmt
    result["origin"] = origin
    return result


@router.post("/demo")
def load_demo(reset: bool = True) -> Dict[str, Any]:
    """Carga todos los ficheros de ``samples/``.

    Es la puerta de entrada de la herramienta: sin esto habria que tener un SIEM
    delante para ver si funciona.
    """
    if reset:
        STORE.clear()
    if not SAMPLES_DIR.exists():
        raise HTTPException(status_code=404, detail="No hay directorio samples/.")

    connector = FileConnector()
    totals = {"read": 0, "normalized": 0, "unmatched": 0, "added": 0, "duplicates": 0}
    files: List[Dict[str, Any]] = []

    for item in sorted(SAMPLES_DIR.iterdir()):
        if not item.is_file() or item.suffix.lower() not in (".json", ".ndjson", ".csv", ".cef", ".log", ".txt"):
            continue
        try:
            records, fmt = connector.read_path(str(item))
        except ConnectorError as exc:
            files.append({"file": item.name, "error": exc.message})
            continue
        stats = _ingest_records(records, f"sample:{item.name}")
        files.append({"file": item.name, "format": fmt, **stats})
        for key in totals:
            totals[key] += stats.get(key, 0)

    return {"files": files, "totals": totals, "events": len(STORE)}


@router.post("/query")
async def query_siem(request: QueryRequest) -> Dict[str, Any]:
    """Lanza una consulta al SIEM y fusiona el resultado en la investigacion."""
    if request.reset:
        STORE.clear()

    try:
        connector = get_connector(request.connector)
    except ConnectorError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc

    if not connector.configured:
        raise HTTPException(
            status_code=409,
            detail=f"El conector '{request.connector}' no tiene credenciales configuradas.",
        )

    try:
        records = await connector.fetch(
            query=request.query,
            time_from=parse_moment(request.time_from),
            time_to=parse_moment(request.time_to),
            limit=min(request.limit, SETTINGS.max_results),
        )
    except ConnectorError as exc:
        # 502: el fallo es del SIEM o de la consulta, no del servidor.
        raise HTTPException(status_code=502, detail=exc.message) from exc

    result = _ingest_records(records, f"{request.connector}:{request.query[:80]}")
    result["connector"] = request.connector
    return result


@router.post("/reset")
def reset_store() -> Dict[str, Any]:
    """Vacia la investigacion en curso."""
    STORE.clear()
    return {"status": "ok", "events": 0}
