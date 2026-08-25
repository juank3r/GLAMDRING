"""Rutas de informe: el incidente contado de forma que se pueda archivar."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from ..config import SETTINGS
from ..graph.query import build_filtered, filter_events, parse_moment
from ..report import FORMATS, build, collect_iocs
from ..report.stix import render_flat
from ..store import STORE

router = APIRouter(prefix="/api", tags=["report"])

# La captura del canvas llega como data-URL desde el navegador. Se valida la
# cabecera y el tamano porque acaba incrustada tal cual en un HTML que despues
# circula por correo.
DATA_URL = re.compile(r"^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=\s]+$")
MAX_IMAGE_BYTES = 12 * 1024 * 1024

SAFE_TITLE = re.compile(r"[^\w\s.-]", re.UNICODE)


class ReportRequest(BaseModel):
    """Peticion de informe. Los filtros son los mismos que los del grafo."""

    format: str = Field(default="html", description="html | markdown | json | stix | iocs")
    title: str = ""
    analyst: str = ""
    image: Optional[str] = Field(default=None, description="data-URL con la captura del grafo")
    download: bool = True

    time_from: Optional[str] = Field(default=None, alias="from")
    time_to: Optional[str] = Field(default=None, alias="to")
    # Opcional y no `int` a secas: el frontend manda `null` para decir "sin
    # filtro", y con un entero estricto Pydantic devolvia un 422 que en la
    # interfaz solo se veia como que el boton de informe no hacia nada.
    min_severity: Optional[int] = Field(default=0, alias="minSeverity")
    sources: Optional[List[str]] = None
    tactics: Optional[List[str]] = None
    types: Optional[List[str]] = None
    q: Optional[str] = None

    model_config = {"populate_by_name": True}

    @property
    def severity_floor(self) -> int:
        """Severidad minima efectiva, tolerando None y valores fuera de rango."""
        return max(0, min(5, self.min_severity or 0))


def _validate_image(image: Optional[str]) -> Optional[str]:
    if not image:
        return None
    text = image.strip()
    if not DATA_URL.match(text):
        raise HTTPException(status_code=400,
                            detail="La captura debe ser un data-URL de imagen en base64.")
    if len(text) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="La captura del grafo es demasiado grande.")
    return text


def _filename(title: str, extension: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    slug = SAFE_TITLE.sub("", title or "informe").strip().replace(" ", "_")[:60] or "informe"
    return f"glamdring_{slug}_{stamp}.{extension}"


@router.post("/report")
def make_report(request: ReportRequest) -> Response:
    """Genera el informe en el formato pedido.

    Se construyen el grafo y la lista de eventos con los MISMOS filtros, para que
    la cronologia y las entidades hablen del mismo subconjunto. Con filtros
    distintos el informe se contradiria a si mismo.
    """
    if request.format not in FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"Formato desconocido. Disponibles: {', '.join(sorted(FORMATS))}.",
        )
    if not len(STORE):
        raise HTTPException(status_code=409,
                            detail="No hay eventos cargados: no hay nada que informar.")

    time_from = parse_moment(request.time_from)
    time_to = parse_moment(request.time_to)

    events = filter_events(
        STORE.events,
        time_from=time_from,
        time_to=time_to,
        min_severity=request.severity_floor,
        sources=request.sources,
        tactics=request.tactics,
        text=request.q,
    )
    if not events:
        raise HTTPException(status_code=409,
                            detail="Los filtros no dejan ningun evento en el informe.")

    graph = build_filtered(
        STORE.events,
        version=STORE.version,
        time_from=time_from,
        time_to=time_to,
        min_severity=request.severity_floor,
        sources=request.sources,
        tactics=request.tactics,
        text=request.q,
        entity_types=request.types,
        max_nodes=0,   # el informe no se recorta: es el documento de archivo
    )

    report = build(
        graph,
        events,
        title=request.title,
        image=_validate_image(request.image),
        analyst=request.analyst,
    )

    media_type, extension, renderer = FORMATS[request.format]
    body = renderer(report)

    headers: Dict[str, str] = {}
    if request.download:
        headers["Content-Disposition"] = (
            f'attachment; filename="{_filename(report["title"], extension)}"'
        )
    return Response(content=body, media_type=media_type, headers=headers)


@router.get("/report/preview")
def preview_report(
    time_from: Optional[str] = Query(default=None, alias="from"),
    time_to: Optional[str] = Query(default=None, alias="to"),
    min_severity: int = Query(default=0, ge=0, le=5, alias="minSeverity"),
) -> Dict[str, Any]:
    """La estructura del informe sin renderizar, para previsualizar en el dialogo."""
    if not len(STORE):
        raise HTTPException(status_code=409, detail="No hay eventos cargados.")
    parsed_from, parsed_to = parse_moment(time_from), parse_moment(time_to)
    events = filter_events(STORE.events, time_from=parsed_from, time_to=parsed_to,
                           min_severity=min_severity)
    graph = build_filtered(STORE.events, version=STORE.version,
                           time_from=parsed_from, time_to=parsed_to,
                           min_severity=min_severity, max_nodes=0)
    return build(graph, events)


@router.get("/iocs")
def get_iocs(
    min_severity: int = Query(default=0, ge=0, le=5, alias="minSeverity"),
    flat: bool = Query(default=False, description="texto plano en vez de JSON"),
) -> Response:
    """Indicadores extraidos del grafo actual.

    Nunca incluye direcciones RFC1918: una lista de bloqueo perimetral con la
    propia red dentro es, en el mejor de los casos, inutil.
    """
    graph = build_filtered(STORE.events, version=STORE.version, min_severity=min_severity,
                           max_nodes=SETTINGS.max_graph_nodes)
    iocs = collect_iocs(graph)

    if flat:
        body = render_flat({"iocs": iocs})
        return Response(content=body, media_type="text/plain; charset=utf-8")

    import json

    total = sum(len(items) for items in iocs.values())
    return Response(
        content=json.dumps({"count": total, "iocs": iocs}, indent=2, ensure_ascii=False),
        media_type="application/json; charset=utf-8",
    )
