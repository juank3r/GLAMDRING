"""Rutas HTTP de GLAMDRING."""

from .routes_appearance import router as appearance_router  # noqa: F401
from .routes_graph import router as graph_router  # noqa: F401
from .routes_ingest import router as ingest_router  # noqa: F401
from .routes_meta import router as meta_router  # noqa: F401
from .routes_receive import router as receive_router  # noqa: F401
from .routes_report import router as report_router  # noqa: F401
from .routes_threat import router as threat_router  # noqa: F401

__all__ = ["meta_router", "ingest_router", "graph_router",
           "appearance_router", "report_router", "threat_router",
           "receive_router"]
