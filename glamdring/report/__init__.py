"""Generacion de informes de incidente.

    build(graph, events) -> dict          estructura intermedia unica
    html.render(report)  -> str           fichero autocontenido, imprimible
    markdown.render(...) -> str           para Jira / TheHive / wiki
    stix.render_stix(...)-> str           STIX-lite para un TIP
    stix.render_flat(...)-> str           lista pelada de IOCs

Los cuatro formatos parten del MISMO diccionario, que es lo que garantiza que
el HTML y el Markdown del mismo incidente cuenten lo mismo.
"""

from . import html, markdown, narrative, stix  # noqa: F401
from .builder import build, collect_iocs, killchain, recommendations  # noqa: F401

FORMATS = {
    "html": ("text/html; charset=utf-8", "html", lambda r: html.render(r)),
    "markdown": ("text/markdown; charset=utf-8", "md", lambda r: markdown.render(r)),
    "json": ("application/json; charset=utf-8", "json", lambda r: stix.render_json(r)),
    "stix": ("application/json; charset=utf-8", "stix.json", lambda r: stix.render_stix(r)),
    "iocs": ("text/plain; charset=utf-8", "txt", lambda r: stix.render_flat(r)),
}

__all__ = ["build", "collect_iocs", "killchain", "recommendations",
           "html", "markdown", "stix", "narrative", "FORMATS"]
