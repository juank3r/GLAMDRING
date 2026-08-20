"""Inteligencia de amenazas: herramientas de intrusion, ransomware y atribucion.

    catalog()                el catalogo cargado (herramientas, grupos, notas)
    scan(eventos)            -> Findings: que se ha detectado
    summarize(findings)      -> dict compacto para API e informe
    attribute(findings)      -> candidatos ordenados
    assess(findings)         -> valoracion completa con el aviso incluido

Los datos se vendorizan en `data/` y se actualizan con
`python tools/fetch_threat_intel.py`.

OJO CON EL NOMBRE `catalog`: aqui se reexporta la FUNCION `catalog()`, que tapa
al submodulo `glamdring.threat.catalog`. `from glamdring.threat import catalog`
devuelve la funcion, no el modulo. Para llegar al modulo hace falta
`importlib.import_module("glamdring.threat.catalog")`. Se mantiene asi porque
`catalog()` es la forma en que se usa el 99% de las veces.

Fuentes: Ransomware Tool Matrix (BushidoUK, CC BY 4.0) y ransomware.live
(Julien Mousqueton). La atribucion es una hipotesis, no un veredicto.
"""

from .attribution import Candidate, assess, attribute, explain  # noqa: F401
from .catalog import Catalog, catalog, reload_catalog  # noqa: F401
from .detect import (  # noqa: F401
    SIGNATURES,
    STAGES,
    BehaviourHit,
    Findings,
    NoteSighting,
    ToolSighting,
    scan,
    severity_floor,
    stage_assessment,
    summarize,
)

__all__ = [
    "Catalog", "catalog", "reload_catalog",
    "scan", "summarize", "stage_assessment", "severity_floor",
    "Findings", "ToolSighting", "NoteSighting", "BehaviourHit",
    "SIGNATURES", "STAGES",
    "attribute", "assess", "explain", "Candidate",
]
