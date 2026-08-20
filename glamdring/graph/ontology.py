"""Ontologia: fuente de verdad de tipos de entidad, relaciones y su aspecto.

El frontend consume esto por ``GET /api/ontology`` y sobrescribe su copia local,
de modo que anadir un tipo de entidad se hace en UN solo sitio.

``model``, ``shape`` y ``glyph`` viven aqui a proposito: la decision "un host es
un puesto de trabajo verde" es semantica, no de presentacion, y debe ser
identica en el grafo, en la leyenda y en el informe.

Paleta: los colores estan separados en matiz Y en luminancia, no solo en matiz.
La version anterior se eligio a ojo y varios tonos se confundian a distancia,
que es justo cuando hay que poder distinguirlos.
"""

from __future__ import annotations

from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Entidades (nodos)
#   model -> figura 3D procedural (web/js/render/models.js)
#   shape -> geometria simple de respaldo en calidad baja
#   rank  -> capa por defecto en la kill-chain cuando no hay tactica MITRE
#   size  -> radio base; el tamano final lo modula el riesgo
# ---------------------------------------------------------------------------
ENTITIES: Dict[str, Dict[str, Any]] = {
    "alert":    {"label": "Alerta",       "color": "#ff2d55", "model": "alert",       "shape": "octahedron",  "glyph": "\U0001F6A8", "rank": 0, "size": 9},
    "user":     {"label": "Usuario",      "color": "#4ea8ff", "model": "person",      "shape": "sphere",      "glyph": "\U0001F464", "rank": 1, "size": 7},
    "host":     {"label": "Host",         "color": "#4ade80", "model": "workstation", "shape": "box",         "glyph": "\U0001F5A5", "rank": 2, "size": 8},
    "process":  {"label": "Proceso",      "color": "#fb923c", "model": "gear",        "shape": "cone",        "glyph": "⚙",     "rank": 3, "size": 5},
    "file":     {"label": "Fichero",      "color": "#d4a5ff", "model": "document",    "shape": "cylinder",    "glyph": "\U0001F4C4", "rank": 4, "size": 4},
    "ip":       {"label": "IP",           "color": "#2dd4bf", "model": "endpoint",    "shape": "icosahedron", "glyph": "\U0001F310", "rank": 5, "size": 5},
    "domain":   {"label": "Dominio",      "color": "#818cf8", "model": "globe",       "shape": "torus",       "glyph": "\U0001F517", "rank": 5, "size": 5},
    "url":      {"label": "URL",          "color": "#a78bfa", "model": "globe",       "shape": "torus",       "glyph": "\U0001F517", "rank": 5, "size": 4},
    "hash":     {"label": "Hash",         "color": "#94a3b8", "model": "hashcube",    "shape": "tetrahedron", "glyph": "#",          "rank": 6, "size": 4},
    "mailbox":  {"label": "Buzon",        "color": "#f472b6", "model": "envelope",    "shape": "sphere",      "glyph": "✉",     "rank": 2, "size": 5},
    "account":  {"label": "Cuenta cloud", "color": "#22d3ee", "model": "cloud",       "shape": "box",         "glyph": "☁",     "rank": 2, "size": 6},
    "service":  {"label": "Servicio",     "color": "#a3e635", "model": "gear",        "shape": "cylinder",    "glyph": "⚭",     "rank": 4, "size": 4},
    "registry": {"label": "Registro",     "color": "#eab308", "model": "key",         "shape": "box",         "glyph": "\U0001F5DD", "rank": 4, "size": 4},
}

UNKNOWN_ENTITY = {
    "label": "Otro", "color": "#78909c", "model": "endpoint",
    "shape": "sphere", "glyph": "?", "rank": 9, "size": 4,
}

# ---------------------------------------------------------------------------
# Roles: que papel juega la entidad en ESTE incidente.
#
# El rol no es una propiedad del tipo sino del contexto, y es lo que hace que el
# grafo se lea de un vistazo. Lo calcula graph/enrich.py.
# ---------------------------------------------------------------------------
ROLES: Dict[str, Dict[str, Any]] = {
    "hostile":    {"label": "Hostil",       "color": "#ff2d55", "emissive": 0.75,
                   "hint": "Infraestructura del atacante"},
    "victim":     {"label": "Victima",      "color": "#fb923c", "emissive": 0.55,
                   "hint": "Entidad propia con impacto confirmado"},
    "suspicious": {"label": "Sospechosa",   "color": "#eab308", "emissive": 0.40,
                   "hint": "Entidad propia con indicios sin confirmar"},
    "asset":      {"label": "Activo sano",  "color": "#4ade80", "emissive": 0.18,
                   "hint": "Entidad propia sin hallazgos"},
    "neutral":    {"label": "Contexto",     "color": "#94a3b8", "emissive": 0.12,
                   "hint": "Artefacto forense de apoyo"},
}

# Sustituciones de figura por pareja "tipo:rol". Lo que no aparece aqui usa el
# ``model`` del tipo.
#
# El caso importante es ``ip:hostile``: una IP externa con trafico de mando y
# control deja de ser una cajita y pasa a ser una figura encapuchada, que se
# reconoce desde el otro extremo de la escena sin leer la etiqueta.
ROLE_MODELS: Dict[str, str] = {
    "ip:hostile": "attacker",
    "domain:hostile": "attacker",
    "url:hostile": "attacker",
    "user:hostile": "attacker",
    "account:hostile": "attacker",
    "mailbox:hostile": "attacker",
}

# Clase de equipo deducida del hostname (la calcula enrich.py). Decide si un
# ``host`` se dibuja como puesto, rack, router o cortafuegos.
DEVICE_MODELS: Dict[str, str] = {
    "workstation": "workstation",
    "server": "server",
    "router": "router",
    "firewall": "firewall",
}


def model_for(entity_type: str, role: str = "", device_class: str = "") -> str:
    """Figura 3D que corresponde a una entidad concreta.

    Prioridad: rol > clase de equipo > tipo. El rol manda porque "esto es del
    atacante" es mas urgente de comunicar que "esto es un servidor".
    """
    override = ROLE_MODELS.get(f"{entity_type}:{role}")
    if override:
        return override
    if entity_type == "host" and device_class in DEVICE_MODELS:
        return DEVICE_MODELS[device_class]
    return str(entity(entity_type).get("model") or "endpoint")


# ---------------------------------------------------------------------------
# Relaciones (aristas)
#   dashed -> relacion inferida o contextual, no un hecho duro del log
#   weight -> peso en el calculo de riesgo y grosor de la arista
# ---------------------------------------------------------------------------
RELATIONS: Dict[str, Dict[str, Any]] = {
    "authenticated": {"label": "autentica en",    "color": "#4ea8ff", "dashed": False, "weight": 3},
    "failed_auth":   {"label": "fallo login en",  "color": "#fb7185", "dashed": True,  "weight": 2},
    "executed":      {"label": "ejecuta",         "color": "#fb923c", "dashed": False, "weight": 3},
    "spawned":       {"label": "lanza",           "color": "#fbbf24", "dashed": False, "weight": 4},
    "ran_on":        {"label": "corre en",        "color": "#4ade80", "dashed": True,  "weight": 1},
    "connected":     {"label": "conecta con",     "color": "#2dd4bf", "dashed": False, "weight": 3},
    "blocked":       {"label": "bloqueado hacia", "color": "#78716c", "dashed": True,  "weight": 1},
    "resolved":      {"label": "resuelve a",      "color": "#818cf8", "dashed": True,  "weight": 1},
    "wrote":         {"label": "escribe",         "color": "#d4a5ff", "dashed": False, "weight": 2},
    "read":          {"label": "lee",             "color": "#a78bfa", "dashed": True,  "weight": 1},
    "deleted":       {"label": "borra",           "color": "#ef4444", "dashed": False, "weight": 2},
    "has_hash":      {"label": "hash",            "color": "#94a3b8", "dashed": True,  "weight": 1},
    "triggered":     {"label": "dispara",         "color": "#ff2d55", "dashed": False, "weight": 5},
    "affects":       {"label": "afecta a",        "color": "#f43f5e", "dashed": False, "weight": 5},
    "owns":          {"label": "posee",           "color": "#f472b6", "dashed": True,  "weight": 1},
    "lateral":       {"label": "movimiento lat.", "color": "#f97316", "dashed": False, "weight": 5},
    "persisted":     {"label": "persiste en",     "color": "#eab308", "dashed": False, "weight": 4},
    "downloaded":    {"label": "descarga",        "color": "#06b6d4", "dashed": False, "weight": 3},
    "sent_to":       {"label": "envia a",         "color": "#f472b6", "dashed": False, "weight": 2},
    "contains_url":  {"label": "contiene URL",    "color": "#a78bfa", "dashed": True,  "weight": 2},
}

UNKNOWN_RELATION = {"label": "relacionado", "color": "#64748b", "dashed": True, "weight": 1}

# ---------------------------------------------------------------------------
# Severidad (escala OCSF 0-6 comprimida a 0-5)
#
# Es lo unico calido de toda la interfaz: si algo esta naranja o rojo, importa.
# ---------------------------------------------------------------------------
SEVERITY: List[Dict[str, Any]] = [
    {"id": 0, "key": "unknown",  "label": "Desconocida", "color": "#64748b"},
    {"id": 1, "key": "info",     "label": "Informativa", "color": "#38bdf8"},
    {"id": 2, "key": "low",      "label": "Baja",        "color": "#4ade80"},
    {"id": 3, "key": "medium",   "label": "Media",       "color": "#fbbf24"},
    {"id": 4, "key": "high",     "label": "Alta",        "color": "#f97316"},
    {"id": 5, "key": "critical", "label": "Critica",     "color": "#ff2d55"},
]

# ---------------------------------------------------------------------------
# MITRE ATT&CK: el orden de la lista ES el orden de capas de la kill-chain
# ---------------------------------------------------------------------------
TACTICS: List[str] = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

TACTIC_LABELS: Dict[str, str] = {
    "reconnaissance": "Reconocimiento",
    "resource-development": "Desarrollo de recursos",
    "initial-access": "Acceso inicial",
    "execution": "Ejecucion",
    "persistence": "Persistencia",
    "privilege-escalation": "Escalada de privilegios",
    "defense-evasion": "Evasion de defensas",
    "credential-access": "Acceso a credenciales",
    "discovery": "Descubrimiento",
    "lateral-movement": "Movimiento lateral",
    "collection": "Recoleccion",
    "command-and-control": "Mando y control",
    "exfiltration": "Exfiltracion",
    "impact": "Impacto",
}

SOURCES: Dict[str, Dict[str, Any]] = {
    "splunk":   {"label": "Splunk",             "color": "#65a637"},
    "sentinel": {"label": "Microsoft Sentinel", "color": "#0078d4"},
    "qradar":   {"label": "IBM QRadar",         "color": "#1f70c1"},
    "elastic":  {"label": "Elastic",            "color": "#f04e98"},
    "generic":  {"label": "Generico",           "color": "#94a3b8"},
}

# Modos de coloreado que ofrece la barra superior. El grafo es el mismo; lo que
# cambia es que dimension se lleva el color, que es la pregunta que el analista
# tenga en la cabeza en ese momento.
COLOR_MODES: List[Dict[str, str]] = [
    {"id": "type",     "label": "Tipo de entidad"},
    {"id": "role",     "label": "Papel en el incidente"},
    {"id": "severity", "label": "Severidad"},
    {"id": "risk",     "label": "Riesgo"},
    {"id": "source",   "label": "Origen del dato"},
    {"id": "tactic",   "label": "Tactica MITRE"},
    {"id": "cluster",  "label": "Comunidad"},
]

# Rampa continua para el modo "riesgo": de verde tranquilo a rojo urgente.
RISK_RAMP: List[str] = ["#4ade80", "#a3e635", "#fbbf24", "#f97316", "#ff2d55"]

# Paleta ciclica para el modo "comunidad". Tonos bien separados entre si porque
# aqui el numero de cluster no significa nada: solo hay que distinguirlos.
CLUSTER_PALETTE: List[str] = [
    "#4ea8ff", "#fb923c", "#4ade80", "#f472b6", "#a78bfa",
    "#2dd4bf", "#eab308", "#f43f5e", "#818cf8", "#a3e635",
]


def entity(entity_type: str) -> Dict[str, Any]:
    return ENTITIES.get(entity_type, UNKNOWN_ENTITY)


def relation(relation_type: str) -> Dict[str, Any]:
    return RELATIONS.get(relation_type, UNKNOWN_RELATION)


def severity(level: int) -> Dict[str, Any]:
    return SEVERITY[max(0, min(5, int(level)))]


def role(role_id: str) -> Dict[str, Any]:
    return ROLES.get(role_id, ROLES["neutral"])


def source(source_id: str) -> Dict[str, Any]:
    return SOURCES.get(source_id, SOURCES["generic"])


def tactic_rank(tactic: str) -> int:
    """Posicion de la tactica en la cadena. 99 si no la conocemos."""
    try:
        return TACTICS.index(tactic)
    except ValueError:
        return 99


def as_dict() -> Dict[str, Any]:
    """Payload de ``GET /api/ontology``."""
    return {
        "entities": ENTITIES,
        "unknownEntity": UNKNOWN_ENTITY,
        "relations": RELATIONS,
        "unknownRelation": UNKNOWN_RELATION,
        "roles": ROLES,
        "roleModels": ROLE_MODELS,
        "deviceModels": DEVICE_MODELS,
        "severity": SEVERITY,
        "tactics": TACTICS,
        "tacticLabels": TACTIC_LABELS,
        "sources": SOURCES,
        "colorModes": COLOR_MODES,
        "riskRamp": RISK_RAMP,
        "clusterPalette": CLUSTER_PALETTE,
    }
