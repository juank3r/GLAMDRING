"""Enriquecido del grafo: roles, clusters y pesos del riesgo.

La diferencia con ``extract.py`` es de alcance. Alli se decide qué es un nodo
mirando UN evento; aquí se decide qué **papel** juega cada nodo mirando el grafo
entero ya montado. Una IP no es hostil por sí misma: lo es porque es externa,
porque una alerta apunta a ella y porque el tráfico que sale hacia ella está
etiquetado como mando y control.

El rol es lo que hace que el grafo se lea de un vistazo: el frontend elige la
figura 3D por la pareja ``(tipo, rol)``, así que el mismo ``host`` se dibuja
como un rack sano o como un puesto comprometido con la pantalla en rojo.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from ..models import GraphDoc, Node
from ..normalize.base import is_private_ip
from . import ontology

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

ROLE_HOSTILE = "hostile"        # infraestructura del atacante
ROLE_VICTIM = "victim"          # entidad nuestra con impacto confirmado
ROLE_SUSPICIOUS = "suspicious"  # entidad nuestra con indicios, sin confirmar
ROLE_ASSET = "asset"            # entidad nuestra, sin hallazgos
ROLE_NEUTRAL = "neutral"        # contexto: hashes, ficheros, procesos benignos

# Tácticas que, vistas desde fuera del perímetro, delatan al atacante.
HOSTILE_TACTICS = frozenset({
    "command-and-control", "exfiltration", "resource-development", "reconnaissance",
})

# Tácticas que, vistas dentro, delatan a una víctima.
VICTIM_TACTICS = frozenset({
    "credential-access", "lateral-movement", "impact", "collection",
    "privilege-escalation", "persistence",
})

# Tipos que representan infraestructura de red y por tanto pueden ser externos.
NETWORK_TYPES = frozenset({"ip", "domain", "url"})

# Tipos que son contexto forense, no actores: nunca se pintan como hostiles.
CONTEXT_TYPES = frozenset({"hash", "file", "process", "registry", "service"})


def is_external(node: Node) -> bool:
    """True si el nodo vive fuera del perímetro.

    Un dominio o una URL son externos por defecto. Una IP lo es si no es
    RFC1918. Los hosts con nombre se consideran nuestros: si estuviera en el
    inventario de otro, no tendríamos su hostname.
    """
    if node.type in ("domain", "url"):
        return True
    if node.type == "ip":
        return not is_private_ip(node.label or node.id.split(":", 1)[-1])
    ip = node.props.get("ip")
    if node.type == "host" and ip:
        return not is_private_ip(str(ip))
    return False


# Prefijos y palabras de hostname que delatan la clase de equipo. Es una
# heuristica de nomenclatura corporativa, no un inventario: por eso hay un
# `deviceClassConfidence` y el panel deja corregirla a mano.
_DEVICE_PATTERNS: Sequence[tuple] = (
    ("firewall", ("fw", "asa", "palo", "fortigate", "fgt", "checkpoint", "srx", "perim")),
    ("router",   ("rtr", "router", "gw", "gateway", "switch", "sw-", "core-", "edge")),
    ("server",   ("srv", "server", "dc0", "dc1", "-dc", "sql", "web", "app", "fs0",
                  "exch", "mail", "vc", "esx", "node", "db")),
)


def guess_device_class(label: str) -> str:
    """Deduce si un host es puesto, servidor, router o cortafuegos.

    Se mira el hostname porque es lo unico que hay: los logs no traen el tipo de
    equipo. Acierta en la mayoria de parques corporativos, donde SRV-DC01 es un
    controlador de dominio y WKS-0421 el portatil de alguien. Cuando no hay
    pista se asume puesto de trabajo, que es lo mas numeroso.
    """
    name = (label or "").strip().lower()
    if not name:
        return "workstation"
    for device_class, needles in _DEVICE_PATTERNS:
        if any(needle in name for needle in needles):
            return device_class
    return "workstation"


def assign_roles(graph: GraphDoc) -> GraphDoc:
    """Escribe ``props.role`` y ``props.external`` en cada nodo.

    El orden importa: primero se marca lo externo, luego se propaga la evidencia
    desde las alertas, y solo al final se decide el rol. Si se decidiera antes de
    propagar, un host que solo aparece como destino de una alerta se quedaría
    como activo sano.
    """
    neighbors = _adjacency(graph)
    by_id = {node.id: node for node in graph.nodes}

    # Evidencia que llega desde las alertas: qué tácticas tocan a cada nodo y
    # cuál es la severidad máxima que le apunta.
    alert_tactics: Dict[str, Set[str]] = defaultdict(set)
    alert_severity: Dict[str, int] = defaultdict(int)
    for node in graph.nodes:
        if node.type != "alert":
            continue
        for neighbor_id in neighbors.get(node.id, ()):
            alert_tactics[neighbor_id].update(node.tactics)
            alert_severity[neighbor_id] = max(alert_severity[neighbor_id], node.max_severity)

    for node in graph.nodes:
        external = is_external(node)
        tactics = set(node.tactics) | alert_tactics.get(node.id, set())
        severity = max(node.max_severity, alert_severity.get(node.id, 0))
        touched_by_alert = node.id in alert_tactics

        role = _decide_role(node, external, tactics, severity, touched_by_alert)
        node.props["external"] = external
        node.props["touchedByAlert"] = touched_by_alert
        node.props["role"] = role

        if node.type == "host":
            node.props.setdefault("deviceClass", guess_device_class(node.label))
        # El modelo 3D se resuelve aqui y no en el navegador para que el informe,
        # la leyenda y el grafo dibujen exactamente la misma figura.
        node.props["model"] = ontology.model_for(
            node.type, role, str(node.props.get("deviceClass") or "")
        )

    # Una dirección alojada en infraestructura del atacante es del atacante.
    # Sin esto, billing@cdn-update-svc.com (el remitente del phishing) sale como
    # "víctima" solo porque los buzones se consideran nuestros por defecto.
    hostile_domains = {
        node.label.lower()
        for node in graph.nodes
        if node.type in ("domain", "url") and node.props.get("role") == ROLE_HOSTILE
    }
    if hostile_domains:
        for node in graph.nodes:
            if node.type not in ("mailbox", "user", "account"):
                continue
            domain = _domain_of(node.label)
            if domain and any(domain == d or domain.endswith("." + d) for d in hostile_domains):
                node.props["role"] = ROLE_HOSTILE
                node.props["external"] = True
                node.props["model"] = ontology.model_for(node.type, ROLE_HOSTILE)

    # Un proceso o un fichero heredan el rol de la máquina donde viven: si el
    # host es la víctima, su proceso malicioso no es "contexto neutro".
    for node in graph.nodes:
        if node.type not in CONTEXT_TYPES or node.props["role"] != ROLE_NEUTRAL:
            continue
        if node.max_severity >= 3 or node.tactics:
            node.props["role"] = ROLE_SUSPICIOUS
            continue
        for neighbor_id in neighbors.get(node.id, ()):
            neighbor = by_id.get(neighbor_id)
            if neighbor is not None and neighbor.props.get("role") == ROLE_VICTIM:
                node.props["role"] = ROLE_SUSPICIOUS
                break

    return graph


def _domain_of(label: str) -> str:
    """Parte de dominio de una direccion de correo o de un UPN."""
    text = str(label or "").strip().lower()
    return text.rsplit("@", 1)[-1] if "@" in text else ""


def _decide_role(node: Node, external: bool, tactics: Set[str],
                 severity: int, touched_by_alert: bool) -> str:
    if node.type == "alert":
        return ROLE_HOSTILE

    if external and node.type in NETWORK_TYPES:
        # Externo + evidencia de C2/exfiltración, o externo señalado por una
        # alerta: es infraestructura del atacante, no un destino cualquiera.
        if tactics & HOSTILE_TACTICS or touched_by_alert or severity >= 4:
            return ROLE_HOSTILE
        return ROLE_NEUTRAL

    if node.type in CONTEXT_TYPES:
        return ROLE_SUSPICIOUS if (severity >= 4 or tactics) else ROLE_NEUTRAL

    # Entidades nuestras: usuarios, hosts, buzones, cuentas.
    if severity >= 4 or (tactics & VICTIM_TACTICS):
        return ROLE_VICTIM
    if severity >= 3 or tactics or touched_by_alert:
        return ROLE_SUSPICIOUS
    return ROLE_ASSET


# ---------------------------------------------------------------------------
# Clusters
# ---------------------------------------------------------------------------


def assign_clusters(graph: GraphDoc, rounds: int = 12) -> GraphDoc:
    """Agrupa el grafo en comunidades por propagación de etiquetas.

    Es el algoritmo más simple que funciona y no necesita dependencias. En un
    grafo de incidente los clusters suelen salir muy interpretables: la cadena
    del atacante por un lado y el ruido de fondo del dominio por otro.

    Se recorren los nodos en orden determinista (no aleatorio, como en el
    algoritmo original) para que dos ejecuciones sobre los mismos datos den el
    mismo resultado: un cluster que cambia de número en cada refresco haría que
    los colores bailasen en pantalla.
    """
    neighbors = _adjacency(graph)
    labels: Dict[str, str] = {node.id: node.id for node in graph.nodes}
    order = sorted(node.id for node in graph.nodes)

    for _ in range(rounds):
        changed = False
        for node_id in order:
            adjacent = neighbors.get(node_id)
            if not adjacent:
                continue
            counts: Dict[str, int] = defaultdict(int)
            for neighbor_id in adjacent:
                counts[labels[neighbor_id]] += 1
            # Empates: gana la etiqueta menor alfabéticamente, otra vez por
            # determinismo.
            best = min(sorted(counts), key=lambda label: (-counts[label], label))
            if best != labels[node_id]:
                labels[node_id] = best
                changed = True
        if not changed:
            break

    # Los identificadores de cluster pasan a ser enteros consecutivos ordenados
    # por tamaño: el cluster 0 es siempre el más grande.
    sizes: Dict[str, int] = defaultdict(int)
    for label in labels.values():
        sizes[label] += 1
    ranking = {label: index for index, label
               in enumerate(sorted(sizes, key=lambda k: (-sizes[k], k)))}

    for node in graph.nodes:
        node.props["cluster"] = ranking[labels[node.id]]
    graph.meta.counts["clusters"] = len(ranking)
    return graph


def _adjacency(graph: GraphDoc) -> Dict[str, Set[str]]:
    adjacency: Dict[str, Set[str]] = defaultdict(set)
    for link in graph.links:
        adjacency[link.source].add(link.target)
        adjacency[link.target].add(link.source)
    return adjacency


# ---------------------------------------------------------------------------
# Pesos del riesgo (configurables desde el panel de administrador)
# ---------------------------------------------------------------------------

DEFAULT_RISK_WEIGHTS: Dict[str, int] = {
    "severity": 12,      # x severidad máxima (0-5)  -> hasta 60, factor dominante
    "tactic": 6,         # x número de tácticas      -> tope tacticCap
    "tacticCap": 18,
    "degree": 2,         # x conexiones              -> tope degreeCap
    "degreeCap": 12,
    "volumeDivisor": 25,  # eventos / divisor        -> tope volumeCap
    "volumeCap": 5,
    "weightDivisor": 10,  # peso de relaciones / div -> tope weightCap
    "weightCap": 5,
    "alertBonus": 15,     # una alerta es, por definición, donde hay que mirar
}

_risk_weights: Dict[str, int] = dict(DEFAULT_RISK_WEIGHTS)


def risk_weights() -> Dict[str, int]:
    return dict(_risk_weights)


def set_risk_weights(values: Optional[Dict[str, Any]]) -> Dict[str, int]:
    """Sustituye los pesos, ignorando claves desconocidas y valores no enteros.

    Lo llama el panel de administrador. Se filtra a conciencia porque estos
    números salen de un formulario web y acaban en una fórmula que ordena la
    atención del analista.
    """
    if values:
        for key, value in values.items():
            if key in DEFAULT_RISK_WEIGHTS:
                try:
                    _risk_weights[key] = max(0, int(value))
                except (TypeError, ValueError):
                    continue
    return risk_weights()


def reset_risk_weights() -> Dict[str, int]:
    _risk_weights.clear()
    _risk_weights.update(DEFAULT_RISK_WEIGHTS)
    return risk_weights()


def score(max_severity: int, tactics: int, degree: int, events: int,
          rel_weight: int, is_alert: bool) -> int:
    """Puntuación 0-100 para ordenar la atención. No es un veredicto.

    El volumen pesa poco a propósito: que una máquina sea habladora no la hace
    peligrosa. Un servidor con 50.000 eventos informativos no debe tapar a la
    workstation con una alerta crítica.
    """
    w = _risk_weights
    total = (
        max_severity * w["severity"]
        + min(tactics * w["tactic"], w["tacticCap"])
        + min(degree * w["degree"], w["degreeCap"])
        + min(events // max(w["volumeDivisor"], 1), w["volumeCap"])
        + min(rel_weight // max(w["weightDivisor"], 1), w["weightCap"])
        + (w["alertBonus"] if is_alert else 0)
    )
    return max(0, min(100, total))


def enrich(graph: GraphDoc) -> GraphDoc:
    """Pasada completa: roles y clusters. La llama ``query.build_filtered``."""
    assign_roles(graph)
    assign_clusters(graph)
    return graph


def role_of(node: Node) -> str:
    return str(node.props.get("role") or ROLE_NEUTRAL)


def nodes_by_role(graph: GraphDoc, role: str) -> List[Node]:
    return [node for node in graph.nodes if role_of(node) == role]
