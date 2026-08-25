"""Filtrado, recorte y calculo de capas.

Los filtros se aplican en dos momentos distintos y no es lo mismo:

* **Sobre eventos** (tiempo, severidad, fuente, texto, tactica): cambian lo que
  se agrega, asi que el grafo se reconstruye. Filtrar por tiempo y quedarse con
  aristas cuyo ``count`` sigue siendo el total seria mentir.
* **Sobre el grafo ya construido** (tipos de entidad, tipos de relacion, foco a
  N saltos, tope de nodos): son podas topologicas y no alteran los recuentos.
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ..models import (
    GraphDoc,
    GraphWindow,
    NormalizedEvent,
    Timeline,
    TimelineBucket,
)
from . import ontology
from .build import build_graph
from .enrich import enrich


# ---------------------------------------------------------------------------
# Filtros sobre eventos
# ---------------------------------------------------------------------------


def filter_events(
    events: Iterable[NormalizedEvent],
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    min_severity: int = 0,
    sources: Optional[Sequence[str]] = None,
    tactics: Optional[Sequence[str]] = None,
    classes: Optional[Sequence[str]] = None,
    text: Optional[str] = None,
) -> List[NormalizedEvent]:
    source_set = {s.lower() for s in sources} if sources else None
    tactic_set = {t.lower() for t in tactics} if tactics else None
    class_set = {c.lower() for c in classes} if classes else None
    needle = text.strip().lower() if text else None

    out: List[NormalizedEvent] = []
    for event in events:
        if time_from and event.time < time_from:
            continue
        if time_to and event.time > time_to:
            continue
        if event.severity < min_severity:
            continue
        if source_set and event.source.lower() not in source_set:
            continue
        if class_set and event.class_name.lower() not in class_set:
            continue
        if tactic_set and not (tactic_set & {t.lower() for t in event.tactics}):
            continue
        if needle and not _matches_text(event, needle):
            continue
        out.append(event)
    return out


def _matches_text(event: NormalizedEvent, needle: str) -> bool:
    """Busqueda libre: primero los campos baratos, el raw solo si hace falta."""
    if needle in event.message.lower():
        return True
    if event.actor and event.actor.user and needle in event.actor.user.lower():
        return True
    for ref in (event.src, event.dst, event.device):
        if ref is None:
            continue
        if ref.hostname and needle in ref.hostname.lower():
            return True
        if ref.ip and needle in ref.ip.lower():
            return True
    if event.process:
        for value in (event.process.name, event.process.path, event.process.cmdline):
            if value and needle in value.lower():
                return True
    if event.file:
        for value in (event.file.name, event.file.path, event.file.sha256):
            if value and needle in value.lower():
                return True
    if event.domain and needle in event.domain.lower():
        return True
    if any(needle in t.id.lower() for t in event.mitre):
        return True
    # Ultimo recurso, el mas caro: serializar el registro original.
    return needle in str(event.raw).lower()


# ---------------------------------------------------------------------------
# Podas sobre el grafo construido
# ---------------------------------------------------------------------------


def prune(
    graph: GraphDoc,
    entity_types: Optional[Sequence[str]] = None,
    relation_types: Optional[Sequence[str]] = None,
    focus: Optional[str] = None,
    hops: int = 1,
    max_nodes: int = 0,
    drop_isolated: bool = True,
) -> GraphDoc:
    """Recorta el grafo sin recalcular agregados."""
    nodes = list(graph.nodes)
    links = list(graph.links)
    truncated = graph.meta.truncated
    notes = list(graph.meta.notes)

    if entity_types:
        allowed = {t.lower() for t in entity_types}
        nodes = [n for n in nodes if n.type.lower() in allowed]

    if relation_types:
        allowed_rel = {t.lower() for t in relation_types}
        links = [l for l in links if l.type.lower() in allowed_rel]

    node_ids = {n.id for n in nodes}
    links = [l for l in links if l.source in node_ids and l.target in node_ids]

    if focus:
        keep = neighborhood(node_ids, links, focus, hops)
        nodes = [n for n in nodes if n.id in keep]
        node_ids = keep
        links = [l for l in links if l.source in node_ids and l.target in node_ids]

    if max_nodes and len(nodes) > max_nodes:
        # Se conservan los de mayor riesgo: son los que el analista necesita ver.
        nodes = sorted(nodes, key=lambda n: -n.risk)[:max_nodes]
        node_ids = {n.id for n in nodes}
        links = [l for l in links if l.source in node_ids and l.target in node_ids]
        truncated = True
        notes.append(f"Grafo recortado a los {max_nodes} nodos de mayor riesgo.")

    if drop_isolated and links:
        connected = {l.source for l in links} | {l.target for l in links}
        # Un nodo aislado con riesgo alto se queda: puede ser la alerta suelta
        # que todavia no ha correlado con nada, y esconderla seria un error.
        nodes = [n for n in nodes if n.id in connected or n.risk >= 60]

    # Se devuelve un GraphDoc NUEVO en vez de modificar el que llega.
    #
    # No es un capricho de estilo. Antes esto hacia `graph.nodes = nodes` sobre
    # el objeto recibido, y con la cache del grafo construido eso era veneno:
    # una consulta con `focus` dejaba el grafo CACHEADO recortado a esa
    # vecindad, y la siguiente consulta completa devolvia el subconjunto de la
    # anterior. Silenciosamente, y solo a partir de la segunda llamada.
    #
    # Los nodos y aristas se comparten (no se copian): quien necesite escribir
    # en sus props hace su propia copia, que es lo que hace build_filtered antes
    # de enriquecer.
    meta = graph.meta.model_copy(deep=True)
    meta.truncated = truncated
    meta.notes = notes
    meta.counts = dict(meta.counts)
    meta.counts["nodes"] = len(nodes)
    meta.counts["links"] = len(links)
    return GraphDoc(nodes=nodes, links=links, meta=meta)


def neighborhood(node_ids: Set[str], links: Sequence, start: str, hops: int) -> Set[str]:
    """BFS no dirigido de ``hops`` saltos desde ``start``."""
    if start not in node_ids:
        return set()
    adjacency: Dict[str, List[str]] = defaultdict(list)
    for link in links:
        adjacency[link.source].append(link.target)
        adjacency[link.target].append(link.source)

    seen = {start}
    frontier = deque([(start, 0)])
    while frontier:
        current, depth = frontier.popleft()
        if depth >= hops:
            continue
        for neighbor in adjacency.get(current, ()):
            if neighbor not in seen:
                seen.add(neighbor)
                frontier.append((neighbor, depth + 1))
    return seen


# ---------------------------------------------------------------------------
# Capas de la kill-chain
# ---------------------------------------------------------------------------


def assign_levels(graph: GraphDoc) -> GraphDoc:
    """Asigna a cada nodo su capa en la narrativa del ataque (``props.level``).

    El criterio principal es la tactica MITRE, porque es lo que cuenta la
    historia. Los nodos sin tactica (la mayoria: una IP no tiene tactica) heredan
    la capa minima de sus vecinos que si la tienen, propagando por BFS. Lo que
    sigue sin capa cae al orden natural de la entidad en la ontologia.

    Se usa esto en vez de ``dagMode`` de la libreria porque un grafo de incidente
    real casi nunca es aciclico y dagMode necesita que lo sea.
    """
    levels: Dict[str, int] = {}
    for node in graph.nodes:
        if node.tactics:
            levels[node.id] = min(ontology.tactic_rank(t) for t in node.tactics)

    adjacency: Dict[str, List[str]] = defaultdict(list)
    for link in graph.links:
        adjacency[link.source].append(link.target)
        adjacency[link.target].append(link.source)

    # Propagacion: cada ronda asigna a los vecinos sin capa la minima conocida.
    frontier = deque(levels.keys())
    while frontier:
        current = frontier.popleft()
        for neighbor in adjacency.get(current, ()):
            if neighbor not in levels:
                levels[neighbor] = levels[current]
                frontier.append(neighbor)

    for node in graph.nodes:
        if node.id not in levels:
            levels[node.id] = ontology.entity(node.type).get("rank", 9)

    # Compactar a enteros consecutivos: si el incidente solo toca acceso inicial
    # y C2, no queremos diez columnas vacias en medio.
    ordered = sorted(set(levels.values()))
    compact = {value: index for index, value in enumerate(ordered)}
    for node in graph.nodes:
        node.props["level"] = compact[levels[node.id]]
    graph.meta.counts["levels"] = len(ordered)
    return graph


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


def timeline(events: Sequence[NormalizedEvent], buckets: int = 120) -> Timeline:
    """Histograma de eventos para el slider y el replay."""
    if not events:
        return Timeline(bucketSeconds=60, buckets=[])

    times = [event.time for event in events]
    start, end = min(times), max(times)
    span = max((end - start).total_seconds(), 1.0)
    bucket_seconds = max(int(span / max(buckets, 1)), 1)

    counters: Dict[int, Tuple[int, int]] = {}
    for event in events:
        index = int((event.time - start).total_seconds() // bucket_seconds)
        count, severity = counters.get(index, (0, 0))
        counters[index] = (count + 1, max(severity, event.severity))

    out = [
        TimelineBucket(
            t=start + timedelta(seconds=index * bucket_seconds),
            count=count,
            maxSeverity=severity,
        )
        for index, (count, severity) in sorted(counters.items())
    ]
    return Timeline(bucketSeconds=bucket_seconds, buckets=out)


def parse_window(time_from: Optional[str], time_to: Optional[str]) -> GraphWindow:
    """Convierte los parametros de la query en una ventana temporal.

    Acepta ISO-8601 y atajos relativos ('-24h', '-7d', '-30m'), que es como
    piensa el analista, no en marcas de tiempo absolutas.
    """
    return GraphWindow(**{"from": _parse_moment(time_from), "to": _parse_moment(time_to)})


def _parse_moment(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    if text.startswith("-") and len(text) > 2:
        unit = text[-1].lower()
        try:
            amount = int(text[1:-1])
        except ValueError:
            return None
        factors = {"m": 60, "h": 3600, "d": 86400, "w": 604800}
        if unit in factors:
            return datetime.now(timezone.utc) - timedelta(seconds=amount * factors[unit])
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# Nombre publico: la API tambien necesita convertir '-24h' en un datetime.
parse_moment = _parse_moment


# ---------------------------------------------------------------------------
# Cache del grafo construido
#
# EL PROBLEMA: build_graph() recorre todos los eventos y extrae nodos y aristas.
# Con 12.600 eventos son 6,3 segundos, y se ejecutaba ENTERO en cada peticion.
# Cada vez que el analista movia un filtro, cambiaba de vista o recargaba, se
# reconstruia el grafo desde cero. Medido contra el servidor: 9,5 y 11,5
# segundos por llamada, y la segunda costaba lo mismo que la primera.
#
# Eso no se arregla con mas CPU. Es Python de un solo hilo: una maquina el doble
# de rapida seguiria tardando casi tres segundos por clic.
#
# LA OBSERVACION: build_graph solo depende de los filtros DE EVENTO (ventana,
# severidad, fuente, tactica, clase, texto). Los otros —tipos de entidad, tipos
# de relacion, foco, saltos, tope de nodos— actuan sobre el grafo ya construido
# y son baratos. Y en la interfaz, los que mas se tocan son justo esos.
#
# POR QUE HAY QUE COPIAR: enrich() escribe en node.props. Servir el objeto
# cacheado tal cual dejaria el rol de una consulta pegado a la siguiente.
#
# Y por que la copia es ligera: se poda ANTES de copiar (de 4.864 nodos a 1.500)
# y se copia solo lo superficial con un `props` nuevo, que es lo unico que
# enrich toca. Una copia profunda del grafo entero costaba 3,9 s, casi tanto
# como reconstruirlo; asi cuesta centesimas.
#
# Medido con 12.600 eventos: 10,5 s reconstruyendo -> 0,16 s desde cache.
# ---------------------------------------------------------------------------

_CACHE: "OrderedDict[tuple, GraphDoc]" = OrderedDict()
# Pocas entradas a proposito: cada grafo grande ocupa decenas de MB y las
# combinaciones de filtro que se repiten de verdad son un puñado.
_CACHE_MAX = 6


def cache_clear() -> None:
    """Vacia la cache. Para los tests y para cuando cambia algo transversal."""
    _CACHE.clear()


def cache_info() -> Dict[str, Any]:
    return {"entries": len(_CACHE), "max": _CACHE_MAX}


def _event_key(
    version: int,
    time_from: Optional[datetime],
    time_to: Optional[datetime],
    min_severity: int,
    sources: Optional[Sequence[str]],
    tactics: Optional[Sequence[str]],
    classes: Optional[Sequence[str]],
    text: Optional[str],
) -> tuple:
    return (
        version,
        time_from.isoformat() if time_from else None,
        time_to.isoformat() if time_to else None,
        min_severity,
        tuple(sorted(sources or ())),
        tuple(sorted(tactics or ())),
        tuple(sorted(classes or ())),
        (text or "").strip().lower(),
    )


def _light_copy(graph: GraphDoc) -> GraphDoc:
    """Copia lo justo para que enrich() no ensucie lo cacheado.

    Nodos y aristas se copian en superficial con un ``props`` propio; el resto
    de campos son inmutables o no se tocan aguas abajo.
    """
    return GraphDoc(
        nodes=[node.model_copy(update={"props": dict(node.props)}) for node in graph.nodes],
        links=[link.model_copy(update={"props": dict(link.props)}) for link in graph.links],
        meta=graph.meta.model_copy(deep=True),
    )


def build_filtered(
    events: Sequence[NormalizedEvent],
    *,
    version: Optional[int] = None,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    min_severity: int = 0,
    sources: Optional[Sequence[str]] = None,
    tactics: Optional[Sequence[str]] = None,
    classes: Optional[Sequence[str]] = None,
    text: Optional[str] = None,
    entity_types: Optional[Sequence[str]] = None,
    relation_types: Optional[Sequence[str]] = None,
    focus: Optional[str] = None,
    hops: int = 1,
    max_nodes: int = 0,
) -> GraphDoc:
    """Atajo: filtra, agrega, poda, enriquece y asigna capas. Lo que usa la API.

    El enriquecido va DESPUES de la poda a proposito: el rol de un nodo depende
    de sus vecinos, y calcularlo sobre el grafo completo para luego recortar
    dejaria nodos etiquetados como victimas por una alerta que ya no se ve.
    """
    key = None
    graph = None
    if version is not None:
        key = _event_key(version, time_from, time_to, min_severity,
                         sources, tactics, classes, text)
        cached = _CACHE.get(key)
        if cached is not None:
            _CACHE.move_to_end(key)
            graph = cached

    if graph is None:
        selected = filter_events(
            events,
            time_from=time_from,
            time_to=time_to,
            min_severity=min_severity,
            sources=sources,
            tactics=tactics,
            classes=classes,
            text=text,
        )
        graph = build_graph(selected, window=GraphWindow(**{"from": time_from, "to": time_to}))
        if key is not None:
            _CACHE[key] = graph
            while len(_CACHE) > _CACHE_MAX:
                _CACHE.popitem(last=False)

    # Podar primero y copiar despues: la poda reduce el grafo antes de pagar la
    # copia, y la copia protege lo cacheado de lo que escribe enrich().
    graph = prune(
        graph,
        entity_types=entity_types,
        relation_types=relation_types,
        focus=focus,
        hops=hops,
        max_nodes=max_nodes,
    )
    if key is not None:
        graph = _light_copy(graph)
    graph = enrich(graph)
    return assign_levels(graph)
