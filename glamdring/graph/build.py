"""Agregacion: lista de eventos -> ``GraphDoc``.

Miles de eventos colapsan en decenas de nodos y aristas. La agregacion es lo que
hace legible el resultado: 400 logons del mismo usuario contra el mismo servidor
son UNA arista con ``count=400``, no 400 lineas.

Cada arista conserva los ``eventUids`` que la produjeron, de modo que al
pincharla se puede volver a los logs crudos. Esa lista se recorta a
``MAX_UIDS_PER_LINK`` para que el JSON no explote; el recuento real sigue en
``count``.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..models import GraphDoc, GraphMeta, GraphWindow, Link, NormalizedEvent, Node
from . import enrich, ontology
from .extract import extract

MAX_UIDS_PER_LINK = 200
MAX_UIDS_PER_NODE = 200


class _NodeAgg:
    __slots__ = ("id", "type", "label", "first_seen", "last_seen", "event_count",
                 "max_severity", "sources", "tactics", "props", "event_uids", "rel_weight")

    def __init__(self, node_id: str, node_type: str, label: str) -> None:
        self.id = node_id
        self.type = node_type
        self.label = label
        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None
        self.event_count = 0
        self.max_severity = 0
        self.sources: set = set()
        self.tactics: set = set()
        self.props: Dict[str, Any] = {}
        self.event_uids: List[str] = []
        self.rel_weight = 0


class _LinkAgg:
    __slots__ = ("key", "source", "target", "type", "count", "severity",
                 "first_seen", "last_seen", "event_uids", "sources", "props")

    def __init__(self, key: Tuple[str, str, str]) -> None:
        self.key = key
        self.source, self.target, self.type = key
        self.count = 0
        self.severity = 0
        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None
        self.event_uids: List[str] = []
        self.sources: set = set()
        self.props: Dict[str, Any] = {}


def _touch(agg: Any, moment: datetime) -> None:
    if agg.first_seen is None or moment < agg.first_seen:
        agg.first_seen = moment
    if agg.last_seen is None or moment > agg.last_seen:
        agg.last_seen = moment


def build_graph(events: Iterable[NormalizedEvent],
                window: Optional[GraphWindow] = None,
                notes: Optional[List[str]] = None) -> GraphDoc:
    """Construye el documento de grafo a partir de eventos ya normalizados."""
    nodes: Dict[str, _NodeAgg] = {}
    links: Dict[Tuple[str, str, str], _LinkAgg] = {}
    event_total = 0
    sources_seen: set = set()
    earliest: Optional[datetime] = None
    latest: Optional[datetime] = None

    for event in events:
        event_total += 1
        sources_seen.add(event.source)
        moment = event.time
        if earliest is None or moment < earliest:
            earliest = moment
        if latest is None or moment > latest:
            latest = moment

        entities, relations = extract(event)

        for spec in entities:
            agg = nodes.get(spec.key)
            if agg is None:
                agg = _NodeAgg(spec.key, spec.type, spec.label)
                nodes[spec.key] = agg
            _touch(agg, moment)
            agg.event_count += 1
            agg.max_severity = max(agg.max_severity, event.severity)
            agg.sources.add(event.source)
            agg.tactics.update(event.tactics)
            if len(agg.event_uids) < MAX_UIDS_PER_NODE:
                agg.event_uids.append(event.uid)
            for key, value in spec.props.items():
                # La primera aparicion manda: evita que un evento tardio con el
                # campo vacio borre lo que ya sabiamos de la entidad.
                if key not in agg.props and value not in (None, ""):
                    agg.props[key] = value
            # Una etiqueta mas larga suele ser la mas informativa
            # ('CORP\\jlopez' frente a 'jlopez').
            if len(spec.label) > len(agg.label):
                agg.label = spec.label

        for rel in relations:
            if rel.source not in nodes or rel.target not in nodes:
                continue
            key = (rel.source, rel.target, rel.type)
            link = links.get(key)
            if link is None:
                link = _LinkAgg(key)
                links[key] = link
            _touch(link, moment)
            link.count += 1
            link.severity = max(link.severity, event.severity)
            link.sources.add(event.source)
            if len(link.event_uids) < MAX_UIDS_PER_LINK:
                link.event_uids.append(event.uid)
            for prop_key, value in rel.props.items():
                link.props.setdefault(prop_key, value)

            weight = ontology.relation(rel.type).get("weight", 1)
            nodes[rel.source].rel_weight += weight
            nodes[rel.target].rel_weight += weight

    links = _merge_ip_into_hosts(nodes, links)
    links = _merge_files_by_hash(nodes, links)
    links = _merge_processes_by_name(nodes, links)

    degrees: Dict[str, int] = defaultdict(int)
    for source, target, _type in links:
        degrees[source] += 1
        degrees[target] += 1

    out_nodes = [
        Node(
            id=agg.id,
            type=agg.type,
            label=agg.label,
            firstSeen=agg.first_seen,
            lastSeen=agg.last_seen,
            eventCount=agg.event_count,
            maxSeverity=agg.max_severity,
            risk=_risk(agg, degrees.get(agg.id, 0)),
            degree=degrees.get(agg.id, 0),
            sources=sorted(agg.sources),
            tactics=sorted(agg.tactics, key=ontology.tactic_rank),
            props=dict(agg.props, eventUids=agg.event_uids),
        )
        for agg in nodes.values()
    ]

    out_links = [
        Link(
            id=f"l{index}",
            source=link.source,
            target=link.target,
            type=link.type,
            count=link.count,
            severity=link.severity,
            firstSeen=link.first_seen,
            lastSeen=link.last_seen,
            eventUids=link.event_uids,
            sources=sorted(link.sources),
            props=link.props,
        )
        for index, link in enumerate(links.values())
    ]

    # Los nodos mas peligrosos primero: el frontend los dibuja y etiqueta antes.
    out_nodes.sort(key=lambda n: (-n.risk, n.type, n.label))

    meta = GraphMeta(
        window=window or GraphWindow(**{"from": earliest, "to": latest}),
        counts={"events": event_total, "nodes": len(out_nodes), "links": len(out_links)},
        sources=sorted(sources_seen),
        notes=notes or [],
    )
    return GraphDoc(meta=meta, nodes=out_nodes, links=out_links)


def _merge_processes_by_name(
    nodes: Dict[str, _NodeAgg],
    links: Dict[Tuple[str, str, str], _LinkAgg],
) -> Dict[Tuple[str, str, str], _LinkAgg]:
    """Funde el proceso conocido solo por nombre en el que si tiene ruta.

    Sysmon da ``C:\\Windows\\explorer.exe``; Defender, en el campo del proceso
    iniciador, da solo ``explorer.exe``. Es el mismo proceso en la misma maquina
    y verlo dos veces en el grafo hace dudar de todo lo demas.

    La union solo se hace **dentro del mismo host** y cuando hay exactamente una
    ruta candidata: si en la maquina conviven ``C:\\Windows\\svchost.exe`` y
    ``C:\\Users\\x\\svchost.exe``, no sabemos a cual referirse y precisamente esa
    ambiguedad es un hallazgo, no algo que convenga tapar.
    """
    grouped: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for node_id, agg in nodes.items():
        if agg.type != "process" or "|" not in node_id:
            continue
        host_part, _, path = node_id.partition("|")
        basename = path.rsplit("\\", 1)[-1]
        grouped[(host_part, basename)].append(node_id)

    alias: Dict[str, str] = {}
    for (_host, basename), node_ids in grouped.items():
        if len(node_ids) < 2:
            continue
        with_path = [nid for nid in node_ids if nid.rsplit("|", 1)[-1] != basename]
        if len(with_path) != 1:
            continue
        winner = with_path[0]
        for node_id in node_ids:
            if node_id != winner:
                alias[node_id] = winner

    if not alias:
        return links
    return _apply_alias(nodes, links, alias)


def _merge_files_by_hash(
    nodes: Dict[str, _NodeAgg],
    links: Dict[Tuple[str, str, str], _LinkAgg],
) -> Dict[Tuple[str, str, str], _LinkAgg]:
    """Funde el fichero sin ruta en el fichero con ruta que comparte hash.

    Una alerta de Sentinel nombra el fichero como ``m.exe`` a secas, mientras que
    Sysmon lo da con su ruta completa. Sin esta pasada el mismo binario sale dos
    veces, y el analista no sabe si son dos copias o un duplicado.

    El hash es la unica identidad fiable de un fichero, asi que la union se hace
    a traves de la arista ``has_hash`` que ambos comparten: si dos nodos fichero
    cuelgan del mismo hash y uno de ellos tiene ruta, el otro es el mismo.
    """
    files_by_hash: Dict[str, List[str]] = defaultdict(list)
    for (source_id, target_id, rel_type) in links:
        if rel_type != "has_hash":
            continue
        if nodes.get(source_id) and nodes[source_id].type == "file" and target_id.startswith("hash:"):
            files_by_hash[target_id].append(source_id)

    alias: Dict[str, str] = {}
    for file_ids in files_by_hash.values():
        if len(file_ids) < 2:
            continue
        # Gana el que tiene ruta (la clave lleva separador de directorio); si
        # hay varios con ruta no se toca nada: son copias reales en sitios
        # distintos y fundirlas ocultaria informacion.
        with_path = [fid for fid in file_ids if "\\" in fid or "/" in fid]
        if len(with_path) != 1:
            continue
        winner = with_path[0]
        for fid in file_ids:
            if fid != winner:
                alias[fid] = winner

    if not alias:
        return links
    return _apply_alias(nodes, links, alias)


def _merge_ip_into_hosts(
    nodes: Dict[str, _NodeAgg],
    links: Dict[Tuple[str, str, str], _LinkAgg],
) -> Dict[Tuple[str, str, str], _LinkAgg]:
    """Funde cada nodo ``ip:X`` en el ``host`` que ha declarado esa IP.

    Sin esta pasada, SRV-DC01 (al que Splunk y Sentinel nombran por hostname) y
    10.4.1.5 (que QRadar y el firewall solo conocen por IP) serian dos nodos
    distintos, y el grafo diria que el trafico sale de una maquina que no existe.

    Solo se funden las IP reclamadas por UN unico host: si dos maquinas dicen
    tener la misma IP (DHCP a lo largo del tiempo, NAT, un inventario sucio),
    unirlas seria inventarse un hecho, asi que se dejan separadas.
    """
    claims: Dict[str, set] = defaultdict(set)
    for agg in nodes.values():
        if agg.type != "host":
            continue
        ip = agg.props.get("ip")
        if ip:
            claims[f"ip:{ip}"].add(agg.id)

    alias = {
        ip_key: next(iter(owners))
        for ip_key, owners in claims.items()
        if len(owners) == 1 and ip_key in nodes
    }
    if not alias:
        return links
    return _apply_alias(nodes, links, alias)


def _apply_alias(
    nodes: Dict[str, _NodeAgg],
    links: Dict[Tuple[str, str, str], _LinkAgg],
    alias: Dict[str, str],
) -> Dict[Tuple[str, str, str], _LinkAgg]:
    """Aplica un mapa ``nodo viejo -> nodo bueno``: funde nodos y recablea aristas.

    Lo comparten las dos pasadas de fusion (IP en host, fichero por hash) porque
    el trabajo sucio es identico: sumar contadores sin perder trazabilidad y
    evitar que queden aristas apuntando a nodos que ya no existen.
    """
    for old_key, new_key in alias.items():
        source = nodes.pop(old_key, None)
        target = nodes.get(new_key)
        if source is None or target is None:
            continue
        target.event_count += source.event_count
        target.max_severity = max(target.max_severity, source.max_severity)
        target.rel_weight += source.rel_weight
        target.sources |= source.sources
        target.tactics |= source.tactics
        if source.first_seen and (target.first_seen is None or source.first_seen < target.first_seen):
            target.first_seen = source.first_seen
        if source.last_seen and (target.last_seen is None or source.last_seen > target.last_seen):
            target.last_seen = source.last_seen
        for key, value in source.props.items():
            target.props.setdefault(key, value)
        for uid in source.event_uids:
            if len(target.event_uids) >= MAX_UIDS_PER_NODE:
                break
            if uid not in target.event_uids:
                target.event_uids.append(uid)

    merged: Dict[Tuple[str, str, str], _LinkAgg] = {}
    for (source_id, target_id, rel_type), link in links.items():
        new_source = alias.get(source_id, source_id)
        new_target = alias.get(target_id, target_id)
        if new_source == new_target:
            continue  # la arista unia el nodo con su propio alias: ya no dice nada
        if new_source not in nodes or new_target not in nodes:
            continue
        key = (new_source, new_target, rel_type)
        existing = merged.get(key)
        if existing is None:
            link.source, link.target, link.key = new_source, new_target, key
            merged[key] = link
            continue
        existing.count += link.count
        existing.severity = max(existing.severity, link.severity)
        existing.sources |= link.sources
        if link.first_seen and (existing.first_seen is None or link.first_seen < existing.first_seen):
            existing.first_seen = link.first_seen
        if link.last_seen and (existing.last_seen is None or link.last_seen > existing.last_seen):
            existing.last_seen = link.last_seen
        for uid in link.event_uids:
            if len(existing.event_uids) >= MAX_UIDS_PER_LINK:
                break
            if uid not in existing.event_uids:
                existing.event_uids.append(uid)
        for prop_key, value in link.props.items():
            existing.props.setdefault(prop_key, value)
    return merged


def _risk(agg: _NodeAgg, degree: int) -> int:
    """Delega en ``enrich.score``, donde viven los pesos configurables.

    La formula esta alli y no aqui porque el panel de administrador puede
    cambiarla en caliente, y tener dos copias de los pesos acabaria con el grafo
    y el informe puntuando distinto.
    """
    return enrich.score(
        max_severity=agg.max_severity,
        tactics=len(agg.tactics),
        degree=degree,
        events=agg.event_count,
        rel_weight=agg.rel_weight,
        is_alert=agg.type == "alert",
    )


def merge_events(existing: List[NormalizedEvent],
                 incoming: Iterable[NormalizedEvent]) -> Tuple[List[NormalizedEvent], int]:
    """Anade eventos evitando duplicados por ``uid``.

    Devuelve (lista combinada, numero de nuevos). Importa cuando el mismo
    incidente se ingesta desde dos SIEM que reenvian la misma telemetria.
    """
    seen = {event.uid for event in existing}
    added = 0
    combined = list(existing)
    for event in incoming:
        if event.uid in seen:
            continue
        seen.add(event.uid)
        combined.append(event)
        added += 1
    combined.sort(key=lambda e: e.time)
    return combined, added
