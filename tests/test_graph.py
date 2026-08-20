"""Extraccion, agregacion, dedupe y filtrado del grafo."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from glamdring.graph.build import build_graph
from glamdring.graph.extract import extract
from glamdring.graph.query import (
    assign_levels,
    build_filtered,
    filter_events,
    neighborhood,
    parse_moment,
    prune,
    timeline,
)
from glamdring.models import ActorRef, HostRef, NormalizedEvent, ProcRef


def _ids(graph):
    return {node.id for node in graph.nodes}


def _links_of(graph, rel_type):
    return [link for link in graph.links if link.type == rel_type]


# ------------------------------------------------------------------ extraccion


def test_extract_logon_creates_user_and_host():
    event = NormalizedEvent(
        uid="x1",
        time=datetime(2026, 8, 19, 9, 40, tzinfo=timezone.utc),
        class_name="Authentication",
        activity="logon_remote",
        status="success",
        actor=ActorRef(user="CORP\\jlopez"),
        device=HostRef(hostname="SRV-DC01.corp.local"),
        src=HostRef(hostname="WKS-0421", ip="10.4.2.11"),
    )
    entities, relations = extract(event)
    keys = {e.key for e in entities}
    assert "user:jlopez" in keys
    assert "host:srv-dc01" in keys
    assert "host:wks-0421" in keys

    types = {r.type for r in relations}
    assert "authenticated" in types
    # Logon remoto correcto entre dos hosts = movimiento lateral.
    assert "lateral" in types


def test_process_is_anchored_to_its_host():
    """powershell.exe en dos maquinas tienen que ser dos nodos distintos."""
    def make(host):
        return NormalizedEvent(
            uid="u" + host,
            time=datetime(2026, 8, 19, 9, 15, tzinfo=timezone.utc),
            class_name="Process Activity",
            activity="launch",
            device=HostRef(hostname=host),
            process=ProcRef(name="powershell.exe",
                            path="C:\\Windows\\System32\\powershell.exe"),
        )

    keys_a = {e.key for e in extract(make("WKS-0421"))[0] if e.type == "process"}
    keys_b = {e.key for e in extract(make("SRV-DC01"))[0] if e.type == "process"}
    assert keys_a and keys_b
    assert keys_a != keys_b


def test_machine_accounts_are_not_nodes():
    event = NormalizedEvent(
        uid="x2",
        time=datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc),
        class_name="Authentication",
        activity="logon",
        actor=ActorRef(user="WKS-0421$"),
        device=HostRef(hostname="SRV-DC01"),
    )
    entities, _ = extract(event)
    assert not [e for e in entities if e.type == "user"]


def test_endpoint_with_hostname_and_ip_is_one_node():
    """La IP se guarda como propiedad del host, no como nodo aparte."""
    event = NormalizedEvent(
        uid="x3",
        time=datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc),
        class_name="Authentication",
        activity="logon",
        actor=ActorRef(user="jlopez"),
        src=HostRef(hostname="WKS-0421", ip="10.4.2.11"),
        device=HostRef(hostname="SRV-DC01"),
    )
    entities, _ = extract(event)
    assert not [e for e in entities if e.type == "ip"]
    host = [e for e in entities if e.key == "host:wks-0421"][0]
    assert host.props.get("ip") == "10.4.2.11"


# ------------------------------------------------------------------ agregacion


def test_build_graph_from_samples(all_events):
    graph = build_graph(all_events)
    assert graph.nodes and graph.links
    assert graph.meta.counts["events"] == len(all_events)
    assert set(graph.meta.sources) == {"splunk", "sentinel", "qradar", "generic"}


def test_user_is_deduplicated_across_siems(all_events):
    """La prueba de fuego: 'CORP\\jlopez', 'jlopez@corp.com' y 'jlopez' son uno."""
    graph = build_graph(all_events)
    users = [node for node in graph.nodes if node.type == "user"]
    jlopez = [node for node in users if node.id == "user:jlopez"]
    assert len(jlopez) == 1

    node = jlopez[0]
    # Y ese unico nodo tiene que acreditar que lo vieron los tres SIEM.
    assert {"splunk", "sentinel", "qradar"} <= set(node.sources)
    assert node.event_count > 10


def test_hosts_are_deduplicated_across_siems(all_events):
    graph = build_graph(all_events)
    ids = _ids(graph)
    # Splunk dice 'WKS-0421.corp.local', Sentinel 'wks-0421.corp.local'.
    assert "host:wks-0421" in ids
    assert "host:srv-dc01" in ids
    assert "host:wks-0421.corp.local" not in ids


def test_links_aggregate_counts(all_events):
    graph = build_graph(all_events)
    failures = _links_of(graph, "failed_auth")
    assert failures
    # Varios 4625 contra la misma cuenta colapsan en una arista con count>1.
    assert max(link.count for link in failures) > 1
    assert all(link.event_uids for link in failures)


def test_lateral_movement_edge_exists(all_events):
    graph = build_graph(all_events)
    lateral = _links_of(graph, "lateral")
    assert lateral, "el 4624 tipo 3 entre WKS-0421 y SRV-DC01 debe generar 'lateral'"
    pairs = {(link.source, link.target) for link in lateral}
    assert ("host:wks-0421", "host:srv-dc01") in pairs


def test_alerts_connect_to_their_entities(all_events):
    graph = build_graph(all_events)
    alerts = [node for node in graph.nodes if node.type == "alert"]
    assert alerts
    affects = _links_of(graph, "affects")
    assert affects
    alert_ids = {node.id for node in alerts}
    assert all(link.source in alert_ids for link in affects)


def test_risk_prioritises_severity_over_volume():
    now = datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc)

    chatty = [
        NormalizedEvent(uid=f"c{i}", time=now + timedelta(seconds=i),
                        class_name="Authentication", activity="logon", severity=1,
                        actor=ActorRef(user="ruidoso"), device=HostRef(hostname="SRV-LOG"))
        for i in range(300)
    ]
    critical = [
        NormalizedEvent(uid="k1", time=now, class_name="Authentication",
                        activity="logon", severity=5,
                        actor=ActorRef(user="victima"), device=HostRef(hostname="WKS-9"))
    ]
    graph = build_graph(chatty + critical)
    by_id = {node.id: node for node in graph.nodes}
    assert by_id["user:victima"].risk > by_id["user:ruidoso"].risk


# --------------------------------------------------------------------- filtros


def test_filter_by_severity(all_events):
    high = filter_events(all_events, min_severity=4)
    assert high
    assert len(high) < len(all_events)
    assert all(event.severity >= 4 for event in high)


def test_filter_by_time_window(all_events):
    start = datetime(2026, 8, 19, 9, 30, tzinfo=timezone.utc)
    selected = filter_events(all_events, time_from=start)
    assert selected
    assert all(event.time >= start for event in selected)


def test_filter_by_text_searches_everywhere(all_events):
    assert filter_events(all_events, text="certutil")
    assert filter_events(all_events, text="45.132.88.17")
    assert filter_events(all_events, text="T1003")
    assert not filter_events(all_events, text="cadena-que-no-existe-en-ningun-log")


def test_prune_by_entity_type(all_events):
    graph = build_graph(all_events)
    pruned = prune(build_graph(all_events), entity_types=["user", "host"])
    assert {node.type for node in pruned.nodes} <= {"user", "host"}
    assert len(pruned.nodes) < len(graph.nodes)
    # No pueden quedar aristas apuntando a nodos eliminados.
    ids = _ids(pruned)
    assert all(link.source in ids and link.target in ids for link in pruned.links)


def test_focus_limits_to_neighborhood(all_events):
    full = build_graph(all_events)
    assert "host:wks-0421" in _ids(full)

    one_hop = prune(build_graph(all_events), focus="host:wks-0421", hops=1)
    two_hops = prune(build_graph(all_events), focus="host:wks-0421", hops=2)

    assert "host:wks-0421" in _ids(one_hop)
    assert len(one_hop.nodes) < len(full.nodes)
    assert len(two_hops.nodes) >= len(one_hop.nodes)


def test_neighborhood_is_undirected():
    class FakeLink:
        def __init__(self, source, target):
            self.source = source
            self.target = target

    ids = {"a", "b", "c", "d"}
    links = [FakeLink("a", "b"), FakeLink("c", "b"), FakeLink("c", "d")]
    assert neighborhood(ids, links, "a", 1) == {"a", "b"}
    assert neighborhood(ids, links, "a", 2) == {"a", "b", "c"}
    assert neighborhood(ids, links, "a", 3) == {"a", "b", "c", "d"}


def test_max_nodes_keeps_the_riskiest(all_events):
    graph = prune(build_graph(all_events), max_nodes=5)
    assert len(graph.nodes) <= 5
    assert graph.meta.truncated
    full = build_graph(all_events)
    top_risk = sorted((node.risk for node in full.nodes), reverse=True)[:5]
    assert min(node.risk for node in graph.nodes) >= min(top_risk)


# ---------------------------------------------------------------------- capas


def test_assign_levels_orders_the_attack(all_events):
    graph = assign_levels(build_graph(all_events))
    levels = [node.props["level"] for node in graph.nodes]
    assert all(isinstance(level, int) for level in levels)
    # Capas consecutivas desde 0, sin huecos.
    assert set(levels) == set(range(max(levels) + 1))


def test_every_node_gets_a_level(all_events):
    graph = assign_levels(build_graph(all_events))
    assert all("level" in node.props for node in graph.nodes)


# ------------------------------------------------------------------- timeline


def test_timeline_buckets(all_events):
    result = timeline(all_events, buckets=20)
    assert result.buckets
    assert result.bucket_seconds >= 1
    assert sum(bucket.count for bucket in result.buckets) == len(all_events)
    times = [bucket.t for bucket in result.buckets]
    assert times == sorted(times)


def test_timeline_empty():
    assert timeline([]).buckets == []


def test_parse_moment_relative():
    now = datetime.now(timezone.utc)
    parsed = parse_moment("-24h")
    assert parsed is not None
    assert timedelta(hours=23, minutes=55) < (now - parsed) < timedelta(hours=24, minutes=5)
    assert parse_moment("2026-08-19T09:00:00Z").hour == 9
    assert parse_moment(None) is None
    assert parse_moment("no-es-una-fecha") is None


# ------------------------------------------------------------------ integracion


def test_build_filtered_end_to_end(all_events):
    graph = build_filtered(all_events, min_severity=4, max_nodes=50)
    assert graph.nodes
    assert all("level" in node.props for node in graph.nodes)
    ids = _ids(graph)
    assert all(link.source in ids and link.target in ids for link in graph.links)


# ------------------------------------------------------- fusion IP <-> host


def test_ip_node_merges_into_host_that_claims_it():
    """Una IP y el host que la declara son la misma maquina, no dos nodos."""
    now = datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc)
    events = [
        # Sentinel sabe el nombre Y la IP del equipo que reporta.
        NormalizedEvent(
            uid="a", time=now, source="sentinel", class_name="Network Activity",
            activity="connect", severity=2,
            device=HostRef(hostname="SRV-DC01", ip="10.4.1.5"),
            dst=HostRef(ip="45.132.88.17"),
        ),
        # QRadar solo conoce la IP.
        NormalizedEvent(
            uid="b", time=now, source="qradar", class_name="Network Activity",
            activity="connect", severity=4,
            src=HostRef(ip="10.4.1.5"),
            dst=HostRef(ip="45.132.88.17"),
        ),
    ]
    graph = build_graph(events)
    ids = _ids(graph)

    assert "host:srv-dc01" in ids
    assert "ip:10.4.1.5" not in ids, "la IP interna debe haberse fundido en su host"
    assert "ip:45.132.88.17" in ids, "la IP externa no tiene host y se queda"

    host = [n for n in graph.nodes if n.id == "host:srv-dc01"][0]
    # El nodo fundido hereda lo que sabia el nodo IP.
    assert {"sentinel", "qradar"} <= set(host.sources)
    assert host.max_severity == 4


def test_merged_links_are_rewired_and_deduplicated():
    now = datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc)
    events = [
        NormalizedEvent(
            uid="a", time=now, source="sentinel", class_name="Network Activity",
            activity="connect", device=HostRef(hostname="SRV-DC01", ip="10.4.1.5"),
            dst=HostRef(ip="45.132.88.17"),
        ),
        NormalizedEvent(
            uid="b", time=now, source="qradar", class_name="Network Activity",
            activity="connect", src=HostRef(ip="10.4.1.5"),
            dst=HostRef(ip="45.132.88.17"),
        ),
    ]
    graph = build_graph(events)
    outbound = [l for l in graph.links if l.target == "ip:45.132.88.17"]
    assert len(outbound) == 1, "las dos aristas equivalentes deben colapsar en una"
    assert outbound[0].source == "host:srv-dc01"
    assert outbound[0].count == 2
    assert set(outbound[0].event_uids) == {"a", "b"}


def test_ambiguous_ip_is_not_merged():
    """Dos hosts reclamando la misma IP: unirlos seria inventarse un hecho."""
    now = datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc)
    events = [
        NormalizedEvent(uid="a", time=now, class_name="Network Activity", activity="connect",
                        device=HostRef(hostname="HOST-A", ip="10.0.0.9"),
                        dst=HostRef(ip="45.132.88.17")),
        NormalizedEvent(uid="b", time=now, class_name="Network Activity", activity="connect",
                        device=HostRef(hostname="HOST-B", ip="10.0.0.9"),
                        dst=HostRef(ip="45.132.88.17")),
        NormalizedEvent(uid="c", time=now, class_name="Network Activity", activity="connect",
                        src=HostRef(ip="10.0.0.9"), dst=HostRef(ip="45.132.88.17")),
    ]
    graph = build_graph(events)
    ids = _ids(graph)
    assert "ip:10.0.0.9" in ids
    assert "host:host-a" in ids and "host:host-b" in ids


def test_samples_merge_dc_ip_into_hostname(all_events):
    """Sobre los datos reales de demo: SRV-DC01 y 10.4.1.5 son el mismo nodo."""
    graph = build_graph(all_events)
    ids = _ids(graph)
    assert "host:srv-dc01" in ids
    assert "ip:10.4.1.5" not in ids
    assert "host:wks-0421" in ids
    assert "ip:10.4.2.11" not in ids
    # La IP del C2 sigue siendo un nodo propio: nadie la reclama como suya.
    assert "ip:45.132.88.17" in ids
