"""Network map layers and the capture history helpers."""

import shutil

import pytest

from packetlens import network_map, queries
from packetlens.database import connect
from packetlens.history import delete_captures, list_captures


def links_for(db, packet_filter=None):
    connection = connect(db, read_only=True)
    try:
        return queries.network_links(connection, packet_filter)
    finally:
        connection.close()


def test_service_labels():
    assert network_map.service_label("TCP", 80, None) == "Web (HTTP)"
    assert network_map.service_label("UDP", 53, None) == "Name lookup (DNS)"
    assert network_map.service_label("TCP", 31337, None) == "TCP port 31337"
    assert network_map.service_label("ICMP", None, 8) == "Ping"
    assert network_map.service_label("ICMPv6", None, 1) == "Network messages (ICMPv6)"
    assert network_map.service_label("OTHER", None, None) == "Other traffic"


def test_layers_conserve_message_counts(scenario_db):
    links = links_for(scenario_db("normal"))
    layers, edges = network_map.build_layers(links, max_nodes=50)
    total = sum(link["packets"] for link in links)

    for nodes in layers:
        assert sum(node["packets"] for node in nodes) == total
    for layer in (0, 1):
        assert sum(p for (l, _, _), (p, _) in edges.items() if l == layer) == total

    services = {node["label"] for node in layers[1]}
    assert {"Web (HTTP)", "Name lookup (DNS)", "Ping", "Secure web (HTTPS)"} <= services


def test_small_max_nodes_groups_the_rest(scenario_db):
    links = links_for(scenario_db("port_scan"))
    layers, edges = network_map.build_layers(links, max_nodes=3)
    services = layers[1]
    assert len(services) == 4
    assert services[-1]["label"].startswith("Other services (")
    total = sum(link["packets"] for link in links)
    assert sum(node["packets"] for node in services) == total


def test_flagged_traffic_is_tracked_across_layers(scenario_db):
    links = links_for(scenario_db("port_scan"))
    scanner = "203.0.113.66"
    _, edges = network_map.build_layers(links, 50, {scanner})
    scanner_packets = sum(l["packets"] for l in links if l["src_ip"] == scanner)
    for layer in (0, 1):
        flagged = sum(f for (l, _, _), (_, f) in edges.items() if l == layer)
        assert flagged == scanner_packets
    # Replies TO the scanner are not flagged.
    reply_edges = [v for (l, _, to), v in edges.items() if l == 1 and to == scanner]
    assert reply_edges and all(flagged == 0 for _, flagged in reply_edges)


def test_figure_builds(scenario_db):
    layers, edges = network_map.build_layers(links_for(scenario_db("host_sweep")), 9,
                                             {"203.0.113.77"})
    fig = network_map.figure(layers, edges, {"203.0.113.77"})
    node_traces = [t for t in fig.data if t.mode == "markers+text"]
    assert len(node_traces) == 3
    assert "#E5484D" in node_traces[0].marker.color


def test_empty_links():
    layers, edges = network_map.build_layers([], 5)
    assert layers == [[], [], []] and edges == {}
    network_map.figure(layers, edges)   # must not crash


# ---- history ------------------------------------------------------------

def test_list_captures_statuses(tmp_path, scenario_db):
    shutil.copy(scenario_db("normal"), tmp_path / "good.db")
    (tmp_path / "broken.db").write_bytes(b"not sqlite")
    import sqlite3
    sqlite3.connect(tmp_path / "old.db").execute("CREATE TABLE x (y)").connection.close()

    entries = {e["file"]: e for e in list_captures(tmp_path)}
    assert entries["good.db"]["status"] == "ok"
    assert entries["good.db"]["source_name"] == "normal.pcap"
    assert entries["good.db"]["packets"] == 33
    assert entries["old.db"]["status"] == "old"
    assert entries["broken.db"]["status"] == "unreadable"


def test_delete_captures(tmp_path, scenario_db):
    shutil.copy(scenario_db("normal"), tmp_path / "a.db")
    (tmp_path / "a.db-journal").write_bytes(b"")
    shutil.copy(scenario_db("normal"), tmp_path / "b.db")

    assert delete_captures([tmp_path / "a.db"], tmp_path) == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == ["b.db"]


def test_delete_refuses_outside_folder(tmp_path):
    inside = tmp_path / "out"
    inside.mkdir()
    keep = tmp_path / "precious.db"
    keep.write_bytes(b"x")
    other = inside / "notes.txt"
    other.write_bytes(b"x")

    for path in (keep, other, inside / ".." / "precious.db"):
        with pytest.raises(ValueError):
            delete_captures([path], inside)
    assert keep.exists() and other.exists()
