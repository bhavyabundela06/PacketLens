"""Filter semantics, consistency between views, and the read-only console."""

import hashlib

import pytest

from packetlens import queries
from packetlens.database import connect
from packetlens.queries import PacketFilter, QueryRejected, run_readonly_query

T0 = 1_700_000_000


@pytest.fixture
def normal(scenario_db):
    connection = connect(scenario_db("normal"), read_only=True)
    yield connection
    connection.close()


FILTERS = [
    PacketFilter(),
    PacketFilter(ip="192.0.2.10"),
    PacketFilter(port=80),
    PacketFilter(protocols=["UDP", "ICMP"]),
    PacketFilter(start_ts=T0 + 1, end_ts=T0 + 3),
    PacketFilter(min_length=60, max_length=100),
    PacketFilter(l7_proto="HTTP"),
    PacketFilter(ip="2001:db8::10", protocols=["TCP"]),
]


@pytest.mark.parametrize("packet_filter", FILTERS)
def test_all_views_describe_same_subset(normal, packet_filter):
    """Every view's totals must equal the filtered summary's totals."""
    total = queries.summary(normal, packet_filter)
    rows = queries.packets(normal, packet_filter, limit=10_000)

    assert total["packets"] == len(rows)
    assert total["captured_bytes"] == sum(row["length"] for row in rows)

    protocols = queries.protocol_distribution(normal, packet_filter)
    assert sum(row["packets"] for row in protocols) == total["packets"]

    timeline = queries.traffic_timeline(normal, packet_filter, 0.5)
    assert sum(row["packets"] for row in timeline) == total["packets"]
    assert sum(row["bytes"] for row in timeline) == total["captured_bytes"]

    with_ip = [row for row in rows if row["src_ip"]]
    hosts = queries.hosts(normal, packet_filter, limit=10_000)
    assert sum(host["pkts_sent"] for host in hosts) == len(with_ip)
    assert sum(host["bytes_sent"] for host in hosts) == sum(r["length"] for r in with_ip)

    transport = [row for row in rows if row["src_port"] is not None]
    conversations = queries.conversations(normal, packet_filter, limit=10_000)
    assert sum(c["packet_count"] for c in conversations) == len(transport)


def test_ip_filter_matches_either_direction(normal):
    rows = queries.packets(normal, PacketFilter(ip="198.51.100.53"))
    directions = {(row["src_ip"], row["dst_ip"]) for row in rows}
    assert directions == {
        ("192.0.2.10", "198.51.100.53"), ("198.51.100.53", "192.0.2.10")
    }


def test_port_filter_matches_either_side(normal):
    rows = queries.packets(normal, PacketFilter(port=53))
    assert {row["src_port"] for row in rows} == {53001, 53}
    assert all(53 in (row["src_port"], row["dst_port"]) for row in rows)


def test_time_range_inclusive(normal):
    first = queries.summary(normal)["first_ts"]
    rows = queries.packets(normal, PacketFilter(start_ts=first, end_ts=first))
    assert len(rows) == 1


def test_zero_matches(normal):
    nothing = PacketFilter(ip="203.0.113.250")
    total = queries.summary(normal, nothing)
    assert total["packets"] == 0 and total["captured_bytes"] == 0
    assert total["first_ts"] is None and total["duration"] == 0.0
    assert queries.traffic_timeline(normal, nothing) == []
    assert queries.hosts(normal, nothing) == []
    assert queries.conversations(normal, nothing) == []
    assert queries.top_senders(normal, nothing) == []


def test_filtered_hosts_differ_from_whole_capture(normal):
    whole = {h["ip"]: h for h in queries.hosts(normal)}
    dns_only = {h["ip"]: h for h in queries.hosts(normal, PacketFilter(port=53))}
    assert dns_only["192.0.2.10"]["pkts_sent"] == 1
    assert whole["192.0.2.10"]["pkts_sent"] > 1


def test_sql_conversations_match_rebuild_flows(normal):
    stored = [dict(row) for row in normal.execute(
        "SELECT protocol, a_ip, a_port, b_ip, b_port, packet_count, "
        "byte_count, packets_a_to_b FROM flows ORDER BY 1, 2, 3, 4, 5")]
    computed = sorted(
        ({key: row[key] for key in stored[0]}
         for row in queries.conversations(normal, limit=10_000)),
        key=lambda row: (row["protocol"], row["a_ip"], row["a_port"],
                         row["b_ip"], row["b_port"]),
    )
    assert computed == stored


def test_timeline_includes_empty_buckets(normal):
    icmp = PacketFilter(protocols=["ICMP"])
    timeline = queries.traffic_timeline(normal, icmp, 0.001)
    # Two ICMP packets about 10 ms apart, 1 ms buckets: the bucket index is
    # floor((ts - first) / size), computed from the stored float timestamps.
    stats = queries.summary(normal, icmp)
    assert len(timeline) == int((stats["last_ts"] - stats["first_ts"]) / 0.001) + 1
    assert len(timeline) >= 10
    assert [b["packets"] for b in (timeline[0], timeline[-1])] == [1, 1]
    assert sum(b["packets"] for b in timeline[1:-1]) == 0
    assert timeline[0]["packets_per_sec"] == 1000


def test_top_talkers_and_ports(normal):
    top = queries.top_senders(normal, limit=1)[0]
    assert top["ip"] == "192.0.2.10"
    by_bytes = queries.top_receivers(normal, by="bytes", limit=3)
    assert by_bytes == sorted(by_bytes, key=lambda r: -r["bytes"])
    ports = queries.top_destination_ports(normal, limit=50)
    assert ("TCP", 80) in {(row["protocol"], row["dst_port"]) for row in ports}


def test_alert_filtering(scenario_db):
    connection = connect(scenario_db("port_scan"), read_only=True)
    try:
        assert len(queries.alerts(connection)) == 2
        assert len(queries.alerts(connection, PacketFilter(ip="2001:db8:bad::66"))) == 1
        # Time filter keeps alerts whose interval overlaps the range.
        assert len(queries.alerts(connection, PacketFilter(start_ts=T0 + 12, end_ts=T0 + 13))) == 1
        # Packet-level filter: an evidence packet must match.
        assert len(queries.alerts(connection, PacketFilter(port=1010))) == 1
        assert queries.alerts(connection, PacketFilter(protocols=["UDP"])) == []

        alert = queries.alerts(connection)[0]
        evidence = queries.alert_evidence(connection, alert["alert_id"])
        assert len(evidence) == alert["evidence_packets"] == 30
    finally:
        connection.close()


# ---- read-only console --------------------------------------------------

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_readonly_query_returns_bounded_rows(demo_db):
    columns, rows, truncated = run_readonly_query(
        demo_db, "SELECT id, protocol FROM packets ORDER BY id", max_rows=3)
    assert columns == ["id", "protocol"]
    assert rows == [(1, "TCP"), (2, "UDP"), (3, "ICMP")]
    assert truncated


@pytest.mark.parametrize("sql", [
    "DELETE FROM packets",
    "UPDATE packets SET protocol = 'X'",
    "INSERT INTO metadata VALUES ('a', 'b')",
    "DROP TABLE packets",
    "CREATE TABLE evil (x)",
    "ATTACH DATABASE '/tmp/other.db' AS other",
    "PRAGMA user_version = 99",
    "PRAGMA journal_mode = DELETE",
    "SELECT 1; DELETE FROM packets",
    "WITH x AS (SELECT 1) DELETE FROM packets",
    "VACUUM",
    "  select * from packets; drop table packets",
])
def test_readonly_query_rejects_changes(demo_db, sql):
    before = sha(demo_db)
    with pytest.raises(QueryRejected):
        run_readonly_query(demo_db, sql)
    assert sha(demo_db) == before


def test_readonly_query_time_limit(demo_db):
    endless = ("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n) "
               "SELECT MAX(x) FROM n")
    with pytest.raises(QueryRejected, match="time limit"):
        run_readonly_query(demo_db, endless, time_limit=0.2)


def test_canned_queries_run(scenario_db):
    for name, sql in queries.CANNED_QUERIES.items():
        columns, rows, _ = run_readonly_query(scenario_db("edge_cases"), sql)
        assert columns, name


def test_evidence_results(scenario_db):
    connection = connect(scenario_db("port_scan"), read_only=True)
    try:
        ipv4, ipv6 = queries.alerts(connection)
        # The IPv4 target answered every attempt with a reset: door closed.
        assert {r["result"] for r in queries.evidence_with_results(connection, ipv4["alert_id"])} == {"closed"}
        # The IPv6 target never replied.
        assert {r["result"] for r in queries.evidence_with_results(connection, ipv6["alert_id"])} == {"no answer"}
    finally:
        connection.close()

    connection = connect(scenario_db("host_sweep"), read_only=True)
    try:
        ping_sweep = queries.alerts(connection)[0]
        results = [r["result"] for r in queries.evidence_with_results(connection, ping_sweep["alert_id"])]
        # Only every 4th pinged host answers in the sample.
        assert results.count("answered") == 5 and results.count("no answer") == 15
    finally:
        connection.close()


def test_open_door_result(make_db):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    from packetlens.detection import DetectionConfig

    eth = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    packets = []
    for index, port in enumerate(range(1, 6)):
        syn = eth / IP(src="203.0.113.1", dst="192.0.2.9") / TCP(sport=40000, dport=port, flags="S")
        syn.time = T0 + index
        packets.append(syn)
    reply = eth / IP(src="192.0.2.9", dst="203.0.113.1") / TCP(sport=3, dport=40000, flags="SA")
    reply.time = T0 + 2.5
    packets.append(reply)
    db = make_db(packets, config=DetectionConfig(port_scan_ports=5, host_sweep_hosts=50))

    connection = connect(db, read_only=True)
    alert = queries.alerts(connection)[0]
    results = {r["dst_port"]: r["result"] for r in queries.evidence_with_results(connection, alert["alert_id"])}
    connection.close()
    assert results[3] == "door open"
    assert results[1] == "no answer"
