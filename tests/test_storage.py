"""Ingestion, schema versioning, flows, and hosts."""

import hashlib
import sqlite3

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from packetlens.database import SCHEMA_VERSION, SchemaVersionError, connect
from packetlens.flows import rebuild_flows
from packetlens.hosts import rebuild_hosts
from packetlens.ingest import IngestError, ingest_capture, main

from .conftest import DEMO_PCAP

ETH = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def test_end_to_end_counts_match_manifest(manifest, scenario_db):
    for file_name, expected in manifest["captures"].items():
        db = scenario_db(file_name.removesuffix(".pcap"))
        connection = connect(db, read_only=True)
        try:
            count = connection.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
            info = connection.execute("SELECT * FROM capture_info").fetchone()
            alerts = connection.execute(
                "SELECT rule, src_ip, dst_ip FROM alerts ORDER BY start_ts"
            ).fetchall()
        finally:
            connection.close()

        assert count == expected["packets"], file_name
        assert info["packet_count"] == count
        assert info["source_name"] == file_name
        assert [dict(row) for row in alerts] == expected["expected_alerts"]


def test_capture_info_hash(demo_db):
    connection = connect(demo_db, read_only=True)
    info = dict(connection.execute("SELECT * FROM capture_info").fetchone())
    connection.close()
    assert info["source_sha256"] == hashlib.sha256(DEMO_PCAP.read_bytes()).hexdigest()
    assert info["source_bytes"] == DEMO_PCAP.stat().st_size


def test_refuses_existing_output(tmp_path, demo_db):
    before = demo_db.read_bytes()
    with pytest.raises(IngestError, match="already exists"):
        ingest_capture(DEMO_PCAP, demo_db)
    assert demo_db.read_bytes() == before


def test_invalid_capture_leaves_no_output(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a capture")
    target = tmp_path / "out.db"

    with pytest.raises(IngestError):
        ingest_capture(bad, target)

    # Neither the database nor any temporary file is left behind.
    assert sorted(path.name for path in tmp_path.iterdir()) == ["bad.pcap"]


def test_capture_cut_mid_record(tmp_path):
    """A file cut inside its last record: Scapy returns that packet shortened.

    The import succeeds, and the short packet is visible because its
    captured length is smaller than the on-wire length in its header.
    """
    good = tmp_path / "good.pcap"
    packets = [ETH / IP(src="192.0.2.1", dst="192.0.2.2") / UDP()] * 50
    for index, packet in enumerate(packets):
        packet.time = 1_700_000_000 + index
    wrpcap(str(good), packets)
    damaged = tmp_path / "damaged.pcap"
    damaged.write_bytes(good.read_bytes()[:-10])
    target = tmp_path / "out.db"

    ingest_capture(damaged, target)

    connection = connect(target, read_only=True)
    rows = connection.execute(
        "SELECT length, wire_length FROM packets ORDER BY id").fetchall()
    connection.close()
    assert len(rows) == 50
    assert all(row["length"] == row["wire_length"] for row in rows[:49])
    assert rows[49]["length"] == rows[49]["wire_length"] - 10
    assert not list(tmp_path.glob("*.partial"))


def test_failure_after_parsing_leaves_no_output(tmp_path, monkeypatch):
    """Simulate a crash in a late step: nothing may look imported."""
    import packetlens.ingest as ingest_module

    def broken(*args, **kwargs):
        raise sqlite3.OperationalError("simulated failure")

    monkeypatch.setattr(ingest_module, "rebuild_hosts", broken)
    target = tmp_path / "out.db"

    with pytest.raises(IngestError, match="simulated failure"):
        ingest_capture(DEMO_PCAP, target)
    assert list(tmp_path.iterdir()) == []


def test_missing_capture(tmp_path):
    with pytest.raises(IngestError, match="not found"):
        ingest_capture(tmp_path / "missing.pcap", tmp_path / "x.db")


def test_cli_reports_errors(tmp_path, capsys):
    assert main([str(tmp_path / "missing.pcap"), str(tmp_path / "x.db")]) == 1
    assert "Error" in capsys.readouterr().err
    assert main([str(DEMO_PCAP), str(tmp_path / "ok.db")]) == 0
    assert "Imported 5 packets" in capsys.readouterr().out


def test_empty_capture_imports(tmp_path):
    empty = tmp_path / "empty.pcap"
    wrpcap(str(empty), [])
    counts = ingest_capture(empty, tmp_path / "empty.db")
    assert counts == {"packets": 0, "flows": 0, "hosts": 0, "alerts": 0}


def test_old_schema_database_is_rejected_and_untouched(tmp_path):
    old = tmp_path / "old.db"
    connection = sqlite3.connect(old)
    connection.execute("CREATE TABLE packets (id INTEGER PRIMARY KEY, ts REAL)")
    connection.commit()
    connection.close()
    before = old.read_bytes()

    with pytest.raises(SchemaVersionError, match="Re-import"):
        connect(old)
    assert old.read_bytes() == before


def test_schema_version_is_set(demo_db):
    connection = connect(demo_db, read_only=True)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    connection.close()


def test_read_only_connection_cannot_write(demo_db):
    connection = connect(demo_db, read_only=True)
    with pytest.raises(sqlite3.OperationalError):
        connection.execute("DELETE FROM packets")
    connection.close()


# ---- flows -------------------------------------------------------------

def test_demo_flows_bidirectional(demo_db):
    assert rebuild_flows(demo_db) == 2
    assert rebuild_flows(demo_db) == 2      # rebuild does not duplicate

    connection = connect(demo_db, read_only=True)
    tcp = dict(connection.execute(
        "SELECT * FROM flows WHERE protocol = 'TCP'").fetchone())
    tcp_bytes = connection.execute(
        "SELECT SUM(length) FROM packets WHERE protocol = 'TCP'").fetchone()[0]
    connection.close()

    assert (tcp["a_ip"], tcp["a_port"], tcp["b_ip"], tcp["b_port"]) == (
        "192.0.2.1", 50000, "192.0.2.2", 80
    )
    assert tcp["packet_count"] == 2
    assert (tcp["packets_a_to_b"], tcp["packets_b_to_a"]) == (1, 1)
    assert tcp["duration"] == 4.0
    assert tcp["byte_count"] == tcp_bytes == tcp["bytes_a_to_b"] + tcp["bytes_b_to_a"]


def test_flows_out_of_order_and_ipv6(make_db):
    packets = [
        ETH / IPv6(src="2001:db8::2", dst="2001:db8::1") / TCP(sport=443, dport=5000, flags="A"),
        ETH / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=5000, dport=443, flags="S"),
        ETH / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=5000, dport=443, flags="A"),
    ]
    # Written in this order, but the first packet has the LATEST time.
    for packet, ts in zip(packets, (1_700_000_010, 1_700_000_000, 1_700_000_005)):
        packet.time = ts
    db = make_db(packets)

    connection = connect(db, read_only=True)
    flow = dict(connection.execute("SELECT * FROM flows").fetchone())
    connection.close()

    assert flow["a_ip"] == "2001:db8::1" and flow["a_port"] == 5000
    assert flow["start_ts"] == 1_700_000_000
    assert flow["end_ts"] == 1_700_000_010
    assert flow["duration"] == 10
    assert (flow["packets_a_to_b"], flow["packets_b_to_a"]) == (2, 1)


# ---- hosts -------------------------------------------------------------

def test_demo_hosts(demo_db):
    assert rebuild_hosts(demo_db) == 2
    assert rebuild_hosts(demo_db) == 2

    connection = connect(demo_db, read_only=True)
    hosts = {row["ip"]: dict(row) for row in connection.execute("SELECT * FROM hosts")}
    connection.close()

    first, second = hosts["192.0.2.1"], hosts["192.0.2.2"]
    assert (first["pkts_sent"], first["pkts_recv"]) == (3, 1)
    assert (second["pkts_sent"], second["pkts_recv"]) == (1, 3)
    # Captured Ethernet frame sizes: TCP = 54, UDP = 42, ICMP = 42 bytes.
    assert (first["bytes_sent"], first["bytes_recv"]) == (138, 54)
    assert (second["bytes_sent"], second["bytes_recv"]) == (54, 138)
    for host in hosts.values():
        assert (host["first_seen"], host["last_seen"]) == (1_700_000_000, 1_700_000_004)


def test_host_totals_match_packets(scenario_db):
    connection = connect(scenario_db("normal"), read_only=True)
    sent = connection.execute("SELECT SUM(pkts_sent), SUM(bytes_sent) FROM hosts").fetchone()
    ip_packets = connection.execute(
        "SELECT COUNT(*), SUM(length) FROM packets WHERE src_ip IS NOT NULL"
    ).fetchone()
    connection.close()
    assert tuple(sent) == tuple(ip_packets)
