"""Detection rules: positives, negatives, window boundaries, reruns."""

import sqlite3

import pytest
from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import Ether

from packetlens.database import connect
from packetlens.detection import (
    DetectionConfig,
    detect_all,
    find_episodes,
    run_detection,
    stored_config,
)

ETH = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
T0 = 1_700_000_000


def syns(source, destination, ports, times, flags="S"):
    packets = []
    for port, ts in zip(ports, times):
        packet = ETH / IP(src=source, dst=destination) / TCP(
            sport=40000, dport=port, flags=flags)
        packet.time = T0 + ts
        packets.append(packet)
    return packets


def alerts_in(db):
    connection = connect(db, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM alerts ORDER BY start_ts")]
    finally:
        connection.close()


# ---- the sliding window itself -----------------------------------------

def test_episode_boundary_is_inclusive():
    # 3 distinct targets; first and last exactly 10.0 s apart.
    events = [(0.0, 1, "a"), (5.0, 2, "b"), (10.0, 3, "c")]
    assert [peak for _, peak in find_episodes(events, 3, 10.0)] == [3]


def test_episode_just_outside_window():
    events = [(0.0, 1, "a"), (5.0, 2, "b"), (10.001, 3, "c")]
    assert list(find_episodes(events, 3, 10.0)) == []


def test_repeated_targets_count_once():
    events = [(index * 0.1, index, "same") for index in range(50)]
    assert list(find_episodes(events, 2, 10.0)) == []


def test_two_separate_episodes():
    events = [(t, t, f"x{t}") for t in range(3)] + \
             [(100 + t, 100 + t, f"y{t}") for t in range(3)]
    episodes = list(find_episodes(events, 3, 5.0))
    assert len(episodes) == 2
    assert [len(events) for events, _ in episodes] == [3, 3]


def test_unsorted_input_is_sorted():
    events = [(10.0, 3, "c"), (0.0, 1, "a"), (5.0, 2, "b")]
    episode, peak = next(find_episodes(events, 3, 10.0))
    assert [event[1] for event in episode] == [1, 2, 3]


# ---- port scan ---------------------------------------------------------

CONFIG = DetectionConfig(port_scan_ports=5, port_scan_window=10,
                         host_sweep_hosts=5, host_sweep_window=10)


def test_port_scan_positive_with_evidence(make_db):
    db = make_db(syns("203.0.113.1", "192.0.2.10", range(1, 6), range(5)),
                 config=CONFIG)
    (alert,) = alerts_in(db)

    assert alert["rule"] == "port_scan"
    assert (alert["src_ip"], alert["dst_ip"]) == ("203.0.113.1", "192.0.2.10")
    assert alert["metric_value"] == 5 and alert["threshold"] == 5
    assert (alert["start_ts"], alert["end_ts"]) == (T0, T0 + 4)
    assert alert["severity"] == "medium"

    connection = connect(db, read_only=True)
    evidence = [row[0] for row in connection.execute(
        "SELECT p.dst_port FROM alert_evidence e JOIN packets p "
        "ON p.id = e.packet_id WHERE e.alert_id = ? ORDER BY p.ts",
        (alert["alert_id"],))]
    connection.close()
    assert evidence == [1, 2, 3, 4, 5]


def test_port_scan_below_threshold(make_db):
    db = make_db(syns("203.0.113.1", "192.0.2.10", range(1, 5), range(4)),
                 config=CONFIG)
    assert alerts_in(db) == []


def test_port_scan_window_boundary(make_db):
    # 5 ports with first->last exactly 10 s: inside (inclusive).
    inside = make_db(syns("203.0.113.1", "192.0.2.10", range(1, 6),
                          [0, 1, 2, 3, 10]), config=CONFIG)
    assert len(alerts_in(inside)) == 1
    # Same, but the last one 10.5 s after the first: never 5 in a window.
    outside = make_db(syns("203.0.113.1", "192.0.2.10", range(1, 6),
                           [0, 1, 2, 3, 10.5]), config=CONFIG)
    assert alerts_in(outside) == []


def test_syn_ack_replies_are_not_scans(make_db):
    db = make_db(syns("192.0.2.10", "203.0.113.1", range(1, 30), range(29),
                      flags="SA"), config=CONFIG)
    assert alerts_in(db) == []


def test_ports_spread_over_destinations_are_not_port_scan(make_db):
    packets = []
    for index in range(10):
        packets += syns("203.0.113.1", f"192.0.2.{index + 1}", [index + 1], [index * 0.1])
    db = make_db(packets, config=DetectionConfig(port_scan_ports=5,
                                                 host_sweep_hosts=50))
    assert alerts_in(db) == []


def test_high_severity(make_db):
    db = make_db(syns("203.0.113.1", "192.0.2.10", range(1, 11),
                      [i * 0.1 for i in range(10)]), config=CONFIG)
    assert alerts_in(db)[0]["severity"] == "high"


# ---- host sweep --------------------------------------------------------

def pings(source, count, spacing):
    packets = []
    for index in range(count):
        packet = ETH / IP(src=source, dst=f"198.51.100.{index + 1}") / ICMP(type=8)
        packet.time = T0 + index * spacing
        packets.append(packet)
    return packets


def test_host_sweep_positive(make_db):
    db = make_db(pings("203.0.113.9", 5, 1.0), config=CONFIG)
    (alert,) = alerts_in(db)
    assert alert["rule"] == "host_sweep"
    assert alert["dst_ip"] is None
    assert alert["metric_value"] == 5


def test_host_sweep_negative_slow(make_db):
    # 5 hosts, but 3 s apart: at most 4 inside any 10 s window.
    db = make_db(pings("203.0.113.9", 5, 3.0), config=CONFIG)
    assert alerts_in(db) == []


def test_echo_replies_not_counted(make_db):
    packets = pings("203.0.113.9", 10, 0.1)
    for packet in packets:
        packet[ICMP].type = 0
    db = make_db(packets, config=CONFIG)
    assert alerts_in(db) == []


# ---- reruns, config, samples -------------------------------------------

def test_rerun_does_not_duplicate(make_db):
    db = make_db(syns("203.0.113.1", "192.0.2.10", range(1, 6), range(5)),
                 config=CONFIG)
    first = alerts_in(db)
    assert run_detection(db, CONFIG) == 1
    assert run_detection(db, CONFIG) == 1
    second = alerts_in(db)
    assert [a["explanation"] for a in first] == [a["explanation"] for a in second]

    connection = connect(db, read_only=True)
    assert connection.execute("SELECT COUNT(*) FROM alert_evidence").fetchone()[0] == 5
    assert stored_config(connection) == CONFIG
    connection.close()


def test_changing_threshold_replaces_alerts(make_db):
    db = make_db(syns("203.0.113.1", "192.0.2.10", range(1, 6), range(5)),
                 config=CONFIG)
    assert run_detection(db, DetectionConfig(port_scan_ports=6)) == 0
    assert alerts_in(db) == []


def test_invalid_config():
    with pytest.raises(ValueError):
        DetectionConfig(port_scan_ports=1)
    with pytest.raises(ValueError):
        DetectionConfig(host_sweep_window=0)


def test_detect_all_does_not_write(scenario_db):
    connection = sqlite3.connect(scenario_db("port_scan").as_uri() + "?mode=ro", uri=True)
    alerts = detect_all(connection)
    connection.close()
    assert len(alerts) == 2


def test_near_threshold_sample_has_no_alerts(scenario_db):
    assert alerts_in(scenario_db("near_threshold")) == []


def test_near_threshold_sample_alerts_when_threshold_lowered(scenario_db, tmp_path):
    import shutil

    copy = tmp_path / "copy.db"
    shutil.copy(scenario_db("near_threshold"), copy)
    # 19 ports at threshold 19 -> alert; 9 pinged hosts at 9 -> alert.
    assert run_detection(copy, DetectionConfig(port_scan_ports=19,
                                               host_sweep_hosts=9)) >= 2
