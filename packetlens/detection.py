"""Rule-based detection of suspicious traffic PATTERNS.

An alert means "this traffic matches a pattern that scans often produce".
It is not proof of an attack: see docs/detection_rules.md for false
positives.

Rules
-----
port_scan:  one source sends TCP SYN-without-ACK packets (connection
            attempts) to at least `port_scan_ports` distinct destination
            ports on ONE destination within `port_scan_window` seconds.
host_sweep: one source sends connection attempts or pings (TCP
            SYN-without-ACK, ICMP echo request, ICMPv6 echo request) to at
            least `host_sweep_hosts` distinct destination IPs within
            `host_sweep_window` seconds.

Window boundary rule: two events are in the same window when
    later.ts - earlier.ts <= window_seconds      (inclusive)

Consecutive windows that all meet the threshold are merged into ONE alert
(an "episode"), so a long scan gives one alert rather than hundreds.

Detection always runs over the WHOLE capture, never a filtered subset.
"""

import json
import sqlite3
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field

TCP_SYN = 0x02
TCP_ACK = 0x10
ICMP_ECHO_REQUEST = 8
ICMPV6_ECHO_REQUEST = 128


@dataclass(frozen=True)
class DetectionConfig:
    port_scan_ports: int = 20
    port_scan_window: float = 10.0
    host_sweep_hosts: int = 10
    host_sweep_window: float = 10.0

    def __post_init__(self):
        for name in ("port_scan_ports", "host_sweep_hosts"):
            if getattr(self, name) < 2:
                raise ValueError(f"{name} must be at least 2")

        for name in ("port_scan_window", "host_sweep_window"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


@dataclass
class Alert:
    rule: str
    severity: str
    src_ip: str
    dst_ip: str | None
    start_ts: float
    end_ts: float
    metric_name: str
    metric_value: int
    threshold: int
    window_seconds: float
    explanation: str
    packet_ids: list = field(default_factory=list)


def find_episodes(events, threshold, window):
    """Find time spans where a window holds >= threshold distinct targets.

    events: list of (ts, packet_id, target), any order.
    Yields (episode_events, peak_distinct) for each episode.

    A two-pointer "sliding window": `right` adds one event at a time and
    `left` drops events that are more than `window` seconds older.
    """
    events = sorted(events, key=lambda event: (event[0], event[1]))
    targets = Counter()
    left = 0
    episode_start = None
    episode_end = None
    peak = 0

    for right, (ts, _packet_id, target) in enumerate(events):
        targets[target] += 1

        while ts - events[left][0] > window:
            old_target = events[left][2]
            targets[old_target] -= 1
            if targets[old_target] == 0:
                del targets[old_target]
            left += 1

        distinct = len(targets)

        if distinct >= threshold:
            if episode_start is None:
                episode_start = left
                peak = 0
            episode_end = right
            peak = max(peak, distinct)

        elif episode_start is not None:
            yield events[episode_start:episode_end + 1], peak
            episode_start = None

    if episode_start is not None:
        yield events[episode_start:episode_end + 1], peak


def _severity(peak, threshold):
    return "high" if peak >= 2 * threshold else "medium"


def detect_port_scans(connection, config):
    rows = connection.execute(
        """
        SELECT id, ts, src_ip, dst_ip, dst_port
        FROM packets
        WHERE protocol = 'TCP'
          AND (tcp_flags & ?) != 0
          AND (tcp_flags & ?) = 0
          AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
          AND dst_port IS NOT NULL
        """,
        (TCP_SYN, TCP_ACK),
    )

    groups = defaultdict(list)
    for packet_id, ts, src_ip, dst_ip, dst_port in rows:
        groups[(src_ip, dst_ip)].append((ts, packet_id, dst_port))

    alerts = []
    for (src_ip, dst_ip), events in sorted(groups.items()):
        for episode, peak in find_episodes(
            events, config.port_scan_ports, config.port_scan_window
        ):
            total = len({event[2] for event in episode})
            alerts.append(Alert(
                rule="port_scan",
                severity=_severity(peak, config.port_scan_ports),
                src_ip=src_ip,
                dst_ip=dst_ip,
                start_ts=episode[0][0],
                end_ts=episode[-1][0],
                metric_name="distinct_dst_ports_in_window",
                metric_value=peak,
                threshold=config.port_scan_ports,
                window_seconds=config.port_scan_window,
                explanation=(
                    f"{src_ip} sent TCP connection attempts (SYN without "
                    f"ACK) to up to {peak} distinct ports on {dst_ip} "
                    f"within {config.port_scan_window:g} s (threshold "
                    f"{config.port_scan_ports}); {total} distinct ports "
                    f"over the whole episode. Port-scan-like pattern."
                ),
                packet_ids=[event[1] for event in episode],
            ))

    return alerts


def detect_host_sweeps(connection, config):
    rows = connection.execute(
        """
        SELECT id, ts, src_ip, dst_ip
        FROM packets
        WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL
          AND (
                (protocol = 'TCP'
                 AND (tcp_flags & ?) != 0 AND (tcp_flags & ?) = 0)
             OR (protocol = 'ICMP' AND icmp_type = ?)
             OR (protocol = 'ICMPv6' AND icmp_type = ?)
          )
        """,
        (TCP_SYN, TCP_ACK, ICMP_ECHO_REQUEST, ICMPV6_ECHO_REQUEST),
    )

    groups = defaultdict(list)
    for packet_id, ts, src_ip, dst_ip in rows:
        groups[src_ip].append((ts, packet_id, dst_ip))

    alerts = []
    for src_ip, events in sorted(groups.items()):
        for episode, peak in find_episodes(
            events, config.host_sweep_hosts, config.host_sweep_window
        ):
            total = len({event[2] for event in episode})
            alerts.append(Alert(
                rule="host_sweep",
                severity=_severity(peak, config.host_sweep_hosts),
                src_ip=src_ip,
                dst_ip=None,
                start_ts=episode[0][0],
                end_ts=episode[-1][0],
                metric_name="distinct_dst_hosts_in_window",
                metric_value=peak,
                threshold=config.host_sweep_hosts,
                window_seconds=config.host_sweep_window,
                explanation=(
                    f"{src_ip} sent connection attempts or pings to up to "
                    f"{peak} distinct hosts within "
                    f"{config.host_sweep_window:g} s (threshold "
                    f"{config.host_sweep_hosts}); {total} distinct hosts "
                    f"over the whole episode. Host-sweep-like pattern."
                ),
                packet_ids=[event[1] for event in episode],
            ))

    return alerts


def detect_all(connection, config=None):
    """Run every rule and return alerts without writing anything."""
    config = config or DetectionConfig()
    alerts = detect_port_scans(connection, config)
    alerts += detect_host_sweeps(connection, config)
    alerts.sort(key=lambda alert: (alert.start_ts, alert.rule, alert.src_ip))
    return alerts


def run_detection(db_path, config=None) -> int:
    """Replace the stored alerts with a fresh run. Returns the alert count.

    Delete + insert happen in one transaction, so rerunning the same
    analysis gives the same rows, never duplicates.
    """
    config = config or DetectionConfig()
    connection = sqlite3.connect(db_path)
    connection.execute("PRAGMA foreign_keys = ON")

    try:
        with connection:
            alerts = detect_all(connection, config)
            connection.execute("DELETE FROM alert_evidence")
            connection.execute("DELETE FROM alerts")

            for alert in alerts:
                cursor = connection.execute(
                    """
                    INSERT INTO alerts (
                        rule, severity, src_ip, dst_ip, start_ts, end_ts,
                        metric_name, metric_value, threshold,
                        window_seconds, explanation
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.rule, alert.severity, alert.src_ip,
                        alert.dst_ip, alert.start_ts, alert.end_ts,
                        alert.metric_name, alert.metric_value,
                        alert.threshold, alert.window_seconds,
                        alert.explanation,
                    ),
                )
                connection.executemany(
                    "INSERT INTO alert_evidence (alert_id, packet_id) "
                    "VALUES (?, ?)",
                    [(cursor.lastrowid, pid) for pid in alert.packet_ids],
                )

            connection.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                ("detection_config", json.dumps(asdict(config))),
            )

        return len(alerts)
    finally:
        connection.close()


def stored_config(connection):
    """Return the DetectionConfig used for the stored alerts, or None."""
    row = connection.execute(
        "SELECT value FROM metadata WHERE key = 'detection_config'"
    ).fetchone()
    return DetectionConfig(**json.loads(row[0])) if row else None
