"""Reusable, filter-aware analysis queries over the packets table.

Every function takes an open connection and a PacketFilter. All of them
build their WHERE clause with the same `filter_sql`, so counts, charts,
conversation tables, and host tables always describe the SAME packet
subset. Conversations and hosts are recomputed from the filtered packets;
they never reuse the whole-capture `flows`/`hosts` tables.

Filter semantics (all given conditions must hold, i.e. they are ANDed):
- ip:        src_ip = ip OR dst_ip = ip
- port:      src_port = port OR dst_port = port
- protocols: protocol is one of the listed labels
- start_ts / end_ts: start_ts <= ts <= end_ts (both inclusive)
- min_length / max_length: captured length within the range (inclusive)
- l7_proto:  l7_proto equals the label (either basis: payload or port)
A field left as None (or an empty protocol list) does not filter.
"""

import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

# SQL expressions that put the two endpoints in the same order as
# flows.flow_key: compare (ip, port) of source vs destination as text/int.
_SRC_IS_A = (
    "(src_ip < dst_ip OR (src_ip = dst_ip AND src_port <= dst_port))"
)


@dataclass
class PacketFilter:
    ip: str | None = None
    port: int | None = None
    protocols: list = field(default_factory=list)
    start_ts: float | None = None
    end_ts: float | None = None
    min_length: int | None = None
    max_length: int | None = None
    l7_proto: str | None = None

    def is_empty(self):
        return self == PacketFilter()

    def describe(self):
        """Human-readable list of active filters (for reports and the UI)."""
        parts = []
        if self.ip:
            parts.append(f"IP {self.ip} (source or destination)")
        if self.port is not None:
            parts.append(f"port {self.port} (source or destination)")
        if self.protocols:
            parts.append("protocol in " + ", ".join(self.protocols))
        if self.start_ts is not None:
            parts.append(f"ts >= {self.start_ts:.6f}")
        if self.end_ts is not None:
            parts.append(f"ts <= {self.end_ts:.6f}")
        if self.min_length is not None:
            parts.append(f"captured length >= {self.min_length}")
        if self.max_length is not None:
            parts.append(f"captured length <= {self.max_length}")
        if self.l7_proto:
            parts.append(f"application label = {self.l7_proto}")
        return parts or ["none (whole capture)"]


def filter_sql(packet_filter):
    """Return (where_clause, params). The clause always starts with WHERE.

    Only placeholders (?) carry user values, never string formatting.
    """
    f = packet_filter or PacketFilter()
    conditions = ["1 = 1"]
    params = []

    if f.ip:
        conditions.append("(src_ip = ? OR dst_ip = ?)")
        params += [f.ip, f.ip]
    if f.port is not None:
        conditions.append("(src_port = ? OR dst_port = ?)")
        params += [f.port, f.port]
    if f.protocols:
        marks = ", ".join("?" for _ in f.protocols)
        conditions.append(f"protocol IN ({marks})")
        params += list(f.protocols)
    if f.start_ts is not None:
        conditions.append("ts >= ?")
        params.append(f.start_ts)
    if f.end_ts is not None:
        conditions.append("ts <= ?")
        params.append(f.end_ts)
    if f.min_length is not None:
        conditions.append("length >= ?")
        params.append(f.min_length)
    if f.max_length is not None:
        conditions.append("length <= ?")
        params.append(f.max_length)
    if f.l7_proto:
        conditions.append("l7_proto = ?")
        params.append(f.l7_proto)

    return "WHERE " + " AND ".join(conditions), params


def _rows(connection, sql, params):
    return [dict(row) for row in _execute(connection, sql, params)]


def _execute(connection, sql, params):
    connection.row_factory = sqlite3.Row
    return connection.execute(sql, params).fetchall()


def summary(connection, packet_filter=None):
    """Packet count, captured bytes, on-wire bytes, and time span."""
    where, params = filter_sql(packet_filter)
    row = _execute(connection, f"""
        SELECT COUNT(*) AS packets,
               COALESCE(SUM(length), 0) AS captured_bytes,
               COALESCE(SUM(wire_length), 0) AS wire_bytes,
               MIN(ts) AS first_ts,
               MAX(ts) AS last_ts
        FROM packets {where}
    """, params)[0]
    result = dict(row)
    result["duration"] = (
        result["last_ts"] - result["first_ts"] if result["packets"] else 0.0
    )
    return result


def protocol_distribution(connection, packet_filter=None):
    where, params = filter_sql(packet_filter)
    return _rows(connection, f"""
        SELECT protocol, COUNT(*) AS packets, SUM(length) AS bytes
        FROM packets {where}
        GROUP BY protocol
        ORDER BY packets DESC, protocol
    """, params)


def application_distribution(connection, packet_filter=None):
    where, params = filter_sql(packet_filter)
    return _rows(connection, f"""
        SELECT COALESCE(l7_proto, 'unknown') AS l7_proto,
               COALESCE(l7_basis, '-') AS l7_basis,
               COUNT(*) AS packets, SUM(length) AS bytes
        FROM packets {where}
        GROUP BY 1, 2
        ORDER BY packets DESC, 1, 2
    """, params)


def _top_ips(connection, packet_filter, column, order_by, limit):
    # column/order_by come only from the two fixed callers below.
    where, params = filter_sql(packet_filter)
    return _rows(connection, f"""
        SELECT {column} AS ip, COUNT(*) AS packets, SUM(length) AS bytes
        FROM packets {where} AND {column} IS NOT NULL
        GROUP BY {column}
        ORDER BY {order_by} DESC, ip
        LIMIT ?
    """, params + [limit])


def top_senders(connection, packet_filter=None, by="packets", limit=10):
    order = "bytes" if by == "bytes" else "packets"
    return _top_ips(connection, packet_filter, "src_ip", order, limit)


def top_receivers(connection, packet_filter=None, by="packets", limit=10):
    order = "bytes" if by == "bytes" else "packets"
    return _top_ips(connection, packet_filter, "dst_ip", order, limit)


def top_destination_ports(connection, packet_filter=None, limit=10):
    where, params = filter_sql(packet_filter)
    return _rows(connection, f"""
        SELECT protocol, dst_port, COUNT(*) AS packets, SUM(length) AS bytes,
               COUNT(DISTINCT src_ip) AS distinct_sources
        FROM packets {where} AND dst_port IS NOT NULL
        GROUP BY protocol, dst_port
        ORDER BY packets DESC, protocol, dst_port
        LIMIT ?
    """, params + [limit])


def conversations(connection, packet_filter=None, order_by="bytes",
                  limit=50):
    """Endpoint conversations computed from the FILTERED packets.

    Same grouping as flows.rebuild_flows, done in SQL. order_by may be
    'bytes', 'packets', or 'duration'.
    """
    order = {
        "bytes": "byte_count", "packets": "packet_count",
        "duration": "duration",
    }.get(order_by, "byte_count")
    where, params = filter_sql(packet_filter)
    return _rows(connection, f"""
        SELECT protocol,
               CASE WHEN {_SRC_IS_A} THEN src_ip ELSE dst_ip END AS a_ip,
               CASE WHEN {_SRC_IS_A} THEN src_port ELSE dst_port END AS a_port,
               CASE WHEN {_SRC_IS_A} THEN dst_ip ELSE src_ip END AS b_ip,
               CASE WHEN {_SRC_IS_A} THEN dst_port ELSE src_port END AS b_port,
               MIN(ts) AS start_ts,
               MAX(ts) AS end_ts,
               MAX(ts) - MIN(ts) AS duration,
               COUNT(*) AS packet_count,
               SUM(length) AS byte_count,
               SUM(CASE WHEN {_SRC_IS_A} THEN 1 ELSE 0 END) AS packets_a_to_b,
               SUM(CASE WHEN {_SRC_IS_A} THEN 0 ELSE 1 END) AS packets_b_to_a
        FROM packets {where}
          AND protocol IN ('TCP', 'UDP')
          AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
          AND src_port IS NOT NULL AND dst_port IS NOT NULL
        GROUP BY 1, 2, 3, 4, 5
        ORDER BY {order} DESC, start_ts
        LIMIT ?
    """, params + [limit])


def hosts(connection, packet_filter=None, limit=100):
    """Per-IP sent/received totals computed from the FILTERED packets."""
    where, params = filter_sql(packet_filter)
    return _rows(connection, f"""
        SELECT ip,
               SUM(sent) AS pkts_sent, SUM(recv) AS pkts_recv,
               SUM(sent * length) AS bytes_sent,
               SUM(recv * length) AS bytes_recv,
               MIN(ts) AS first_seen, MAX(ts) AS last_seen
        FROM (
            SELECT src_ip AS ip, 1 AS sent, 0 AS recv, length, ts
            FROM packets {where} AND src_ip IS NOT NULL
            UNION ALL
            SELECT dst_ip AS ip, 0 AS sent, 1 AS recv, length, ts
            FROM packets {where} AND dst_ip IS NOT NULL
        )
        GROUP BY ip
        ORDER BY bytes_sent + bytes_recv DESC, ip
        LIMIT ?
    """, params + params + [limit])


def traffic_timeline(connection, packet_filter=None, bucket_seconds=1.0):
    """Packets and captured bytes per time bucket.

    Bucket k covers [first_ts + k*size, first_ts + (k+1)*size). Buckets
    with no packets are included with zeros, so a chart does not hide gaps.
    "per second" rates are packets / bucket_seconds.
    """
    if bucket_seconds <= 0:
        raise ValueError("bucket_seconds must be positive")

    where, params = filter_sql(packet_filter)
    first = _execute(
        connection, f"SELECT MIN(ts) FROM packets {where}", params
    )[0][0]

    if first is None:
        return []

    rows = _execute(connection, f"""
        SELECT CAST((ts - ?) / ? AS INTEGER) AS bucket,
               COUNT(*) AS packets, SUM(length) AS bytes
        FROM packets {where}
        GROUP BY bucket
        ORDER BY bucket
    """, [first, bucket_seconds] + params)

    counts = {row["bucket"]: row for row in rows}
    last_bucket = rows[-1]["bucket"]
    timeline = []

    for bucket in range(last_bucket + 1):
        row = counts.get(bucket)
        packets = row["packets"] if row else 0
        size = row["bytes"] if row else 0
        timeline.append({
            "bucket_start": first + bucket * bucket_seconds,
            "packets": packets,
            "bytes": size,
            "packets_per_sec": packets / bucket_seconds,
            "bytes_per_sec": size / bucket_seconds,
        })

    return timeline


def network_links(connection, packet_filter=None):
    """Who talked to whom, for what service: input for the network map.

    service_port is the smaller of the two ports (usually the server's
    well-known port); NULL when the packet has no ports.
    """
    where, params = filter_sql(packet_filter)
    return _rows(connection, f"""
        SELECT src_ip, dst_ip, protocol,
               CASE WHEN src_port IS NULL OR dst_port IS NULL THEN NULL
                    WHEN dst_port <= src_port THEN dst_port
                    ELSE src_port END AS service_port,
               CASE WHEN protocol IN ('ICMP', 'ICMPv6') THEN icmp_type END
                   AS icmp_type,
               COUNT(*) AS packets, SUM(length) AS bytes
        FROM packets {where} AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
        GROUP BY 1, 2, 3, 4, 5
    """, params)


def packets(connection, packet_filter=None, limit=200, offset=0):
    where, params = filter_sql(packet_filter)
    return _rows(connection, f"""
        SELECT * FROM packets {where}
        ORDER BY ts, id
        LIMIT ? OFFSET ?
    """, params + [limit, offset])


def alerts(connection, packet_filter=None):
    """Stored whole-capture alerts that are RELEVANT to the filter.

    Alerts are computed for the whole capture; filtering only chooses
    which alerts to show:
    - ip filter: alert src_ip or dst_ip equals the IP;
    - time filter: the alert interval overlaps [start_ts, end_ts];
    - other filters (port, protocol, size, l7): an alert is shown if at
      least one of its evidence packets matches the whole filter.
    """
    f = packet_filter or PacketFilter()
    conditions = ["1 = 1"]
    params = []

    if f.ip:
        conditions.append("(a.src_ip = ? OR a.dst_ip = ?)")
        params += [f.ip, f.ip]
    if f.start_ts is not None:
        conditions.append("a.end_ts >= ?")
        params.append(f.start_ts)
    if f.end_ts is not None:
        conditions.append("a.start_ts <= ?")
        params.append(f.end_ts)

    packet_level = (
        f.port is not None or f.protocols or f.min_length is not None
        or f.max_length is not None or f.l7_proto
    )
    if packet_level:
        where, packet_params = filter_sql(f)
        conditions.append(f"""EXISTS (
            SELECT 1 FROM alert_evidence e JOIN packets p ON p.id = e.packet_id
            WHERE e.alert_id = a.alert_id
              AND p.id IN (SELECT id FROM packets {where}))""")
        params += packet_params

    return _rows(connection, f"""
        SELECT a.*, (SELECT COUNT(*) FROM alert_evidence e
                     WHERE e.alert_id = a.alert_id) AS evidence_packets
        FROM alerts a
        WHERE {' AND '.join(conditions)}
        ORDER BY a.start_ts, a.rule, a.src_ip
    """, params)


def alert_evidence(connection, alert_id, limit=500):
    """Packets that support one alert."""
    return _rows(connection, """
        SELECT p.* FROM alert_evidence e JOIN packets p ON p.id = e.packet_id
        WHERE e.alert_id = ?
        ORDER BY p.ts, p.id
        LIMIT ?
    """, [alert_id, limit])


def evidence_with_results(connection, alert_id, limit=500):
    """Evidence packets plus what happened to each attempt.

    result is worked out from the target's reply, if the capture holds one:
    - TCP: a SYN+ACK back means "door open"; a RST back means "closed";
    - ICMP/ICMPv6 echo: an echo reply back means "answered";
    - no matching reply after the attempt: "no answer".
    A reply must come from the target, to the sender, on the same pair of
    ports, at or after the attempt's time.
    """
    rows = alert_evidence(connection, alert_id, limit)
    for row in rows:
        if row["protocol"] == "TCP":
            reply = connection.execute("""
                SELECT tcp_flags FROM packets
                WHERE protocol = 'TCP' AND src_ip = ? AND dst_ip = ?
                  AND src_port = ? AND dst_port = ? AND ts >= ?
                ORDER BY ts LIMIT 1
            """, (row["dst_ip"], row["src_ip"], row["dst_port"],
                  row["src_port"], row["ts"])).fetchone()
            if reply is None:
                row["result"] = "no answer"
            elif reply[0] & 0x12 == 0x12:
                row["result"] = "door open"
            elif reply[0] & 0x04:
                row["result"] = "closed"
            else:
                row["result"] = "other reply"
        elif row["protocol"] in ("ICMP", "ICMPv6"):
            reply_type = 0 if row["protocol"] == "ICMP" else 129
            reply = connection.execute("""
                SELECT 1 FROM packets
                WHERE protocol = ? AND icmp_type = ? AND src_ip = ?
                  AND dst_ip = ? AND ts >= ? LIMIT 1
            """, (row["protocol"], reply_type, row["dst_ip"], row["src_ip"],
                  row["ts"])).fetchone()
            row["result"] = "answered" if reply else "no answer"
        else:
            row["result"] = None
    return rows


def capture_info(connection):
    row = _execute(connection, "SELECT * FROM capture_info", [])
    return dict(row[0]) if row else None


def l7_labels(connection):
    return [row[0] for row in _execute(connection, """
        SELECT DISTINCT l7_proto FROM packets
        WHERE l7_proto IS NOT NULL ORDER BY 1
    """, [])]


# ---------------------------------------------------------------------------
# Canned queries for the query console. Each one is a fixed, reviewed SQL
# statement; the console runs them through run_readonly_query anyway.
CANNED_QUERIES = {
    "Which devices sent the most data?": """
        SELECT src_ip AS device, COUNT(*) AS messages, SUM(length) AS bytes
        FROM packets WHERE src_ip IS NOT NULL
        GROUP BY src_ip ORDER BY bytes DESC""",
    "Which doors (ports) were tried most?": """
        SELECT dst_port AS door, COUNT(*) AS attempts,
               COUNT(DISTINCT src_ip) AS devices
        FROM packets
        WHERE protocol = 'TCP' AND (tcp_flags & 2) != 0 AND (tcp_flags & 16) = 0
        GROUP BY dst_port ORDER BY attempts DESC, door LIMIT 20""",
    "Who tried the most different doors?": """
        SELECT src_ip AS device, dst_ip AS target,
               COUNT(DISTINCT dst_port) AS different_doors, COUNT(*) AS messages
        FROM packets WHERE dst_port IS NOT NULL
        GROUP BY src_ip, dst_ip ORDER BY different_doors DESC LIMIT 20""",
    "Messages per kind of traffic": """
        SELECT protocol AS kind, COUNT(*) AS messages, SUM(length) AS bytes
        FROM packets GROUP BY protocol ORDER BY messages DESC""",
    "Which name lookups (DNS) were seen?": """
        SELECT id, ts, src_ip, dst_ip, info FROM packets
        WHERE l7_proto = 'DNS' AND l7_basis = 'payload' ORDER BY ts""",
    "Ping and network messages by type": """
        SELECT protocol, icmp_type, icmp_code, COUNT(*) AS messages
        FROM packets WHERE protocol IN ('ICMP', 'ICMPv6')
        GROUP BY protocol, icmp_type, icmp_code ORDER BY messages DESC""",
    "Fragments and cut-off messages": """
        SELECT id, ts, src_ip, dst_ip, protocol, length, wire_length,
               is_fragment
        FROM packets WHERE is_fragment = 1 OR wire_length > length
        ORDER BY ts""",
    "IPv4 vs IPv6": """
        SELECT COALESCE(ip_version, 'non-IP') AS ip_version,
               COUNT(*) AS messages, SUM(length) AS bytes
        FROM packets GROUP BY ip_version""",
}


class QueryRejected(Exception):
    """The read-only console refused or stopped a query."""


# SQLite authorizer action codes that a read-only SELECT needs.
_ALLOWED_ACTIONS = {
    sqlite3.SQLITE_SELECT,
    sqlite3.SQLITE_READ,
    sqlite3.SQLITE_FUNCTION,
    # WITH RECURSIVE ... only reads; the time limit stops runaway ones.
    getattr(sqlite3, "SQLITE_RECURSIVE", 33),
}


def _authorizer(action, arg1, arg2, db_name, trigger):
    if action in _ALLOWED_ACTIONS:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def run_readonly_query(db_path, sql, max_rows=500, time_limit=2.0):
    """Run ONE user-supplied SELECT safely. Returns (columns, rows, truncated).

    Three independent protections, so no single check has to be perfect:
    1. The file is opened with SQLite's read-only mode (mode=ro).
    2. An authorizer denies every action except reading tables and calling
       functions: no INSERT/UPDATE/DELETE/CREATE/DROP/ATTACH/PRAGMA.
    3. A progress handler aborts queries running longer than time_limit.
    sqlite3 itself refuses to run more than one statement per call.
    At most max_rows rows are fetched.
    """
    db_path = Path(db_path).resolve()
    connection = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
    deadline = time.monotonic() + time_limit

    def progress():
        # Returning non-zero tells SQLite to interrupt the query.
        return 1 if time.monotonic() > deadline else 0

    try:
        connection.set_authorizer(_authorizer)
        connection.set_progress_handler(progress, 10_000)

        try:
            cursor = connection.execute(sql)
            rows = cursor.fetchmany(max_rows + 1)
        except sqlite3.DatabaseError as error:
            message = str(error)
            if "interrupted" in message:
                message = f"stopped after {time_limit:g} s time limit"
            raise QueryRejected(message) from error
        except sqlite3.ProgrammingError as error:
            raise QueryRejected(str(error)) from error

        if cursor.description is None:
            raise QueryRejected("only queries that return rows are allowed")

        columns = [column[0] for column in cursor.description]
        truncated = len(rows) > max_rows
        return columns, [tuple(row) for row in rows[:max_rows]], truncated
    finally:
        connection.close()
