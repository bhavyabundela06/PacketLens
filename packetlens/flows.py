"""Endpoint conversation summaries ("flows").

A flow here groups every TCP or UDP packet between the same two endpoints
(IP address + port) for the same protocol, in either direction, across the
whole capture. It is NOT a reconstructed TCP session: SYN/FIN boundaries
are ignored, so two connections that reuse identical ports become one row.
"""

import sqlite3


def flow_key(protocol, src_ip, src_port, dst_ip, dst_port):
    """Return (protocol, endpoint_a, endpoint_b, packet_goes_a_to_b).

    Sorting the two endpoints gives both directions the same key. The
    smaller (ip, port) pair is endpoint "a". The comparison is a plain
    text/number sort, the same as the SQL version in queries.py.
    """
    source = (src_ip, src_port)
    destination = (dst_ip, dst_port)
    endpoint_a, endpoint_b = sorted((source, destination))
    return protocol, endpoint_a, endpoint_b, source == endpoint_a


def rebuild_flows(db_path) -> int:
    """Rebuild TCP/UDP conversation summaries from stored packets."""
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    try:
        with connection:
            connection.execute("DELETE FROM flows")

            packets = connection.execute("""
                SELECT protocol, src_ip, src_port, dst_ip, dst_port,
                       ts, length
                FROM packets
                WHERE protocol IN ('TCP', 'UDP')
                  AND src_ip IS NOT NULL
                  AND dst_ip IS NOT NULL
                  AND src_port IS NOT NULL
                  AND dst_port IS NOT NULL
            """)

            flows = {}

            for packet in packets:
                protocol, endpoint_a, endpoint_b, a_to_b = flow_key(
                    packet["protocol"],
                    packet["src_ip"], packet["src_port"],
                    packet["dst_ip"], packet["dst_port"],
                )
                key = (protocol, endpoint_a, endpoint_b)

                if key not in flows:
                    flows[key] = {
                        "start": packet["ts"],
                        "end": packet["ts"],
                        "packets": [0, 0],
                        "bytes": [0, 0],
                    }

                flow = flows[key]
                # min/max (not first/last) handles out-of-order timestamps.
                flow["start"] = min(flow["start"], packet["ts"])
                flow["end"] = max(flow["end"], packet["ts"])
                direction = 0 if a_to_b else 1
                flow["packets"][direction] += 1
                flow["bytes"][direction] += packet["length"]

            rows = []

            for (protocol, endpoint_a, endpoint_b), flow in flows.items():
                rows.append((
                    protocol,
                    endpoint_a[0],
                    endpoint_a[1],
                    endpoint_b[0],
                    endpoint_b[1],
                    flow["start"],
                    flow["end"],
                    flow["end"] - flow["start"],
                    sum(flow["packets"]),
                    sum(flow["bytes"]),
                    flow["packets"][0],
                    flow["packets"][1],
                    flow["bytes"][0],
                    flow["bytes"][1],
                ))

            connection.executemany("""
                INSERT INTO flows (
                    protocol, a_ip, a_port, b_ip, b_port,
                    start_ts, end_ts, duration, packet_count, byte_count,
                    packets_a_to_b, packets_b_to_a,
                    bytes_a_to_b, bytes_b_to_a
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)

        return len(rows)
    finally:
        connection.close()
