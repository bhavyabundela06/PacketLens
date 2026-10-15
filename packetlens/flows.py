import sqlite3


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
                source = (packet["src_ip"], packet["src_port"])
                destination = (packet["dst_ip"], packet["dst_port"])

                # Canonical order makes both directions use the same key.
                endpoint_a, endpoint_b = sorted((source, destination))
                key = (packet["protocol"], endpoint_a, endpoint_b)

                if key not in flows:
                    flows[key] = {
                        "start": packet["ts"],
                        "end": packet["ts"],
                        "packets": 0,
                        "bytes": 0,
                    }

                flow = flows[key]
                flow["start"] = min(flow["start"], packet["ts"])
                flow["end"] = max(flow["end"], packet["ts"])
                flow["packets"] += 1
                flow["bytes"] += packet["length"]

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
                    flow["packets"],
                    flow["bytes"],
                ))

            connection.executemany("""
                INSERT INTO flows (
                    protocol, a_ip, a_port, b_ip, b_port,
                    start_ts, end_ts, duration, packet_count, byte_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)

        return len(rows)
    finally:
        connection.close()