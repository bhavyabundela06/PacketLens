import sqlite3

def rebuild_hosts(db_path) -> int:
    """Rebuild per-IP summaries from stored packets."""
    connection = sqlite3.connect(db_path)

    try:
        with connection:
            connection.execute("DELETE FROM hosts")

            connection.execute("""
                INSERT INTO hosts (
                    ip, pkts_sent, pkts_recv,
                    bytes_sent, bytes_recv,
                    first_seen, last_seen
                )
                SELECT
                    ip,
                    SUM(pkts_sent),
                    SUM(pkts_recv),
                    SUM(bytes_sent),
                    SUM(bytes_recv),
                    MIN(ts),
                    MAX(ts)
                FROM (
                    SELECT
                        src_ip AS ip,
                        1 AS pkts_sent,
                        0 AS pkts_recv,
                        length AS bytes_sent,
                        0 AS bytes_recv,
                        ts
                    FROM packets
                    WHERE src_ip IS NOT NULL

                    UNION ALL

                    SELECT
                        dst_ip AS ip,
                        0 AS pkts_sent,
                        1 AS pkts_recv,
                        0 AS bytes_sent,
                        length AS bytes_recv,
                        ts
                    FROM packets
                    WHERE dst_ip IS NOT NULL
                ) AS activity
                GROUP BY ip
            """)

            count = connection.execute(
                "SELECT COUNT(*) FROM hosts"
            ).fetchone()[0]

        return count
    finally:
        connection.close()