import sqlite3
from pathlib import Path

from packetlens.hosts import rebuild_hosts


db_path = (
    Path(__file__).resolve().parent.parent
    / "data/output/demo_with_hosts.db"
)

assert db_path.is_file(), "Run ingestion for demo_with_hosts.db first."

assert rebuild_hosts(db_path) == 2
assert rebuild_hosts(db_path) == 2

connection = sqlite3.connect(db_path)
connection.row_factory = sqlite3.Row

try:
    hosts = {
        row["ip"]: row
        for row in connection.execute("SELECT * FROM hosts")
    }

    first = hosts["192.0.2.1"]
    second = hosts["192.0.2.2"]

    assert (first["pkts_sent"], first["pkts_recv"]) == (3, 1)
    assert (second["pkts_sent"], second["pkts_recv"]) == (1, 3)

    # Captured Ethernet frame sizes:
    # TCP = 54 bytes, UDP = 42 bytes, ICMP = 42 bytes.
    assert first["bytes_sent"] == 138
    assert first["bytes_recv"] == 54
    assert second["bytes_sent"] == 54
    assert second["bytes_recv"] == 138

    for host in hosts.values():
        assert host["first_seen"] == 1700000000
        assert host["last_seen"] == 1700000004

    print("Host checks passed: counts, bytes, timestamps, and rebuilds.")
finally:
    connection.close()