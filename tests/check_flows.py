import sqlite3
import tempfile
from pathlib import Path

from packetlens.flows import rebuild_flows
from packetlens.ingest import ingest_capture

# Self-contained: import the committed demo capture into a temporary database.
_temporary = tempfile.TemporaryDirectory()
db_path = Path(_temporary.name) / "demo.db"
ingest_capture(
    Path(__file__).resolve().parent.parent / "data/samples/demo.pcap", db_path
)


# Repeating the rebuild must not duplicate the summaries.
assert rebuild_flows(db_path) == 2
assert rebuild_flows(db_path) == 2

connection = sqlite3.connect(db_path)
connection.row_factory = sqlite3.Row

try:
    tcp = connection.execute(
        "SELECT * FROM flows WHERE protocol = 'TCP'"
    ).fetchone()

    assert tcp is not None
    assert tcp["a_ip"] == "192.0.2.1"
    assert tcp["a_port"] == 50000
    assert tcp["b_ip"] == "192.0.2.2"
    assert tcp["b_port"] == 80
    assert tcp["packet_count"] == 2
    assert tcp["duration"] == 4.0

    expected_bytes = connection.execute(
        "SELECT SUM(length) FROM packets WHERE protocol = 'TCP'"
    ).fetchone()[0]

    assert tcp["byte_count"] == expected_bytes

    print("Flow checks passed: both TCP directions share one flow.")
finally:
    connection.close()