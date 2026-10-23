"""Time each pipeline stage on a synthetic capture of a chosen size.

Usage:  python -m tests.benchmark [PACKETS]      (default 50000)

Everything is written to a temporary directory and removed afterwards.
Numbers depend on the machine; report them with the packet count.
"""

import sys
import tempfile
import time
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter

from packetlens import queries
from packetlens.database import connect
from packetlens.detection import run_detection
from packetlens.ingest import ingest_capture
from packetlens.queries import PacketFilter
from packetlens.report import build_report
from packetlens.xml_export import export_xml


def make_capture(path, count):
    """Mixed TCP/UDP traffic between 50 clients and 5 servers."""
    eth = Ether(src="02:00:00:00:00:0a", dst="02:00:00:00:00:0b")
    with PcapWriter(str(path)) as writer:
        for index in range(count):
            client = f"192.0.2.{index % 50 + 1}"
            server = f"198.51.100.{index % 5 + 1}"
            if index % 3:
                packet = eth / IP(src=client, dst=server) / TCP(
                    sport=40000 + index % 1000, dport=443, flags="PA") / Raw(b"x" * 200)
            else:
                packet = eth / IP(src=client, dst=server) / UDP(
                    sport=50000 + index % 1000, dport=53) / Raw(b"y" * 60)
            packet.time = 1_700_000_000 + index * 0.001
            writer.write(packet)


def timed(label, function):
    start = time.perf_counter()
    result = function()
    print(f"{label:<34} {time.perf_counter() - start:8.2f} s")
    return result


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 50_000

    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        capture = directory / "bench.pcap"
        database = directory / "bench.db"

        print(f"Synthetic capture: {count} packets")
        timed("build capture (not PacketLens)", lambda: make_capture(capture, count))
        print(f"capture size: {capture.stat().st_size / 1e6:.1f} MB")
        timed("ingest (parse+insert+summaries)", lambda: ingest_capture(capture, database))
        timed("detection rerun", lambda: run_detection(database))

        connection = connect(database, read_only=True)
        timed("summary + protocols (unfiltered)", lambda: (
            queries.summary(connection), queries.protocol_distribution(connection)))
        timed("conversations (filtered port 53)", lambda: queries.conversations(
            connection, PacketFilter(port=53)))
        timed("timeline, 1 s buckets", lambda: queries.traffic_timeline(connection))
        connection.close()

        timed("HTML report", lambda: build_report(database))
        timed("XML export", lambda: export_xml(database, directory / "bench.xml"))
        print(f"database size: {database.stat().st_size / 1e6:.1f} MB, "
              f"XML size: {(directory / 'bench.xml').stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
