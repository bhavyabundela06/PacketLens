from pathlib import Path

from packetlens.parser import read_packets


capture = Path(__file__).resolve().parent.parent / "data/samples/demo.pcap"
records = list(read_packets(capture))

assert len(records) == 5
assert [row["protocol"] for row in records] == [
    "TCP", "UDP", "ICMP", "ARP", "TCP"
]

assert records[0]["src_ip"] == "192.0.2.1"
assert records[0]["dst_port"] == 80
assert records[0]["tcp_flags"] == 2  # SYN flag

assert records[1]["dst_port"] == 53
assert records[1]["tcp_flags"] is None

assert records[2]["src_port"] is None
assert records[3]["ip_version"] is None

assert records[4]["src_ip"] == "192.0.2.2"
assert records[4]["src_port"] == 80
assert records[4]["dst_port"] == 50000
assert records[4]["tcp_flags"] == 18  # SYN + ACK

for row in records:
    print(row["protocol"], row["src_ip"], row["dst_port"])

print("Parser checks passed")