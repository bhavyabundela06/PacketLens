import tempfile
from pathlib import Path

from scapy.layers.inet import TCP, UDP
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
)
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from packetlens.parser import read_packets


source = "2001:db8::1"
destination = "2001:db8::2"

forward = Ether(
    src="02:00:00:00:00:01",
    dst="02:00:00:00:00:02",
)
reverse = Ether(
    src="02:00:00:00:00:02",
    dst="02:00:00:00:00:01",
)

packets = [
    forward / IPv6(src=source, dst=destination, hlim=64)
    / TCP(sport=50000, dport=443, flags="S"),

    forward / IPv6(src=source, dst=destination, hlim=64)
    / UDP(sport=50001, dport=53),

    forward / IPv6(src=source, dst=destination, hlim=64)
    / ICMPv6EchoRequest(id=1, seq=1),

    reverse / IPv6(src=destination, dst=source, hlim=64)
    / ICMPv6EchoReply(id=1, seq=1),
]

for index, packet in enumerate(packets):
    packet.time = 1700000100 + index

with tempfile.TemporaryDirectory() as directory:
    capture = Path(directory) / "ipv6.pcap"
    wrpcap(str(capture), packets)
    records = list(read_packets(capture))

assert len(records) == 4
assert [row["protocol"] for row in records] == [
    "TCP", "UDP", "ICMPv6", "ICMPv6"
]

for index, row in enumerate(records):
    assert row["ip_version"] == 6
    assert row["ttl"] == 64
    assert row["ts"] == 1700000100 + index
    assert row["src_ip"] == (destination if index == 3 else source)
    assert row["dst_ip"] == (source if index == 3 else destination)

assert records[0]["dst_port"] == 443
assert records[0]["tcp_flags"] == 2
assert records[1]["dst_port"] == 53

for row in records[2:]:
    assert row["src_port"] is None
    assert row["dst_port"] is None
    assert row["tcp_flags"] is None

print("IPv6 checks passed: TCP, UDP, ping request, and ping reply.")