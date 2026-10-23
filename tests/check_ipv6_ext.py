import tempfile
from pathlib import Path

from scapy.layers.inet import TCP, UDP
from scapy.layers.inet6 import (
    IPv6,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    ICMPv6EchoRequest,
)
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from packetlens.parser import read_packets


ethernet = Ether(
    src="02:00:00:00:00:01",
    dst="02:00:00:00:00:02",
)

network = IPv6(
    src="2001:db8::1",
    dst="2001:db8::2",
    hlim=64,
)

packets = [
    ethernet / network / IPv6ExtHdrHopByHop()
    / TCP(sport=50000, dport=443, flags="S"),

    ethernet / network / IPv6ExtHdrDestOpt()
    / UDP(sport=50001, dport=53),

    ethernet / network / IPv6ExtHdrRouting()
    / ICMPv6EchoRequest(id=1, seq=1),

    ethernet / network / IPv6ExtHdrHopByHop()
    / IPv6ExtHdrDestOpt()
    / ICMPv6EchoRequest(id=1, seq=2),

    ethernet / network
    / IPv6ExtHdrFragment(nh=58, offset=1, m=0, id=123)
    / Raw(b"fragment"),
]

for index, packet in enumerate(packets):
    packet.time = 1700000200 + index

with tempfile.TemporaryDirectory() as directory:
    capture = Path(directory) / "extensions.pcap"
    wrpcap(str(capture), packets)
    records = list(read_packets(capture))

assert len(records) == 5
assert [row["protocol"] for row in records] == [
    "TCP", "UDP", "ICMPv6", "ICMPv6", "OTHER"
]

for row in records:
    assert row["ip_version"] == 6
    assert row["src_ip"] == "2001:db8::1"
    assert row["dst_ip"] == "2001:db8::2"
    assert row["ttl"] == 64

assert records[0]["dst_port"] == 443
assert records[0]["tcp_flags"] == 2
assert records[1]["dst_port"] == 53

for row in records[2:]:
    assert row["src_port"] is None
    assert row["dst_port"] is None
    assert row["tcp_flags"] is None

print("IPv6 extension checks passed.")