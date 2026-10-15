from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap


output = Path(__file__).resolve().parent.parent / "data/samples/demo.pcap"
output.parent.mkdir(parents=True, exist_ok=True)

ethernet = Ether(
    src="02:00:00:00:00:01",
    dst="02:00:00:00:00:02",
)

packets = [
    ethernet / IP(src="192.0.2.1", dst="192.0.2.2")
    / TCP(sport=50000, dport=80, flags="S"),

    ethernet / IP(src="192.0.2.1", dst="192.0.2.2")
    / UDP(sport=50001, dport=53),

    ethernet / IP(src="192.0.2.1", dst="192.0.2.2")
    / ICMP(type=8),

    ethernet / ARP(
        hwsrc="02:00:00:00:00:01",
        hwdst="02:00:00:00:00:02",
        psrc="192.0.2.1",
        pdst="192.0.2.2",
        op=2,
    ),
    Ether(
        src="02:00:00:00:00:02",
        dst="02:00:00:00:00:01",
    )
    / IP(src="192.0.2.2", dst="192.0.2.1")
    / TCP(sport=80, dport=50000, flags="SA"),
]

for index, packet in enumerate(packets):
    packet.time = 1700000000 + index

wrpcap(str(output), packets)
print(f"Created {output} with {len(packets)} packets")