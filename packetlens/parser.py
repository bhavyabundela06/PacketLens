from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader


def parse_packet(packet) -> dict:
    """Convert one captured packet into a database-ready dictionary."""
    record = {
        "ts": float(packet.time),
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "ip_version": None,
        "src_port": None,
        "dst_port": None,
        "protocol": "OTHER",
        "length": len(bytes(packet)),
        "payload_length": None,
        "ttl": None,
        "tcp_flags": None,
        "tcp_seq": None,
        "tcp_ack": None,
        "tcp_window": None,
        "l7_proto": None,
        "info": packet.summary(),
    }

    if Ether in packet:
        record["src_mac"] = packet[Ether].src
        record["dst_mac"] = packet[Ether].dst

    if IP in packet:
        network = packet[IP]
        record["src_ip"] = network.src
        record["dst_ip"] = network.dst
        record["ip_version"] = 4
        record["ttl"] = int(network.ttl)

    elif IPv6 in packet:
        network = packet[IPv6]
        record["src_ip"] = network.src
        record["dst_ip"] = network.dst
        record["ip_version"] = 6
        record["ttl"] = int(network.hlim)

    elif ARP in packet:
        record["protocol"] = "ARP"

    if TCP in packet:
        transport = packet[TCP]
        record["protocol"] = "TCP"
        record["src_port"] = int(transport.sport)
        record["dst_port"] = int(transport.dport)
        record["payload_length"] = len(bytes(transport.payload))
        record["tcp_flags"] = int(transport.flags)
        record["tcp_seq"] = int(transport.seq)
        record["tcp_ack"] = int(transport.ack)
        record["tcp_window"] = int(transport.window)

    elif UDP in packet:
        transport = packet[UDP]
        record["protocol"] = "UDP"
        record["src_port"] = int(transport.sport)
        record["dst_port"] = int(transport.dport)
        record["payload_length"] = len(bytes(transport.payload))

    elif ICMP in packet:
        record["protocol"] = "ICMP"

    return record


def read_packets(pcap_path):
    """Yield one parsed packet at a time from a capture file."""
    with PcapReader(str(pcap_path)) as capture:
        for packet in capture:
            yield parse_packet(packet)