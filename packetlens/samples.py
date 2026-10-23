"""Deterministic synthetic captures for tests and demonstrations.

Nothing here sends traffic: packets are only built in memory and written
to .pcap files. Every packet has explicit MAC addresses, so Scapy never
tries to look anything up on the local network.

Addresses come only from documentation ranges (RFC 5737 / RFC 3849):
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32.
Timestamps are fixed offsets from BASE_TS, and payloads are synthetic.

Run:  python -m packetlens.samples data/samples
It writes one .pcap per scenario plus manifest.json, which lists the
expected packet count and which alerts should (and should not) appear
with the DEFAULT DetectionConfig.
"""

import argparse
import json
import sys
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP, fragment
from scapy.layers.inet6 import (
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    IPv6,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
)
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

BASE_TS = 1_700_000_000.0  # 2023-11-14 22:13:20 UTC

CLIENT = "192.0.2.10"
SERVER = "198.51.100.20"
DNS_SERVER = "198.51.100.53"
SCANNER = "203.0.113.66"
SWEEPER = "203.0.113.77"
CLIENT6 = "2001:db8::10"
SERVER6 = "2001:db8::20"
SCANNER6 = "2001:db8:bad::66"

MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"


def _eth(forward=True):
    if forward:
        return Ether(src=MAC_A, dst=MAC_B)
    return Ether(src=MAC_B, dst=MAC_A)


def _stamp(packets_with_offsets):
    """Set packet.time = BASE_TS + offset and return the packet list."""
    result = []
    for offset, packet in packets_with_offsets:
        packet.time = BASE_TS + offset
        result.append(packet)
    return result


def tcp_conversation(client, server, cport, sport, start, request, response,
                     ipv6=False):
    """A complete, ordinary TCP exchange: handshake, data, and close."""
    L3 = IPv6 if ipv6 else IP

    def c2s(flags, seq, ack, data=b""):
        pkt = _eth() / L3(src=client, dst=server) / TCP(
            sport=cport, dport=sport, flags=flags, seq=seq, ack=ack)
        return pkt / Raw(data) if data else pkt

    def s2c(flags, seq, ack, data=b""):
        pkt = _eth(False) / L3(src=server, dst=client) / TCP(
            sport=sport, dport=cport, flags=flags, seq=seq, ack=ack)
        return pkt / Raw(data) if data else pkt

    c, s = 1000, 5000
    return [
        (start + 0.000, c2s("S", c, 0)),
        (start + 0.010, s2c("SA", s, c + 1)),
        (start + 0.020, c2s("A", c + 1, s + 1)),
        (start + 0.030, c2s("PA", c + 1, s + 1, request)),
        (start + 0.050, s2c("PA", s + 1, c + 1 + len(request), response)),
        (start + 0.060, c2s("FA", c + 1 + len(request), s + 1 + len(response))),
        (start + 0.070, s2c("FA", s + 1 + len(response), c + 2 + len(request))),
        (start + 0.080, c2s("A", c + 2 + len(request), s + 2 + len(response))),
    ]


def normal_traffic():
    """Ordinary mixed traffic. Expected alerts: none."""
    http_request = (b"GET /index.html HTTP/1.1\r\nHost: www.example\r\n"
                    b"User-Agent: packetlens-sample\r\n\r\n")
    http_response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                     b"Content-Length: 29\r\n\r\n<html>synthetic page</html>\r\n")
    # Bytes shaped like a TLS ClientHello record header; contents synthetic.
    tls_hello = bytes([0x16, 0x03, 0x01, 0x00, 0x2a]) + b"\x01" + b"\x00" * 41
    tls_reply = bytes([0x16, 0x03, 0x03, 0x00, 0x10]) + b"\x02" + b"\x00" * 15

    items = []
    items += tcp_conversation(CLIENT, SERVER, 49152, 80, 0.0,
                              http_request, http_response)
    items += tcp_conversation(CLIENT, SERVER, 49153, 443, 1.0,
                              tls_hello, tls_reply)
    items += [
        (2.000, _eth() / IP(src=CLIENT, dst=DNS_SERVER)
         / UDP(sport=53001, dport=53)
         / DNS(id=7, rd=1, qd=DNSQR(qname="www.example.", qtype="A"))),
        (2.020, _eth(False) / IP(src=DNS_SERVER, dst=CLIENT)
         / UDP(sport=53, dport=53001)
         / DNS(id=7, qr=1, rd=1, ra=1,
               qd=DNSQR(qname="www.example.", qtype="A"),
               an=DNSRR(rrname="www.example.", type="A", rdata=SERVER))),
        (3.000, _eth() / IP(src=CLIENT, dst=SERVER) / ICMP(type=8, id=1, seq=1)
         / Raw(b"synthetic-ping")),
        (3.010, _eth(False) / IP(src=SERVER, dst=CLIENT)
         / ICMP(type=0, id=1, seq=1) / Raw(b"synthetic-ping")),
        (4.000, Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff")
         / ARP(op=1, hwsrc=MAC_A, psrc=CLIENT, pdst="192.0.2.1")),
        (4.001, Ether(src=MAC_B, dst=MAC_A)
         / ARP(op=2, hwsrc=MAC_B, hwdst=MAC_A, psrc="192.0.2.1", pdst=CLIENT)),
        (5.000, _eth() / IP(src=CLIENT, dst=SERVER) / UDP(sport=123, dport=123)
         / Raw(b"\x23" + b"\x00" * 47)),
    ]
    items += tcp_conversation(CLIENT6, SERVER6, 50000, 80, 6.0,
                              http_request, http_response, ipv6=True)
    items += [
        (7.000, _eth() / IPv6(src=CLIENT6, dst=SERVER6)
         / ICMPv6EchoRequest(id=2, seq=1, data=b"synthetic")),
        (7.010, _eth(False) / IPv6(src=SERVER6, dst=CLIENT6)
         / ICMPv6EchoReply(id=2, seq=1, data=b"synthetic")),
    ]
    return _stamp(items)


def port_scan():
    """IPv4 and IPv6 SYN scans of one host each. Expected: 2 port_scan."""
    items = []
    # 30 ports in 2.9 s on one IPv4 target; closed ports answer with RST.
    for index, port in enumerate(range(20, 50)):
        t = index * 0.1
        items.append((t, _eth() / IP(src=SCANNER, dst=SERVER)
                      / TCP(sport=40000, dport=port, flags="S", seq=index)))
        items.append((t + 0.001, _eth(False) / IP(src=SERVER, dst=SCANNER)
                      / TCP(sport=port, dport=40000, flags="RA", ack=index + 1)))
    # 25 ports in 4.8 s on one IPv6 target.
    for index, port in enumerate(range(1000, 1025)):
        items.append((10 + index * 0.2, _eth() / IPv6(src=SCANNER6, dst=SERVER6)
                      / TCP(sport=41000, dport=port, flags="S")))
    # Some unrelated normal traffic in the same capture.
    items += tcp_conversation(CLIENT, SERVER, 49200, 80, 20.0,
                              b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n")
    return _stamp(items)


def host_sweep():
    """ICMP echo sweep of 20 hosts and TCP/22 sweep of 12. Expected: 2."""
    items = []
    for index in range(1, 21):
        target = f"192.0.2.{index}"
        items.append((index * 0.2, _eth() / IP(src=SWEEPER, dst=target)
                      / ICMP(type=8, id=9, seq=index)))
        if index % 4 == 0:  # only some hosts answer
            items.append((index * 0.2 + 0.002, _eth(False)
                          / IP(src=target, dst=SWEEPER)
                          / ICMP(type=0, id=9, seq=index)))
    for index in range(1, 13):
        items.append((30 + index * 0.5, _eth()
                      / IP(src=SWEEPER, dst=f"198.51.100.{index}")
                      / TCP(sport=42000 + index, dport=22, flags="S")))
    return _stamp(items)


def traffic_burst():
    """A legitimate large transfer: 2000 data packets in 2 s. Expected: none.

    Lots of packets and bytes, but all within ONE established conversation,
    so neither scan rule applies. Around it, 30 s of quiet background
    traffic (one ping and reply per second) gives the traffic-volume chart
    a baseline, so the burst at t = 10-12 s stands out.
    """
    items = []
    for second in range(30):
        items.append((second, _eth() / IP(src=CLIENT, dst=SERVER)
                      / ICMP(type=8, id=5, seq=second)))
        items.append((second + 0.001, _eth(False) / IP(src=SERVER, dst=CLIENT)
                      / ICMP(type=0, id=5, seq=second)))
    items += tcp_conversation(CLIENT, SERVER, 49300, 443, 9.0,
                              bytes([0x16, 0x03, 0x01, 0x00, 0x05]) + b"hello",
                              bytes([0x16, 0x03, 0x03, 0x00, 0x05]) + b"world")
    chunk = bytes([0x17, 0x03, 0x03, 0x03, 0xe3]) + b"\xaa" * 995
    for index in range(2000):
        items.append((10.0 + index * 0.001, _eth(False)
                      / IP(src=SERVER, dst=CLIENT)
                      / TCP(sport=443, dport=49300, flags="PA",
                            seq=10_000 + index * 1000, ack=2000)
                      / Raw(chunk)))
        if index % 10 == 9:
            items.append((10.0 + index * 0.001 + 0.0005, _eth()
                          / IP(src=CLIENT, dst=SERVER)
                          / TCP(sport=49300, dport=443, flags="A",
                                seq=2000, ack=10_000 + (index + 1) * 1000)))
    return _stamp(items)


def edge_cases():
    """Parser edge cases. Expected alerts: none."""
    items = []

    # IPv6 with extension headers before TCP and UDP.
    items.append((0.0, _eth() / IPv6(src=CLIENT6, dst=SERVER6)
                  / IPv6ExtHdrHopByHop() / TCP(sport=50100, dport=443, flags="S")))
    items.append((0.1, _eth() / IPv6(src=CLIENT6, dst=SERVER6)
                  / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt()
                  / UDP(sport=50101, dport=53)))

    # IPv6 fragments: the first carries the UDP header, the second does not.
    items.append((0.2, _eth() / IPv6(src=CLIENT6, dst=SERVER6)
                  / IPv6ExtHdrFragment(nh=17, offset=0, m=1, id=77)
                  / UDP(sport=50102, dport=9999) / Raw(b"A" * 32)))
    items.append((0.3, _eth() / IPv6(src=CLIENT6, dst=SERVER6)
                  / IPv6ExtHdrFragment(nh=17, offset=5, m=0, id=77)
                  / Raw(b"B" * 32)))

    # IPv4 fragments of one UDP datagram.
    big = (_eth() / IP(src=CLIENT, dst=SERVER, id=4242)
           / UDP(sport=50200, dport=9999) / Raw(b"C" * 2400))
    for index, piece in enumerate(fragment(big, fragsize=1000)):
        items.append((0.4 + index * 0.01, _eth() / piece[IP]))

    # ICMP "port unreachable" that QUOTES the UDP packet that caused it.
    # The outer packet is SERVER -> CLIENT ICMP; the quoted ports must not
    # be stored as this packet's ports.
    quoted = IP(src=CLIENT, dst=SERVER) / UDP(sport=50300, dport=33434)
    items.append((0.5, _eth(False) / IP(src=SERVER, dst=CLIENT)
                  / ICMP(type=3, code=3) / quoted))

    # IP-in-IP tunnel: outer 192.0.2.x addresses, inner TCP must be ignored.
    items.append((0.6, _eth() / IP(src="192.0.2.1", dst="192.0.2.2")
                  / IP(src="198.51.100.1", dst="198.51.100.2")
                  / TCP(sport=1111, dport=2222, flags="S")))

    # A packet truncated by the capture's snapshot length.
    full = (_eth() / IP(src=CLIENT, dst=SERVER)
            / TCP(sport=50400, dport=80, flags="PA") / Raw(b"GET /" + b"x" * 200))
    truncated = Ether(bytes(full)[:40])
    truncated.wirelen = len(full)
    items.append((0.7, truncated))

    # Out-of-order timestamp: written last, but earlier than everything.
    items.append((-1.0, _eth() / IP(src=CLIENT, dst=SERVER)
                  / UDP(sport=50500, dport=5000) / Raw(b"late-written")))

    # Text that needs escaping in XML/HTML lives in the payload; the
    # summary ("info") field stays plain ASCII produced by Scapy.
    items.append((0.8, _eth() / IP(src=CLIENT, dst=SERVER)
                  / UDP(sport=50600, dport=5001) / Raw(b"<b>&\x00</b>")))
    return _stamp(items)


def near_threshold():
    """Benign patterns just below the default thresholds. Expected: none.

    Default thresholds: port_scan 20 ports / 10 s, host_sweep 10 hosts / 10 s.
    """
    items = []
    # 19 distinct ports in 9 s: one below the port-scan threshold.
    for index in range(19):
        items.append((index * 0.5, _eth() / IP(src=CLIENT, dst=SERVER)
                      / TCP(sport=51000 + index, dport=8000 + index, flags="S")))
    # 20 distinct ports, but split 10 + 10 with a 20 s gap: never 20 in
    # one window.
    for index in range(10):
        items.append((30 + index * 0.1, _eth() / IP(src=CLIENT, dst="198.51.100.21")
                      / TCP(sport=52000 + index, dport=9000 + index, flags="S")))
        items.append((60 + index * 0.1, _eth() / IP(src=CLIENT, dst="198.51.100.21")
                      / TCP(sport=52100 + index, dport=9100 + index, flags="S")))
    # A server answering many ports with SYN+ACK: ACK is set, so these are
    # replies, not connection attempts.
    for index in range(30):
        items.append((90 + index * 0.1, _eth(False) / IP(src=SERVER, dst=CLIENT)
                      / TCP(sport=443, dport=53000 + index, flags="SA")))
    # 9 hosts pinged in 4 s: one below the host-sweep threshold.
    for index in range(1, 10):
        items.append((120 + index * 0.5, _eth()
                      / IP(src="192.0.2.200", dst=f"198.51.100.{index}")
                      / ICMP(type=8, id=3, seq=index)))
    # Many UDP packets to many ports (e.g. a media session): UDP is not
    # counted by either rule.
    for index in range(40):
        items.append((150 + index * 0.05, _eth() / IP(src=CLIENT, dst=SERVER)
                      / UDP(sport=54000, dport=10000 + index) / Raw(b"rtp")))
    return _stamp(items)


SCENARIOS = {
    "normal": (normal_traffic, [], "Mixed TCP/UDP/ICMP/ARP/DNS/HTTP/TLS and IPv6 request/reply traffic."),
    "port_scan": (port_scan, [
        {"rule": "port_scan", "src_ip": SCANNER, "dst_ip": SERVER},
        {"rule": "port_scan", "src_ip": SCANNER6, "dst_ip": SERVER6},
    ], "SYN scans of 30 IPv4 ports and 25 IPv6 ports, plus one normal HTTP exchange."),
    "host_sweep": (host_sweep, [
        {"rule": "host_sweep", "src_ip": SWEEPER, "dst_ip": None},
        {"rule": "host_sweep", "src_ip": SWEEPER, "dst_ip": None},
    ], "ICMP echo sweep of 20 hosts, then a TCP/22 SYN sweep of 12 hosts 30 s later."),
    "burst": (traffic_burst, [], "Legitimate 2000-packet TLS-like transfer in about 2 s at t=10 s, over 30 s of one-ping-per-second background traffic."),
    "edge_cases": (edge_cases, [], "IPv6 extension headers, IPv4/IPv6 fragments, ICMP error with a quoted packet, IP-in-IP, a truncated packet, an out-of-order timestamp."),
    "near_threshold": (near_threshold, [], "Benign patterns just below default thresholds, SYN+ACK replies, UDP to many ports."),
}


def write_samples(directory, overwrite=False):
    """Write every scenario and manifest.json into directory."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {
        "detection_config": "default (port_scan 20 ports/10 s, host_sweep 10 hosts/10 s)",
        "base_ts": BASE_TS,
        "captures": {},
    }

    for name, (builder, expected_alerts, description) in SCENARIOS.items():
        path = directory / f"{name}.pcap"
        packets = builder()

        if path.exists() and not overwrite:
            raise FileExistsError(f"{path} exists (use --overwrite)")

        wrpcap(str(path), packets)
        manifest["captures"][path.name] = {
            "description": description,
            "packets": len(packets),
            "expected_alerts": expected_alerts,
            "expected_alert_count": len(expected_alerts),
        }

    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("directory", type=Path, nargs="?",
                        default=Path("data/samples"))
    parser.add_argument("--overwrite", action="store_true",
                        help="replace existing sample files")
    args = parser.parse_args(argv)

    try:
        manifest = write_samples(args.directory, args.overwrite)
    except FileExistsError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    for name, entry in manifest["captures"].items():
        print(f"{name}: {entry['packets']} packets, "
              f"{entry['expected_alert_count']} expected alerts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
