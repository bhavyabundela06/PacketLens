"""Parser field extraction, including IPv6 and edge cases."""

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    ICMPv6DestUnreach,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    IPv6,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
)
from scapy.layers.l2 import Dot1Q, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from packetlens.parser import CaptureReadError, parse_packet, read_packets

from .conftest import DEMO_PCAP

ETH = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
REV = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")


def roundtrip(tmp_path, packets):
    """Write packets to a pcap and parse them back, like a real import."""
    for index, packet in enumerate(packets):
        packet.time = 1_700_000_000 + index
    capture = tmp_path / "t.pcap"
    wrpcap(str(capture), packets)
    return list(read_packets(capture))


def test_demo_capture_fields():
    records = list(read_packets(DEMO_PCAP))

    assert [row["protocol"] for row in records] == [
        "TCP", "UDP", "ICMP", "ARP", "TCP"
    ]
    assert records[0]["src_ip"] == "192.0.2.1"
    assert records[0]["dst_port"] == 80
    assert records[0]["tcp_flags"] == 2          # SYN
    assert records[1]["dst_port"] == 53
    assert records[1]["tcp_flags"] is None
    assert records[2]["src_port"] is None
    assert records[2]["icmp_type"] == 8          # echo request
    assert records[3]["ip_version"] is None      # ARP is not IP
    assert records[4]["src_port"] == 80
    assert records[4]["tcp_flags"] == 18         # SYN + ACK
    assert [row["ts"] for row in records] == [
        1_700_000_000 + index for index in range(5)
    ]

    for row in records:
        assert row["length"] == row["wire_length"]
        assert row["src_mac"] is not None


def test_ipv6_basic(tmp_path):
    source, destination = "2001:db8::1", "2001:db8::2"
    records = roundtrip(tmp_path, [
        ETH / IPv6(src=source, dst=destination, hlim=64)
        / TCP(sport=50000, dport=443, flags="S"),
        ETH / IPv6(src=source, dst=destination, hlim=64)
        / UDP(sport=50001, dport=53),
        ETH / IPv6(src=source, dst=destination, hlim=64)
        / ICMPv6EchoRequest(id=1, seq=1),
        REV / IPv6(src=destination, dst=source, hlim=64)
        / ICMPv6EchoReply(id=1, seq=1),
    ])

    assert [row["protocol"] for row in records] == [
        "TCP", "UDP", "ICMPv6", "ICMPv6"
    ]
    assert [row["icmp_type"] for row in records[2:]] == [128, 129]
    assert records[3]["src_ip"] == destination
    for row in records:
        assert row["ip_version"] == 6
        assert row["ttl"] == 64
    for row in records[2:]:
        assert row["src_port"] is None and row["tcp_flags"] is None


def test_ipv6_extension_headers(tmp_path):
    network = IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=64)
    records = roundtrip(tmp_path, [
        ETH / network / IPv6ExtHdrHopByHop()
        / TCP(sport=50000, dport=443, flags="S"),
        ETH / network / IPv6ExtHdrDestOpt() / UDP(sport=50001, dport=53),
        ETH / network / IPv6ExtHdrRouting() / ICMPv6EchoRequest(id=1, seq=1),
        ETH / network / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt()
        / ICMPv6EchoRequest(id=1, seq=2),
        ETH / network / IPv6ExtHdrFragment(nh=58, offset=1, m=0, id=123)
        / Raw(b"fragment"),
        ETH / network / IPv6ExtHdrFragment(nh=6, offset=0, m=1, id=124)
        / TCP(sport=50002, dport=22, flags="S"),
    ])

    assert [row["protocol"] for row in records] == [
        "TCP", "UDP", "ICMPv6", "ICMPv6", "OTHER", "TCP"
    ]
    assert records[0]["dst_port"] == 443
    assert records[1]["dst_port"] == 53
    # Non-initial fragment: protocol number known, but no invented ports.
    assert records[4]["ip_proto"] == 58
    assert records[4]["is_fragment"] == 1
    assert records[4]["src_port"] is None
    # First fragment: transport header is present.
    assert records[5]["is_fragment"] == 1
    assert records[5]["dst_port"] == 22
    for row in records[:4]:
        assert row["is_fragment"] == 0


def test_ipv4_fragments_only_first_has_ports(tmp_path):
    from scapy.layers.inet import fragment

    big = IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=1, dport=53) \
        / Raw(b"x" * 2500)
    records = roundtrip(tmp_path, [ETH / piece for piece in fragment(big, 1000)])

    assert len(records) == 3
    assert all(row["is_fragment"] == 1 for row in records)
    assert records[0]["protocol"] == "UDP" and records[0]["dst_port"] == 53
    for row in records[1:]:
        assert row["protocol"] == "OTHER"
        assert row["src_port"] is None and row["dst_port"] is None
        assert row["ip_proto"] == 17


def test_icmp_error_does_not_use_quoted_ports(tmp_path):
    quoted = IP(src="192.0.2.1", dst="203.0.113.5") / UDP(sport=5353, dport=53)
    records = roundtrip(tmp_path, [
        REV / IP(src="198.51.100.1", dst="192.0.2.1")
        / ICMP(type=3, code=3) / quoted,
        REV / IPv6(src="2001:db8::9", dst="2001:db8::1") / ICMPv6DestUnreach()
        / IPv6(src="2001:db8::1", dst="2001:db8::5") / TCP(sport=1, dport=22),
    ])

    assert records[0]["protocol"] == "ICMP"
    assert (records[0]["src_ip"], records[0]["dst_ip"]) == (
        "198.51.100.1", "192.0.2.1"
    )
    assert (records[0]["icmp_type"], records[0]["icmp_code"]) == (3, 3)
    assert records[1]["protocol"] == "ICMPv6"
    assert records[1]["icmp_type"] == 1
    for row in records:
        assert row["src_port"] is None and row["dst_port"] is None


def test_ip_in_ip_keeps_outer_header_only(tmp_path):
    records = roundtrip(tmp_path, [
        ETH / IP(src="192.0.2.1", dst="192.0.2.2")
        / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2),
    ])

    row = records[0]
    assert (row["src_ip"], row["dst_ip"]) == ("192.0.2.1", "192.0.2.2")
    assert row["protocol"] == "OTHER"
    assert row["ip_proto"] == 4
    assert row["src_port"] is None


def test_vlan_tagged_packet(tmp_path):
    records = roundtrip(tmp_path, [
        ETH / Dot1Q(vlan=10) / IP(src="192.0.2.1", dst="192.0.2.2")
        / TCP(sport=1234, dport=80, flags="S"),
    ])
    assert records[0]["protocol"] == "TCP"
    assert records[0]["dst_port"] == 80


def test_truncated_packet_records_both_lengths(tmp_path):
    full = ETH / IP(src="192.0.2.1", dst="192.0.2.2") \
        / TCP(sport=1, dport=80, flags="PA") / Raw(b"y" * 200)
    cut = Ether(bytes(full)[:40])
    cut.wirelen = len(full)
    row = roundtrip(tmp_path, [cut])[0]

    assert row["length"] == 40
    assert row["wire_length"] == len(full)
    # The TCP header was cut off: no ports are guessed.
    assert row["protocol"] == "OTHER"
    assert row["src_port"] is None
    assert row["ip_proto"] == 6


def test_application_labels(tmp_path):
    from scapy.layers.dns import DNS, DNSQR

    records = roundtrip(tmp_path, [
        ETH / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=5000, dport=53)
        / DNS(qd=DNSQR(qname="example.")),
        ETH / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=5000, dport=8080)
        / Raw(b"GET / HTTP/1.1\r\n\r\n"),
        ETH / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=5000, dport=80,
                                                         flags="S"),
        ETH / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=5000, dport=7000)
        / Raw(b"\x16\x03\x01\x00\x05hello"),
        ETH / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=5000, dport=7001)
        / Raw(b"unknown"),
    ])

    labels = [(row["l7_proto"], row["l7_basis"]) for row in records]
    assert labels == [
        ("DNS", "payload"),
        ("HTTP", "payload"),     # found by content even on a non-80 port
        ("HTTP", "port"),        # SYN to port 80: only a guess
        ("TLS", "payload"),
        (None, None),            # unknown is fine
    ]


def test_invalid_capture_raises(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"this is not a capture file")
    with pytest.raises(CaptureReadError):
        list(read_packets(bad))


def test_empty_capture(tmp_path):
    empty = tmp_path / "empty.pcap"
    wrpcap(str(empty), [])
    assert list(read_packets(empty)) == []


def test_parse_packet_without_ethernet():
    packet = IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=1, dport=2)
    packet.time = 1.5
    row = parse_packet(packet)
    assert row["src_mac"] is None
    assert row["protocol"] == "UDP"
    assert row["ts"] == 1.5
