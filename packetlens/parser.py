"""Turn captured packets into flat, database-ready dictionaries.

The parser looks only at the OUTERMOST network header of each packet and
the transport header that directly follows it. It deliberately does not
search the whole packet for a TCP/UDP layer, because a packet can contain
other headers further inside it, for example:

- an ICMP error message quotes part of the packet that caused the error;
- an IP-in-IP or 6in4 tunnel carries a complete second IP packet.

Taking ports from those inner headers would mix one packet's addresses
with another packet's ports. See docs/schema.md for every field.

Not supported (documented limitations):
- tunnels/encapsulation (IP-in-IP, 6in4, GRE, VXLAN): only the outer header
  is recorded and the protocol is "OTHER";
- fragment reassembly: each fragment is stored separately, and only the
  first fragment carries transport ports;
- encrypted contents (TLS, SSH, ...): only visible header fields are used;
- truncated captures: fields that were not captured are NULL.
"""

from scapy.error import Scapy_Exception
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    IPv6,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
)
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import PcapReader


class CaptureReadError(Exception):
    """Raised when a file cannot be read as a PCAP/PCAPNG capture."""


IPV6_EXTENSION_HEADERS = (
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
)

# Well-known ports used ONLY as a guess. Rows labelled this way have
# l7_basis = 'port', meaning "this port is usually used for this protocol",
# not "we saw this protocol in the payload".
PORT_GUESSES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "TLS", 546: "DHCPv6", 547: "DHCPv6",
    993: "TLS", 995: "TLS", 5353: "MDNS",
}

HTTP_REQUEST_STARTS = (
    b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ",
    b"PATCH ", b"CONNECT ", b"TRACE ",
)

ICMPV6_PROTOCOL_NUMBER = 58


def ipv6_next_header(ipv6_packet):
    """Follow common extension headers and return the next protocol number.

    Returns None for a non-initial fragment, because the bytes after its
    fragment header are the middle of the original payload, not a header.
    """
    next_header = ipv6_packet.nh
    layer = ipv6_packet.payload

    while isinstance(layer, IPV6_EXTENSION_HEADERS):
        if isinstance(layer, IPv6ExtHdrFragment) and layer.offset != 0:
            # Later fragments don't start with the transport header.
            return None

        next_header = layer.nh
        layer = layer.payload

    return next_header


def _skip_ipv6_extensions(ipv6_packet):
    """Return (layer after extension headers, is_fragment, protocol number).

    For a non-initial fragment the returned layer is None.
    """
    is_fragment = False
    next_header = ipv6_packet.nh
    layer = ipv6_packet.payload

    while isinstance(layer, IPV6_EXTENSION_HEADERS):
        next_header = layer.nh

        if isinstance(layer, IPv6ExtHdrFragment):
            is_fragment = True

            if layer.offset != 0:
                return None, True, next_header

        layer = layer.payload

    return layer, is_fragment, next_header


def _outer_network_layer(packet):
    """Return the first IPv4, IPv6, or ARP layer, searching outside-in.

    Stopping at the FIRST one guarantees we never use an inner (tunnelled
    or quoted) IP header in place of the real outer header.
    """
    layer = packet

    while layer is not None and not isinstance(layer, Raw):
        if isinstance(layer, (IP, IPv6, ARP)):
            return layer

        if not layer.payload:
            return None

        layer = layer.payload

    return None


def _identify_application(record, transport):
    """Set l7_proto and l7_basis conservatively.

    l7_basis = 'payload' -> the payload was checked and looks like it.
    l7_basis = 'port'    -> only a guess from a well-known port number.
    Both NULL            -> unknown.
    """
    payload = transport.payload

    if isinstance(transport, UDP) and isinstance(payload, DNS):
        # Scapy's DNS dissector produced a DNS message without leftover
        # undecoded bytes, so we treat this as confirmed DNS.
        if Raw not in payload:
            record["l7_proto"] = "DNS"
            record["l7_basis"] = "payload"
            return

    if isinstance(transport, TCP) and isinstance(payload, Raw):
        data = bytes(payload)[:16]

        if data.startswith(HTTP_REQUEST_STARTS) or data.startswith(b"HTTP/1."):
            record["l7_proto"] = "HTTP"
            record["l7_basis"] = "payload"
            return

        # TLS record header: content type 0x14-0x17, version 0x03 0x0X.
        if len(data) >= 3 and 0x14 <= data[0] <= 0x17 and data[1] == 0x03:
            record["l7_proto"] = "TLS"
            record["l7_basis"] = "payload"
            return

    for port in (record["dst_port"], record["src_port"]):
        if port in PORT_GUESSES:
            record["l7_proto"] = PORT_GUESSES[port]
            record["l7_basis"] = "port"
            return


def _parse_transport(record, transport):
    """Fill TCP/UDP/ICMP fields from the layer right after the IP header."""
    if isinstance(transport, TCP):
        record["protocol"] = "TCP"
        record["src_port"] = int(transport.sport)
        record["dst_port"] = int(transport.dport)
        record["payload_length"] = len(bytes(transport.payload))
        record["tcp_flags"] = int(transport.flags)
        record["tcp_seq"] = int(transport.seq)
        record["tcp_ack"] = int(transport.ack)
        record["tcp_window"] = int(transport.window)
        _identify_application(record, transport)

    elif isinstance(transport, UDP):
        record["protocol"] = "UDP"
        record["src_port"] = int(transport.sport)
        record["dst_port"] = int(transport.dport)
        record["payload_length"] = len(bytes(transport.payload))
        _identify_application(record, transport)

    elif isinstance(transport, ICMP):
        record["protocol"] = "ICMP"
        record["icmp_type"] = int(transport.type)
        record["icmp_code"] = int(transport.code)


def parse_packet(packet) -> dict:
    """Convert one captured packet into a database-ready dictionary."""
    captured = len(bytes(packet))
    wire_length = getattr(packet, "wirelen", None)

    record = {
        "ts": float(packet.time),
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "ip_version": None,
        "ip_proto": None,
        "src_port": None,
        "dst_port": None,
        "protocol": "OTHER",
        "length": captured,
        "wire_length": int(wire_length) if wire_length else captured,
        "payload_length": None,
        "ttl": None,
        "is_fragment": 0,
        "tcp_flags": None,
        "tcp_seq": None,
        "tcp_ack": None,
        "tcp_window": None,
        "icmp_type": None,
        "icmp_code": None,
        "l7_proto": None,
        "l7_basis": None,
        "info": packet.summary(),
    }

    # Ether is the outermost layer for normal Ethernet captures.
    if isinstance(packet, Ether):
        record["src_mac"] = packet.src
        record["dst_mac"] = packet.dst

    network = _outer_network_layer(packet)

    if isinstance(network, ARP):
        record["protocol"] = "ARP"

    elif isinstance(network, IP):
        record["src_ip"] = network.src
        record["dst_ip"] = network.dst
        record["ip_version"] = 4
        record["ip_proto"] = int(network.proto)
        record["ttl"] = int(network.ttl)

        # MF flag set or non-zero offset means this is a fragment.
        more_fragments = bool(int(network.flags) & 0x1)
        record["is_fragment"] = int(more_fragments or network.frag != 0)

        if network.frag == 0:
            _parse_transport(record, network.payload)

    elif isinstance(network, IPv6):
        record["src_ip"] = network.src
        record["dst_ip"] = network.dst
        record["ip_version"] = 6
        record["ttl"] = int(network.hlim)

        transport, is_fragment, next_header = _skip_ipv6_extensions(network)
        record["is_fragment"] = int(is_fragment)
        record["ip_proto"] = int(next_header)

        if transport is not None:
            if next_header == ICMPV6_PROTOCOL_NUMBER:
                record["protocol"] = "ICMPv6"

                if hasattr(transport, "type") and not isinstance(transport, Raw):
                    record["icmp_type"] = int(transport.type)
                    record["icmp_code"] = int(getattr(transport, "code", 0))
            else:
                _parse_transport(record, transport)

    return record


def read_packets(pcap_path):
    """Yield one parsed packet at a time from a PCAP or PCAPNG file.

    Raises CaptureReadError if the file is not a readable capture.
    """
    try:
        capture = PcapReader(str(pcap_path))
    except (Scapy_Exception, EOFError, OSError) as error:
        raise CaptureReadError(
            f"{pcap_path} is not a readable PCAP/PCAPNG file: {error}"
        ) from error

    with capture:
        try:
            for packet in capture:
                yield parse_packet(packet)
        except Scapy_Exception as error:
            raise CaptureReadError(
                f"Capture {pcap_path} is damaged or truncated: {error}"
            ) from error
