"""The dashboard's "network map": a three-layer diagram, read left to right.

    Who sent it  ->  What it was for  ->  Who received it
    (source IP)      (service)            (destination IP)

It looks like a small neural network: each column is a layer, each circle
is a node, and each curved line is a link whose thickness grows with the
number of messages (packets) that took that path.

The "service" of a TCP/UDP message is guessed from its ports: the smaller
of the two port numbers is usually the server's well-known port (e.g. 80
for web), while the other is a random high "client" port. ICMP becomes
"Ping" or "Network messages". This is a presentation heuristic only.
"""

import math
from collections import defaultdict

import plotly.graph_objects as go

SERVICE_NAMES = {
    20: "File transfer (FTP data)", 21: "File transfer (FTP)",
    22: "Remote login (SSH)", 23: "Remote login (Telnet)",
    25: "Email sending (SMTP)", 53: "Name lookup (DNS)",
    67: "Address setup (DHCP)", 68: "Address setup (DHCP)",
    80: "Web (HTTP)", 110: "Email (POP3)", 123: "Clock sync (NTP)",
    143: "Email (IMAP)", 443: "Secure web (HTTPS)",
    546: "Address setup (DHCPv6)", 547: "Address setup (DHCPv6)",
    993: "Secure email (IMAPS)", 995: "Secure email (POP3S)",
    3389: "Remote desktop (RDP)", 5353: "Local discovery (mDNS)",
}

LAYER_TITLES = ("WHO SENT IT", "WHAT IT WAS FOR", "WHO RECEIVED IT")

# Two palettes, matching the dashboard's light and dark themes.
PALETTES = {
    "light": {"device": "#4F5BD5", "service": "#2BB3A3", "flagged": "#E5484D",
              "other": "#A7AAB3", "muted": "#6C6F78", "text": "#17181C",
              "link": "rgba(160, 160, 150, 0.40)",
              "link_flagged": "rgba(229, 72, 77, 0.45)", "ring": "#FAFAF8"},
    "dark": {"device": "#8F97F3", "service": "#2BB3A3", "flagged": "#EF5F63",
             "other": "#6B6E77", "muted": "#8E9199", "text": "#ECECEE",
             "link": "rgba(120, 122, 130, 0.45)",
             "link_flagged": "rgba(239, 95, 99, 0.50)", "ring": "#111215"},
}


def service_label(protocol, service_port, icmp_type):
    """Friendly name for what a message was for."""
    if protocol in ("TCP", "UDP") and service_port is not None:
        name = SERVICE_NAMES.get(service_port)
        return name if name else f"{protocol} port {service_port}"
    if protocol == "ICMP":
        return "Ping" if icmp_type in (0, 8) else "Network messages (ICMP)"
    if protocol == "ICMPv6":
        return "Ping" if icmp_type in (128, 129) else "Network messages (ICMPv6)"
    return "Other traffic"


def build_layers(links, max_nodes=10, suspicious_ips=()):
    """Turn network_links rows into nodes and edges for the three layers.

    Only the `max_nodes` busiest nodes per layer are drawn; the rest are
    merged into one "Other ..." node so the picture stays readable.

    Returns (layers, edges):
      layers: three lists of dicts {label, packets, bytes}, busiest first;
      edges:  dict {(layer, from_label, to_label): (packets, flagged)},
              layer 0 = sender->service, layer 1 = service->receiver;
              `flagged` counts the packets SENT BY a suspicious IP, so a
              scanner's traffic stays highlighted across both layers.
    """
    suspicious_ips = set(suspicious_ips)
    senders, services, receivers = (defaultdict(lambda: [0, 0]) for _ in range(3))
    paths = []

    for row in links:
        service = service_label(row["protocol"], row["service_port"], row["icmp_type"])
        packets, size = row["packets"], row["bytes"] or 0
        for table, key in ((senders, row["src_ip"]), (services, service),
                           (receivers, row["dst_ip"])):
            table[key][0] += packets
            table[key][1] += size
        paths.append((row["src_ip"], service, row["dst_ip"], packets))

    def keep(table, other_name):
        ranked = sorted(table.items(), key=lambda item: (-item[1][0], item[0]))
        kept = {name for name, _ in ranked[:max_nodes]}
        nodes = [{"label": name, "packets": p, "bytes": b}
                 for name, (p, b) in ranked[:max_nodes]]
        rest = ranked[max_nodes:]
        if rest:
            nodes.append({
                "label": f"{other_name} ({len(rest)})",
                "packets": sum(p for _, (p, _) in rest),
                "bytes": sum(b for _, (_, b) in rest),
            })
        return nodes, kept

    sender_nodes, kept_senders = keep(senders, "Other devices")
    service_nodes, kept_services = keep(services, "Other services")
    receiver_nodes, kept_receivers = keep(receivers, "Other devices")

    def name(value, kept, nodes):
        return value if value in kept else nodes[-1]["label"]

    edges = defaultdict(lambda: [0, 0])
    for src, service, dst, packets in paths:
        s = name(src, kept_senders, sender_nodes)
        v = name(service, kept_services, service_nodes)
        d = name(dst, kept_receivers, receiver_nodes)
        flagged = packets if src in suspicious_ips else 0
        for key in ((0, s, v), (1, v, d)):
            edges[key][0] += packets
            edges[key][1] += flagged

    edges = {key: tuple(value) for key, value in edges.items()}
    return [sender_nodes, service_nodes, receiver_nodes], edges


def _positions(nodes):
    """Spread nodes evenly from top (1.0) to bottom (0.0)."""
    count = len(nodes)
    if count == 1:
        return {nodes[0]["label"]: 0.5}
    return {node["label"]: 1 - index / (count - 1) for index, node in enumerate(nodes)}


def _curve(x0, y0, x1, y1, steps=24):
    """Points on a smooth S-shaped (cubic Bezier) curve between two nodes."""
    xs, ys = [], []
    for step in range(steps + 1):
        t = step / steps
        a, b, c, d = (1 - t) ** 3, 3 * (1 - t) ** 2 * t, 3 * (1 - t) * t ** 2, t ** 3
        xs.append(a * x0 + b * (x0 + 0.5) + c * (x1 - 0.5) + d * x1)
        ys.append(a * y0 + b * y0 + c * y1 + d * y1)
    return xs, ys


def split_label(label):
    """'Secure web (HTTPS)' -> ('Secure web', 'HTTPS'); otherwise (label, '')."""
    if label.endswith(")") and " (" in label:
        name, _, rest = label.rpartition(" (")
        return name, rest[:-1]
    return label, ""


def figure(layers, edges, suspicious_ips=(), theme="light"):
    """Build the Plotly figure for the network map."""
    colors = PALETTES.get(theme, PALETTES["light"])
    suspicious_ips = set(suspicious_ips)
    positions = [_positions(nodes) for nodes in layers]
    largest = max((packets for packets, _ in edges.values()), default=1)
    fig = go.Figure()

    # Links, grouped into a few traces by thickness and colour (fast to draw).
    groups = defaultdict(lambda: ([], []))
    for (layer, start, end), (packets, flagged) in edges.items():
        xs, ys = _curve(layer, positions[layer][start],
                        layer + 1, positions[layer + 1][end])
        width = 1 + round(9 * math.sqrt(packets / largest))
        # Red when most of this link's traffic came from a flagged device.
        suspicious = flagged * 2 >= packets and flagged > 0
        group = groups[(width, suspicious)]
        group[0].extend(xs + [None])
        group[1].extend(ys + [None])

    for (width, suspicious), (xs, ys) in sorted(groups.items(), key=lambda g: g[0][1]):
        fig.add_trace(go.Scatter(
            x=xs, y=ys, mode="lines", hoverinfo="skip", showlegend=False,
            line=dict(width=width, shape="spline",
                      color=colors["link_flagged" if suspicious else "link"]),
        ))

    # Nodes, each with a two-line label: name, then a muted detail line.
    biggest = max((n["packets"] for nodes in layers for n in nodes), default=1)
    text_positions = ("middle left", "middle right", "middle right")
    verbs = ("sent", None, "received")

    for layer, nodes in enumerate(layers):
        marker_colors, sizes, texts, hovers = [], [], [], []
        for node in nodes:
            label = node["label"]
            flagged = label in suspicious_ips
            grouped = label.startswith("Other ")
            if flagged:
                color = colors["flagged"]
            elif grouped:
                color = colors["other"]
            else:
                color = colors["device" if layer != 1 else "service"]
            marker_colors.append(color)
            sizes.append(9 + 15 * math.sqrt(node["packets"] / biggest))

            if grouped:
                # "Other services (49)" -> "Other services" / "49 more · 73"
                name, hidden = split_label(label)
                detail = f"{hidden} more · {node['packets']:,}"
                if layer != 1:
                    detail += f" {verbs[layer]}"
            elif layer == 1:
                name, technical = split_label(label)
                detail = f"{technical} · {node['packets']:,}" if technical else f"{node['packets']:,}"
            else:
                name, detail = label, f"{node['packets']:,} {verbs[layer]}"
            name_color = colors["flagged"] if flagged else colors["text"]
            texts.append(f"<span style='color:{name_color}'>{name}</span><br>"
                         f"<span style='color:{colors['muted']};font-size:11px'>{detail}</span>")
            note = "<br>Flagged as suspicious" if flagged else ""
            hovers.append(f"<b>{label}</b><br>{node['packets']:,} messages · "
                          f"{node['bytes']:,} bytes{note}")

        fig.add_trace(go.Scatter(
            x=[layer] * len(nodes),
            y=[positions[layer][n["label"]] for n in nodes],
            mode="markers+text", text=texts,
            textposition=text_positions[layer], textfont=dict(size=13),
            hovertext=hovers, hoverinfo="text", showlegend=False,
            marker=dict(size=sizes, color=marker_colors,
                        line=dict(width=3, color=colors["ring"])),
        ))

    for layer, title in enumerate(LAYER_TITLES):
        fig.add_annotation(x=layer, y=1.14, text=title, showarrow=False,
                           font=dict(size=11, color=colors["muted"]),
                           xref="x", yref="y")

    tallest = max((len(nodes) for nodes in layers), default=1)
    fig.update_layout(
        height=max(400, 64 * tallest + 140),
        margin=dict(l=10, r=10, t=10, b=10),
        xaxis=dict(visible=False, range=[-0.85, 2.75], fixedrange=True),
        yaxis=dict(visible=False, range=[-0.1, 1.2], fixedrange=True),
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        hoverlabel=dict(font_size=13), showlegend=False,
    )
    return fig
