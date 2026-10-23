"""Self-contained HTML findings report.

The report states its scope explicitly:
- statistics, protocols, hosts, conversations: the FILTERED packet subset;
- alerts: computed over the WHOLE capture, then shown if relevant to the
  filter (see queries.alerts for the exact rule).

Every value that comes from the capture or the user (IP strings, packet
summaries, file names, filter text) passes through html.escape, so a
crafted capture cannot inject markup or scripts into the report.
"""

import argparse
import html
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from packetlens import queries
from packetlens.database import SchemaVersionError, connect
from packetlens.detection import stored_config
from packetlens.queries import PacketFilter

LIMITATIONS = [
    "Offline analysis of one saved capture; nothing outside the capture is "
    "known (e.g. traffic the sensor did not see).",
    "Alerts are suspicious-pattern indicators, not proof of malicious "
    "activity. Scanners, monitoring tools, and some legitimate software "
    "produce the same patterns.",
    "Conversations group packets by endpoints over the whole time range; "
    "they are not reconstructed TCP sessions.",
    "Byte counts are captured bytes. If the capture was truncated "
    "(snapshot length), on-wire bytes are larger.",
    "Fragments are not reassembled; only first fragments carry ports.",
    "Tunnelled/encapsulated traffic is recorded by its outer header only.",
    "Application labels with basis 'port' are guesses from port numbers.",
    "Traffic volume is not a measurement of congestion, capacity, packet "
    "loss, or retransmissions; none of these are measured.",
]


def _e(value):
    """Escape any value for HTML; None becomes an em dash."""
    return "&mdash;" if value is None else html.escape(str(value))


def _ts(value):
    if value is None:
        return "&mdash;"
    moment = datetime.fromtimestamp(value, tz=timezone.utc)
    return _e(moment.strftime("%Y-%m-%d %H:%M:%S.%f UTC"))


def _table(rows, columns, formats=None):
    formats = formats or {}
    if not rows:
        return "<p class='empty'>No rows for this scope.</p>"
    head = "".join(f"<th>{_e(label)}</th>" for _, label in columns)
    body = []
    for row in rows:
        cells = []
        for key, _ in columns:
            value = row.get(key)
            cells.append(f"<td>{formats[key](value) if key in formats else _e(value)}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


STYLE = """
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:2rem auto;
max-width:1100px;padding:0 1rem;color:#1d2433;background:#fff;line-height:1.45}
h1{margin-bottom:.2rem}h2{border-bottom:1px solid #d8dde6;padding-bottom:.2rem;margin-top:2rem}
table{border-collapse:collapse;width:100%;font-size:.88rem;margin:.5rem 0}
th,td{border:1px solid #d8dde6;padding:.3rem .5rem;text-align:left;vertical-align:top}
th{background:#f2f4f8}.empty{color:#667}.note{background:#fff8e1;border:1px solid #f0d58c;
padding:.6rem .8rem;border-radius:4px}.sev-high{color:#a30d0d;font-weight:600}
.sev-medium{color:#9a5b00;font-weight:600}code{background:#f2f4f8;padding:0 .2rem}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem}dt{font-weight:600}
"""


def build_report(db_path, packet_filter=None, top=10, max_evidence=20):
    """Return the report as an HTML string."""
    packet_filter = packet_filter or PacketFilter()
    connection = connect(db_path, read_only=True)

    try:
        info = queries.capture_info(connection) or {}
        stats = queries.summary(connection, packet_filter)
        protocols = queries.protocol_distribution(connection, packet_filter)
        apps = queries.application_distribution(connection, packet_filter)
        senders = queries.top_senders(connection, packet_filter, limit=top)
        receivers = queries.top_receivers(connection, packet_filter, limit=top)
        ports = queries.top_destination_ports(connection, packet_filter, limit=top)
        talks = queries.conversations(connection, packet_filter, limit=top)
        host_rows = queries.hosts(connection, packet_filter, limit=top)
        alert_rows = queries.alerts(connection, packet_filter)
        config = stored_config(connection)
        evidence = {
            alert["alert_id"]: queries.alert_evidence(
                connection, alert["alert_id"], limit=max_evidence)
            for alert in alert_rows
        }
    finally:
        connection.close()

    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>PacketLens findings: {_e(info.get('source_name', 'capture'))}</title>",
        f"<style>{STYLE}</style></head><body>",
        "<h1>PacketLens findings report</h1>",
        f"<p>Generated {_e(datetime.now(timezone.utc).isoformat(timespec='seconds'))}</p>",
        "<h2>Capture</h2><dl>",
        f"<dt>Source file</dt><dd>{_e(info.get('source_name'))}</dd>",
        f"<dt>SHA-256</dt><dd><code>{_e(info.get('source_sha256'))}</code></dd>",
        f"<dt>Packets in capture</dt><dd>{_e(info.get('packet_count'))}</dd>",
        f"<dt>Imported at</dt><dd>{_e(info.get('imported_at'))}</dd>",
        f"<dt>Database</dt><dd>{_e(Path(db_path).name)}</dd></dl>",
        "<h2>Scope</h2>",
        "<p>Applied filters: " + "; ".join(_e(item) for item in packet_filter.describe()) + "</p>",
        "<p class='note'>Statistics, protocols, hosts, and conversations below "
        "use only the packets matching these filters. Alerts were computed "
        "over the <strong>whole capture</strong> and are listed if they "
        "relate to the filter.</p>",
        "<h2>Summary statistics</h2><dl>",
        f"<dt>Packets</dt><dd>{stats['packets']}</dd>",
        f"<dt>Captured bytes</dt><dd>{stats['captured_bytes']}</dd>",
        f"<dt>On-wire bytes</dt><dd>{stats['wire_bytes']}</dd>",
        f"<dt>First packet</dt><dd>{_ts(stats['first_ts'])}</dd>",
        f"<dt>Last packet</dt><dd>{_ts(stats['last_ts'])}</dd>",
        f"<dt>Observed span</dt><dd>{stats['duration']:.6f} s</dd></dl>",
        "<h2>Protocols</h2>",
        _table(protocols, [("protocol", "Protocol"), ("packets", "Packets"), ("bytes", "Captured bytes")]),
        "<h3>Application labels</h3><p>Basis <code>payload</code> = content "
        "checked; <code>port</code> = guess from a well-known port.</p>",
        _table(apps, [("l7_proto", "Label"), ("l7_basis", "Basis"), ("packets", "Packets"), ("bytes", "Bytes")]),
        "<h2>Hosts</h2>",
        f"<h3>Top {top} senders (packets)</h3>",
        _table(senders, [("ip", "IP"), ("packets", "Packets"), ("bytes", "Bytes")]),
        f"<h3>Top {top} receivers (packets)</h3>",
        _table(receivers, [("ip", "IP"), ("packets", "Packets"), ("bytes", "Bytes")]),
        f"<h3>Busiest hosts (top {top} by total bytes)</h3>",
        _table(host_rows, [("ip", "IP"), ("pkts_sent", "Pkts sent"), ("pkts_recv", "Pkts recv"),
                           ("bytes_sent", "Bytes sent"), ("bytes_recv", "Bytes recv")]),
        f"<h3>Busiest destination ports (top {top})</h3>",
        _table(ports, [("protocol", "Protocol"), ("dst_port", "Port"), ("packets", "Packets"),
                       ("distinct_sources", "Distinct sources")]),
        f"<h2>Largest endpoint conversations (top {top} by bytes)</h2>",
        _table(talks, [("protocol", "Proto"), ("a_ip", "A IP"), ("a_port", "A port"),
                       ("b_ip", "B IP"), ("b_port", "B port"), ("packet_count", "Packets"),
                       ("byte_count", "Bytes"), ("duration", "Duration (s)")]),
        "<h2>Detection</h2>",
    ]

    if config:
        parts.append(
            "<p>Configuration: port_scan &ge; "
            f"{config.port_scan_ports} distinct ports on one destination within "
            f"{config.port_scan_window:g} s; host_sweep &ge; {config.host_sweep_hosts} "
            f"distinct destinations within {config.host_sweep_window:g} s. "
            "Windows are inclusive (last &minus; first &le; window).</p>"
        )
    else:
        parts.append("<p>Detection has not been run on this database.</p>")

    parts.append(f"<p>{len(alert_rows)} indicator(s) relevant to this scope. "
                 "These are suspicious patterns, not proof of an attack.</p>")

    for alert in alert_rows:
        severity = alert["severity"] if alert["severity"] in ("high", "medium", "low") else "low"
        parts += [
            f"<h3>#{alert['alert_id']} {_e(alert['rule'])} "
            f"<span class='sev-{severity}'>[{_e(alert['severity'])}]</span></h3>",
            "<dl>",
            f"<dt>Source</dt><dd>{_e(alert['src_ip'])}</dd>",
            f"<dt>Destination</dt><dd>{_e(alert['dst_ip'] or 'many')}</dd>",
            f"<dt>Interval</dt><dd>{_ts(alert['start_ts'])} &rarr; {_ts(alert['end_ts'])}</dd>",
            f"<dt>Observed</dt><dd>{_e(alert['metric_name'])} = {alert['metric_value']} "
            f"(threshold {alert['threshold']}, window {alert['window_seconds']:g} s)</dd>",
            f"<dt>Explanation</dt><dd>{_e(alert['explanation'])}</dd>",
            f"<dt>Evidence</dt><dd>{alert['evidence_packets']} packets "
            f"(first {min(max_evidence, alert['evidence_packets'])} shown)</dd></dl>",
            _table(evidence[alert["alert_id"]], [
                ("id", "Packet id"), ("ts", "Time"), ("src_ip", "Src"), ("src_port", "Sport"),
                ("dst_ip", "Dst"), ("dst_port", "Dport"), ("protocol", "Proto"), ("info", "Summary"),
            ], {"ts": _ts}),
        ]

    parts += ["<h2>Limitations</h2><ul>"]
    parts += [f"<li>{_e(item)}</li>" for item in LIMITATIONS]
    parts += ["</ul></body></html>"]
    return "\n".join(parts)


def write_report(db_path, output_path, packet_filter=None):
    output_path = Path(output_path)
    content = build_report(db_path, packet_filter)
    # "x" mode refuses to overwrite an existing report.
    with output_path.open("x", encoding="utf-8") as handle:
        handle.write(content)
    return output_path


def main(argv=None):
    parser = argparse.ArgumentParser(description="Write an HTML findings report.")
    parser.add_argument("database", type=Path)
    parser.add_argument("output", type=Path, help="new .html file to create")
    parser.add_argument("--ip")
    parser.add_argument("--port", type=int)
    parser.add_argument("--protocol", action="append", default=[],
                        help="repeatable, e.g. --protocol TCP --protocol UDP")
    parser.add_argument("--start-ts", type=float)
    parser.add_argument("--end-ts", type=float)
    parser.add_argument("--min-length", type=int)
    parser.add_argument("--max-length", type=int)
    parser.add_argument("--l7")
    args = parser.parse_args(argv)

    packet_filter = PacketFilter(
        ip=args.ip, port=args.port, protocols=args.protocol,
        start_ts=args.start_ts, end_ts=args.end_ts,
        min_length=args.min_length, max_length=args.max_length,
        l7_proto=args.l7,
    )

    try:
        write_report(args.database, args.output, packet_filter)
    except (OSError, SchemaVersionError, sqlite3.DatabaseError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
