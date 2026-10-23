# Database schema (version 2)

The schema lives in [`schema.sql`](../schema.sql). Each SQLite file holds
**exactly one capture**. Its version is stored in SQLite's built-in
`PRAGMA user_version` (currently `2`).

## Conventions

| Topic | Rule |
|---|---|
| Timestamps | Seconds since the Unix epoch (1970-01-01 UTC), stored as `REAL`. Pcap files store microseconds, but a `REAL` near 1.7 × 10⁹ is only accurate to about 0.2 µs, so `1700000000.2` may read back as `1700000000.2000000477`. Treat values as accurate to the microsecond. |
| Captured bytes | `packets.length`: the bytes actually saved in the file for that packet, link-layer header included (for Ethernet, the 14-byte header is counted). Every byte total in PacketLens (`byte_count`, `bytes_sent`, chart bytes, ...) is a sum of `length`. |
| On-wire bytes | `packets.wire_length`: the original packet length from the pcap record header. It equals `length` unless the capture was **truncated** (a "snapshot length" smaller than the packet). Then `wire_length > length`. |
| NULL | NULL means "this field does not exist for this packet, or could not be read", e.g. ports for ICMP, ARP, later fragments, or a cut-off TCP header. It never means zero. |
| Protocol labels | `TCP`, `UDP`, `ICMP`, `ICMPv6`, `ARP`, `OTHER` (enforced by a `CHECK` constraint). `OTHER` covers non-IP frames, tunnels, non-initial fragments, truncated transport headers, and other IP protocols; `ip_proto` still says which IP protocol it was. |
| SQL values | Every user-supplied value goes through `?` / `:name` placeholders. The only text built into SQL strings is fixed table/column names from code. |

## `capture_info` (one row)

| Column | Meaning |
|---|---|
| `id` | Always 1 (`CHECK (id = 1)` enforces one capture per database). |
| `source_name` | Original file name of the capture. |
| `source_sha256` | SHA-256 of the capture file, which identifies exactly which file was analysed. |
| `source_bytes` | Capture file size. |
| `packet_count` | Packets imported. |
| `imported_at` | UTC ISO-8601 time of the import. |
| `parser_version` | Version of the parser rules (`"2"`). |

A database is published under its final name only after the import has
finished, so a database without a `capture_info` row was not produced by a
successful `ingest_capture` run.

## `packets` (one row per captured packet)

| Column | Meaning / NULL rule |
|---|---|
| `id` | Position in the file (1 = first packet). The file order is kept even when timestamps are out of order. |
| `ts` | Capture timestamp (see conventions). |
| `src_mac`, `dst_mac` | Ethernet addresses; NULL for non-Ethernet link types. |
| `src_ip`, `dst_ip` | Addresses from the **outermost** IPv4/IPv6 header. NULL for ARP and non-IP. |
| `ip_version` | 4, 6, or NULL. |
| `ip_proto` | IP protocol number of the payload (6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6, 4 IP-in-IP, ...). For IPv6, this is the value after skipping extension headers. |
| `src_port`, `dst_port` | TCP/UDP ports. NULL for other protocols and for **non-initial fragments** (their bytes are not a transport header). |
| `protocol` | Label, see conventions. |
| `length` | Captured bytes. |
| `wire_length` | On-wire bytes (≥ `length`). |
| `payload_length` | Captured bytes after the TCP/UDP header. NULL when not TCP/UDP. For a first fragment, this counts only the part inside that fragment. |
| `ttl` | IPv4 TTL or IPv6 hop limit. |
| `is_fragment` | 1 if IPv4 MF flag/offset or an IPv6 Fragment header marks a fragment, else 0. |
| `tcp_flags` | TCP flag bits as an integer (FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32, ...). SYN+ACK = 18. |
| `tcp_seq`, `tcp_ack`, `tcp_window` | Raw TCP header values. |
| `icmp_type`, `icmp_code` | ICMP or ICMPv6 type/code (e.g. 8 = IPv4 echo request, 128 = ICMPv6 echo request). |
| `l7_proto` | Application label (`DNS`, `HTTP`, `TLS`, `SSH`, `NTP`, ...), or NULL = unknown. |
| `l7_basis` | `payload` = the payload was checked and matched (DNS parsed by Scapy, HTTP request/response line, TLS record header); `port` = only a guess from a well-known port; NULL when `l7_proto` is NULL. |
| `info` | Scapy's one-line summary. Untrusted text. |

Indexes: `ts`, `src_ip`, `dst_ip`, `dst_port`, `protocol`.

## `flows` (endpoint conversations, whole capture)

One row per (protocol, endpoint A, endpoint B) for TCP/UDP packets that
have both IPs and both ports. The two endpoints `(ip, port)` are sorted, and
the smaller one is **A**, so both directions share one row.

> These are **endpoint conversations**, not TCP sessions. SYN/FIN are not
> used to split them; two connections reusing identical ports become one row.

`start_ts`/`end_ts` are the min/max timestamps, so out-of-order packets are
handled correctly; `duration = end_ts - start_ts`. `packet_count`/`byte_count`
are totals; `packets_a_to_b`, `packets_b_to_a`, `bytes_a_to_b`,
`bytes_b_to_a` split them by direction.

## `hosts` (per IP, whole capture)

`pkts_sent`/`bytes_sent` count packets where the IP is `src_ip`;
`pkts_recv`/`bytes_recv` where it is `dst_ip`. `first_seen`/`last_seen`
are min/max `ts` in either role.

`flows` and `hosts` are rebuilt from scratch (`DELETE` + `INSERT` in one
transaction) by `rebuild_flows` / `rebuild_hosts`, so rebuilding twice gives
identical rows.

## `alerts` and `alert_evidence`

See [detection_rules.md](detection_rules.md). `alerts` has one row per
detected episode: `rule`, `severity` (`medium`/`high`), `src_ip`, `dst_ip`
(NULL for host sweeps, which target many hosts), `start_ts`, `end_ts`,
`metric_name`, `metric_value` (peak count in one window), `threshold`,
`window_seconds`, `explanation`.
`alert_evidence(alert_id, packet_id)` links each alert to the packets that
support it (foreign keys to `alerts` and `packets`).
`metadata` stores the detection settings used (`key = 'detection_config'`,
JSON).

## Filter semantics (queries.py, dashboard, report)

Filters are combined with **AND**. A filter left empty does not restrict.

| Filter | Matches when |
|---|---|
| IP | `src_ip = X OR dst_ip = X` |
| Port | `src_port = P OR dst_port = P` |
| Protocols | `protocol IN (...)` |
| Time range | `start ≤ ts ≤ end` (inclusive) |
| Size range | `min ≤ length ≤ max` (captured bytes, inclusive) |
| Application label | `l7_proto = label` (payload or port basis) |

Every filtered view (summary, protocol chart, timeline, top talkers, ports,
conversations, hosts, packet list, report) is computed from the same filtered
`packets` rows. Filtered conversations and hosts are **recomputed** from those
packets; the stored whole-capture `flows`/`hosts` tables are not used for
filtered views.

**Alerts are computed for the whole capture.** A filter selects which alerts
to show: the IP filter matches alert `src_ip`/`dst_ip`, the time filter keeps
alerts whose interval overlaps the range, and other filters keep an alert if
at least one of its evidence packets matches the whole filter.

## Existing databases and schema changes

Databases from schema version 1 (before this change; `user_version = 0`)
are **never modified automatically**. Opening one raises `SchemaVersionError`
with instructions. Re-import the original capture into a new file:

```bash
.venv/bin/python -m packetlens.ingest data/samples/demo.pcap data/output/demo_v2.db
```

The old file stays where it was until you delete it yourself.
