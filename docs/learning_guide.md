# Learning guide

This guide explains PacketLens from the bottom up. Read it with the code
open. Each section ends with a small exercise. Do the exercise *before*
reading the next section, because predicting a result and then checking it is
how the ideas stick.

Commands assume you are in the project folder and use `.venv/bin/python`.

---

## 0. Vocabulary

- **Packet**: one unit of data sent over a network. A capture records
  packets with a timestamp each.
- **PCAP / PCAPNG**: file formats for saved captures (Wireshark, tcpdump).
  Each record has the captured bytes plus two lengths: *captured length*
  (bytes saved) and *original length* (bytes on the wire).
- **Layers**: a packet is nested headers. Ethernet (MAC addresses) carries
  IP (IP addresses), which carries TCP/UDP (ports), which carries the
  application data (HTTP, DNS, ...).
- **TCP flags**: bits in the TCP header. SYN = "let's connect", ACK = "I
  acknowledge", FIN = "I'm done", RST = "reset/refused".
- **ICMP**: control messages: ping (echo request/reply), "destination
  unreachable", etc. ICMPv6 is the IPv6 version.
- **IPv6 extension headers**: optional headers between the IPv6 header and
  TCP/UDP (Hop-by-Hop, Routing, Destination Options, Fragment).
- **Fragment**: a piece of an IP packet that was too big; only the first
  piece contains the TCP/UDP header.
- **SQLite**: a database stored in one file, used through Python's built-in
  `sqlite3` module.
- **Scapy**: a Python library that can decode (dissect) packet bytes into
  layers. PacketLens only uses it to *read and build* packets, never to
  send them.

---

## 1. `parser.py`: bytes → dictionary

`read_packets(path)` opens the file with `PcapReader` and `yield`s one
dictionary per packet. A *generator* (`yield`) means the whole capture is
never in memory at once.

`parse_packet(packet)` fills a dict with every column of the `packets`
table, starting from `None`/`"OTHER"`, then:

1. If the outermost layer is Ethernet, take the MAC addresses.
2. `_outer_network_layer` walks **outside-in** and returns the *first*
   IPv4, IPv6, or ARP layer. Why the first? An ICMP error contains a copy of
   the packet that caused it, and a tunnel contains a whole second IP packet.
   The old code used `TCP in packet`, which searches *everywhere*, so it could
   take ports from the inner packet. The new code reads only the layer
   directly after the outer IP header.
3. IPv4: if the fragment offset is not 0, the payload is the middle of
   some other packet, so it does **not** parse ports. IPv6:
   `_skip_ipv6_extensions` follows extension headers until the real
   transport header, and stops early for later fragments.
4. `_parse_transport` reads TCP/UDP/ICMP fields.
5. `_identify_application` labels DNS/HTTP/TLS when the **payload**
   matches (`l7_basis='payload'`), otherwise guesses from well-known ports
   (`l7_basis='port'`), otherwise leaves it unknown.

**Exercise 1.** In a Python shell:

```python
from scapy.all import Ether, IP, ICMP, UDP
from packetlens.parser import parse_packet
p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="198.51.100.1", dst="192.0.2.1") / ICMP(type=3, code=3) / IP(src="192.0.2.1", dst="203.0.113.5") / UDP(sport=5353, dport=53)
p = Ether(bytes(p)); p.time = 0
parse_packet(p)
```

Predict `protocol`, `src_ip`, `src_port`, and `icmp_type` first, then check.
(Always give Scapy explicit MAC addresses. Without them it may try to
look up a MAC on your real network.)

---

## 2. `schema.sql` and `database.py`: dictionary → row

`create_database` runs `schema.sql` and sets `PRAGMA user_version = 2`.
`insert_packets` uses `executemany` with **named placeholders**
(`:src_ip`), so values are passed separately from the SQL text and cannot
change the query (no SQL injection). All batches run inside one `with
connection:` block, which is one transaction: all rows are saved, or none.

`connect(db, read_only=True)` opens with SQLite's `mode=ro` and checks the
schema version. An old database raises `SchemaVersionError` and is left
untouched.

**Exercise 2.** Open [schema.md](schema.md) and find two columns that are
NULL for an ARP packet but not for a TCP packet. Then check with:

```bash
.venv/bin/python -m packetlens.ingest data/samples/demo.pcap /tmp/ex2.db
sqlite3 /tmp/ex2.db "SELECT protocol, src_ip, src_port FROM packets"
```

---

## 3. `ingest.py`: putting it together safely

`ingest_capture` does parse → insert → `rebuild_flows` →
`rebuild_hosts` → `run_detection` → `capture_info`, all into a hidden
temporary file (`.name.db.XXXX.partial`). Only at the end does
`_publish_without_overwrite` hard-link it to the real name. A hard link
fails if the name already exists, so even a race cannot overwrite a file. On
any error, the `finally:` block removes the temporary file.

**Exercise 3.** Run the import on a text file
(`echo hi > /tmp/x.pcap`). What error do you get? Is there any `.db` or
`.partial` file left? Why not?

---

## 4. `flows.py` and `hosts.py`: summaries

`flow_key` sorts the two `(ip, port)` endpoints so `A→B` and `B→A` produce
the same key. `rebuild_flows` deletes all flows and recomputes them (so
rerunning is safe), keeping min/max timestamps (correct even with
out-of-order packets) and per-direction counts.

`rebuild_hosts` is a single SQL statement: a `UNION ALL` of
"source role" rows and "destination role" rows, then `GROUP BY ip`.

**Exercise 4.** The demo capture has a TCP SYN 192.0.2.1:50000 → :80 at
t=0 and a SYN+ACK back at t=4. Predict `a_ip`, `b_port`, `duration`, and
`packets_b_to_a` for that flow, then check in `tests/test_storage.py`.

---

## 5. `queries.py`: filters and analysis

`PacketFilter` holds the user's filters; `filter_sql` turns it into
`WHERE ... AND ...` plus a parameter list. Every analysis function calls it,
so every view uses the same packets. The test
`test_all_views_describe_same_subset` checks this for 8 different filters.

`conversations` repeats the flow grouping *in SQL* with `CASE WHEN` so it
can run on any filtered subset. `test_sql_conversations_match_rebuild_flows`
checks both implementations agree.

`run_readonly_query` is the SQL console. Read its docstring: three
independent protections (read-only file, authorizer, time limit).

**Exercise 5 (add a query).** Add a function `busiest_source_ports` that
mirrors `top_destination_ports` but groups by `src_port`. Write a test that
checks its packet total equals `summary(...)["packets"]` minus packets
without ports.

---

## 6. `detection.py`: rules

Read [detection_rules.md](detection_rules.md) first. Then trace
`find_episodes` by hand with
`[(0,1,'a'), (5,2,'b'), (10,3,'c')]`, threshold 3, window 10.
Write down `left`, `right`, and the counter after each step.

**Exercise 6 (change a threshold).**

```bash
.venv/bin/python -m packetlens.samples /tmp/samples
.venv/bin/python -m packetlens.ingest /tmp/samples/near_threshold.pcap /tmp/near.db
.venv/bin/python -c "from packetlens.detection import *; print(run_detection('/tmp/near.db', DetectionConfig(port_scan_ports=19)))"
```

Predict the number printed before running it.

---

## 7. `report.py`, `xml_export.py`, `dashboard.py`

- The report calls the same query functions with the same filter, and
  escapes every value with `html.escape`.
- The XML exporter writes row by row; NULL → `is_null="true"`; forbidden
  control characters → U+FFFD with a `replaced_invalid_chars` count.
- The dashboard is a Streamlit script: it reruns top-to-bottom on every
  click. Look for every `st.button`, because those are the only places that
  change data (analyse, re-check detection, clear history).
- `network_map.py` draws the "Network map" tab. `build_layers` groups
  traffic into three columns (senders, services, receivers); the service is
  guessed from the smaller port number (usually the server's port).
  `figure` draws each link as a smooth curve whose thickness grows with
  the number of messages.
- `history.py` lists saved analyses and deletes them. It refuses to delete
  anything that is not a `.db` file directly inside the output folder.

**Exercise 7.** In `network_map.SERVICE_NAMES`, add `8000: "Test server"`.
`near_threshold.pcap` sends one connection attempt to each of ports
8000–8018. Predict: on its network map (Detailed view), will "Test server"
appear as its own node, or be grouped into "Other services"? Why? Check,
then remove the line again.

---

## 8. One packet through the whole pipeline

We follow the HTTP request in `normal.pcap` (packet id 4), built in
`samples.tcp_conversation`:

```
Ether(02:00:00:00:00:0a → 02:00:00:00:00:0b)
 / IP(192.0.2.10 → 198.51.100.20, ttl 64)
 / TCP(49152 → 80, flags PA, seq 1001, ack 5001)
 / Raw(b"GET /index.html HTTP/1.1\r\nHost: www.example\r\n...")
```

1. **File.** `wrpcap` wrote it with timestamp `1700000000.03`.
2. **Parser.** Outer layer is Ethernet → MACs. First network layer is IPv4
   → `src_ip=192.0.2.10`, `dst_ip=198.51.100.20`, `ip_proto=6`, `ttl=64`,
   offset 0 so not a fragment. Next layer is TCP → ports `49152`/`80`,
   `tcp_flags=24` (PSH 8 + ACK 16), seq 1001, ack 5001. Payload starts
   with `GET ` → `l7_proto='HTTP'`, `l7_basis='payload'`. Captured length
   132 bytes = 14 Ethernet + 20 IP + 20 TCP + 78 payload, and
   `payload_length=78`. Not truncated, so `wire_length=132`.
3. **Database.** Inserted as row `id=4` in the `packets` table.
4. **Flows.** Key `(TCP, (192.0.2.10, 49152), (198.51.100.20, 80))`;
   192.0.2.10 sorts first, so it is endpoint A and this packet counts as
   A→B. The flow ends with 8 packets (5 A→B, 3 B→A), 603 bytes, duration
   ≈ 0.08 s.
5. **Hosts.** Adds 1 packet / 132 bytes to `pkts_sent`/`bytes_sent` of
   192.0.2.10 and to `pkts_recv`/`bytes_recv` of 198.51.100.20.
6. **Detection.** Flags 24 include ACK, so it is **not** a connection
   attempt; neither rule counts it. (Packet 1, the SYN, is counted, but
   one destination port and one host are far below the thresholds.)
7. **Dashboard / report.** With filter `port = 80` it appears in the
   packet list, the protocol chart (TCP), the timeline bucket at
   t ≈ 0.03 s, the 192.0.2.10 ↔ 198.51.100.20 conversation, and both hosts.
   With filter `l7_proto = HTTP` it also appears, because its label is HTTP.
8. **XML.** `<packet><id>4</id><ts>1700000000.03</ts>...<l7_basis>payload</l7_basis>...</packet>`.

**Exercise 8.** Do the same trace for the DNS *response* in
`normal.pcap`. Which packet id is it, what is its `l7_basis`, and in which
direction of its flow does it count?

---

## Suggested study order

1. `schema.sql` + [schema.md](schema.md)
2. `parser.py` + `tests/test_parser.py`
3. `database.py`, `ingest.py` + `tests/test_storage.py`
4. `flows.py`, `hosts.py`
5. `queries.py` + `tests/test_queries.py`
6. `detection.py` + [detection_rules.md](detection_rules.md) + `tests/test_detection.py`
7. `report.py`, `xml_export.py` + their tests
8. `samples.py` (how the test data is built)
9. `dashboard.py` (last; it only calls the modules above)
