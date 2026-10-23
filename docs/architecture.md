# Architecture: from PCAP to dashboard and report

```
                 +-------------------+
  capture.pcap → | parser.py         |  one dict per packet (generator)
                 +---------+---------+
                           |
                 +---------v---------+
                 | database.py       |  insert_packets: batched INSERTs
                 | schema.sql        |  into packets (one transaction)
                 +---------+---------+
                           |
       +-------------------+--------------------+
       |                   |                    |
+------v------+   +--------v-------+   +--------v--------+
| flows.py    |   | hosts.py       |   | detection.py    |
| endpoint    |   | per-IP totals  |   | port_scan,      |
| convers.    |   | (whole capt.)  |   | host_sweep      |
+------+------+   +--------+-------+   +--------+--------+
       |                   |                    |
       +-------------------+--------------------+
                           |   one SQLite file per capture
                 +---------v---------+
                 | queries.py        |  filter-aware read queries,
                 |                   |  read-only SQL console
                 +----+---------+----+
                      |         |
         +------------v-+    +--v-------------+    +----------------+
         | dashboard.py |    | report.py      |    | xml_export.py  |
         | Streamlit +  |    | HTML findings  |    | all stored     |
         | Plotly       |    | (filtered)     |    | records → XML  |
         +--------------+    +----------------+    +----------------+
```

`ingest.py` runs the top half (parse → insert → flows → hosts → detection →
`capture_info`). Everything below the database only reads, except the
dashboard's "Run detection" button, which calls `run_detection` again.

## Modules

| Module | Role | Main functions |
|---|---|---|
| `parser.py` | Reads a capture with Scapy's `PcapReader` (PCAP and PCAPNG), turns each packet into a flat dict | `read_packets`, `parse_packet` |
| `database.py` | Creates the schema, inserts packets, opens databases with a schema-version check | `create_database`, `insert_packets`, `connect` |
| `ingest.py` | Command-line import; builds the database under a temporary name and renames it only on success | `ingest_capture`, `main` |
| `flows.py` | Rebuilds whole-capture endpoint conversations | `rebuild_flows`, `flow_key` |
| `hosts.py` | Rebuilds whole-capture per-IP totals (one SQL statement) | `rebuild_hosts` |
| `detection.py` | Sliding-window rules, writes `alerts` + `alert_evidence` | `find_episodes`, `detect_all`, `run_detection` |
| `queries.py` | `PacketFilter` and every analysis query; read-only console | `filter_sql`, `summary`, `conversations`, `hosts`, `traffic_timeline`, `alerts`, `run_readonly_query` |
| `report.py` | Escaped, self-contained HTML report | `build_report`, `write_report` |
| `xml_export.py` | Streams all stored records to XML | `export_xml` |
| `samples.py` | Writes deterministic synthetic captures and `manifest.json` | `write_samples` |
| `network_map.py` | Builds the dashboard's three-layer "who → what for → whom" diagram | `build_layers`, `figure`, `service_label` |
| `history.py` | Lists and deletes saved analyses in the output folder (refuses anything outside it) | `list_captures`, `delete_captures` |
| `dashboard.py` | Streamlit user interface (theme in `.streamlit/config.toml`) | (script) |

## Key design decisions

1. **One capture per database.** Simple to reason about: no `capture_id`
   column on every row, and deleting a database deletes the capture.
2. **Parse outer headers only.** The parser stops at the first IP/IPv6/ARP
   header and reads the transport header right after it (after IPv6
   extension headers). That avoids taking ports from ICMP-quoted packets or
   tunnelled inner packets.
3. **Streaming where it matters.** `read_packets` is a generator and
   `insert_packets` writes in batches of 1000, so the capture is never fully in
   memory. `xml_export` writes row by row. (`rebuild_flows` and detection keep
   one dictionary entry per conversation/group, which is proportional to the
   number of conversations, not packets.)
4. **Atomic outputs.** Import and XML export write to a hidden `.partial`
   file first and publish it with a hard link (which fails if the target
   exists), so a crash never leaves a complete-looking output and an existing
   file is never overwritten.
5. **One filter, many views.** `filter_sql` is the only place a `WHERE`
   clause is built. Summary, charts, conversations, hosts, and the report all
   use it, so they always agree.
6. **Detection is whole-capture and replaceable.** Rerunning replaces alerts
   in one transaction, so there are no duplicates.
7. **Defence in depth for free-form SQL.** Read-only file mode, an
   authorizer allowing only reads, a time limit, and a row cap.

## Streamlit reruns

Streamlit reruns the whole script on every widget change. Side effects
(import, detection) run only inside button handlers. Import always creates
a new timestamped database file, and `ingest_capture` refuses an existing
name, so a duplicate click cannot double-import. Everything else is a
read-only query.
