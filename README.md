# PacketLens

PacketLens is an **offline** network-traffic analysis tool for a college
project. It reads a saved capture (PCAP/PCAPNG), stores every packet in
SQLite, builds conversation and host summaries, runs two rule-based
scan indicators, and presents the results in a Streamlit dashboard, an
XML export, and an HTML findings report.

```
PCAP → parser → SQLite (packets, flows, hosts, alerts) → queries
     → dashboard / HTML report / XML
```

It does **not** capture live traffic, send packets, scan networks, or use
machine learning.

## Setup

Tested only with **Python 3.14.3** on macOS. The code uses Python 3.10
syntax (`str | None`), so 3.10 or newer is required; versions other than
3.14.3 have not been tested.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Dependencies (`requirements.txt`): Scapy (packet decoding), Streamlit and
Plotly (dashboard), and pytest (tests). Everything else (`sqlite3`, `xml`,
`html`) is in the standard library.

## Quick start

```bash
# 1. Create the deterministic synthetic captures (+ manifest.json)
.venv/bin/python -m packetlens.samples data/samples

# 2. Import one into a NEW database (refuses to overwrite)
.venv/bin/python -m packetlens.ingest data/samples/port_scan.pcap data/output/port_scan.db

# 3. Exports
.venv/bin/python -m packetlens.xml_export data/output/port_scan.db data/output/port_scan.xml
.venv/bin/python -m packetlens.report data/output/port_scan.db data/output/port_scan.html

# 4. Dashboard (run from the project folder)
.venv/bin/streamlit run packetlens/dashboard.py
```

The dashboard opens on a cover page: upload a recording, try an example,
or open one of your recent recordings ("← All recordings" in the sidebar
brings you back). It is written for non-technical users. Its tabs are Overview,
Network map (a left-to-right "who sent → what for → who received"
diagram), Activity, Suspicious activity, Details, and Reports. From the
sidebar you can analyse a new recording (upload or example), switch
between saved analyses, and clear history (with a confirmation step).
Saved analyses live in `data/output/`.

`.streamlit/config.toml` sets the look (a quiet light/dark palette, and
the Inter font if installed, otherwise the computer's own interface font)
and makes the dashboard reachable only from this computer
(`address = "localhost"`). Nothing is loaded from the internet, so the
dashboard works offline. The layout follows the Claude Design mockups;
Streamlit cannot reproduce everything exactly (for example, the banner has
no "Review →" link because Streamlit cannot switch tabs from a link).

Report filters: `--ip`, `--port`, `--protocol` (repeatable), `--start-ts`,
`--end-ts`, `--min-length`, `--max-length`, `--l7`. See
`python -m packetlens.report --help`.

## Tests

```bash
.venv/bin/python -m pytest              # full suite, temporary files only
.venv/bin/python -m tests.check_parser  # original assertion scripts still work
.venv/bin/python -m tests.benchmark 50000   # optional timing run
```

The original `tests/check_*.py` scripts are kept. The three that used to
need hand-made databases in `data/output/` now import `demo.pcap` into a
temporary database themselves.

## Sample data

`python -m packetlens.samples DIR` writes six captures using only
documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
2001:db8::/32), fixed timestamps, and synthetic payloads:

| File | Packets | Expected alerts (default settings) |
|---|---|---|
| `normal.pcap` | 33 | none |
| `port_scan.pcap` | 93 | 2 × `port_scan` (IPv4 and IPv6) |
| `host_sweep.pcap` | 37 | 2 × `host_sweep` (ICMP and TCP/22) |
| `burst.pcap` | 2268 | none (legitimate volume burst) |
| `edge_cases.pcap` | 12 | none (fragments, ICMP error, IP-in-IP, truncation, out-of-order) |
| `near_threshold.pcap` | 118 | none (just under the thresholds) |

`manifest.json` records the same, and the test suite checks it.
`data/samples/demo.pcap` is the original 5-packet capture (committed).
Generated samples are git-ignored because they can be reproduced.

## Performance (measured)

On an Apple M3 laptop, Python 3.14.3, with `python -m tests.benchmark
50000` (50,000 mixed TCP/UDP packets, 11 MB capture):

| Stage | Time |
|---|---|
| Import (parse + insert + flows + hosts + detection) | 8.7 s |
| Summary / filtered conversations / timeline queries | ≤ 0.02 s each |
| HTML report | 0.2 s |
| XML export (45.5 MB output) | 0.8 s |

Import throughput here was about 5,800 packets/s (stages inside the import were not timed separately).
The benchmark traffic contains no connection-attempt packets, so the
detection time it shows is not representative of scan-heavy captures.
No larger captures were measured.

## Documentation

- [docs/architecture.md](docs/architecture.md): how data flows through the modules
- [docs/schema.md](docs/schema.md): tables, units, NULLs, filter semantics
- [docs/detection_rules.md](docs/detection_rules.md): rule logic, thresholds, false positives
- [docs/learning_guide.md](docs/learning_guide.md): beginner walkthrough with exercises
- [docs/viva_questions.md](docs/viva_questions.md): questions with answers tied to the code
- [docs/demo_walkthrough.md](docs/demo_walkthrough.md): reproducible demo script

## Limitations

- One capture per database. Re-import to analyse another capture.
- Old databases (schema version 1) are rejected, not migrated. Re-import
  the capture (see [docs/schema.md](docs/schema.md)).
- "Flows" are endpoint conversations over the whole capture, not
  reconstructed TCP sessions.
- No fragment reassembly; only first fragments have ports.
- Tunnels/encapsulation (IP-in-IP, GRE, VXLAN, ...) are recorded by the
  outer header only, as `protocol = 'OTHER'`.
- Encrypted payloads are not decoded. Application labels are either payload
  checks (DNS, HTTP, TLS record header) or port guesses (labelled as such).
- Truncated packets keep NULL for fields that were not captured; byte totals
  are captured bytes (`wire_length` holds on-wire size).
- ARP rows have no IP fields, so ARP sweeps are not detected. UDP and
  FIN/NULL/Xmas scans are not detected.
- Alerts are suspicious-pattern indicators, not proof of malicious
  activity. Detection accuracy on real-world traffic has **not** been
  evaluated; only the synthetic scenarios are tested.
- Traffic-volume charts do not measure congestion, capacity, loss, or
  retransmissions.
- `rebuild_flows` and detection keep per-conversation/per-group state in
  memory; very large captures with millions of conversations were not tested.


