# Demo walkthrough

A reproducible demonstration using only the bundled synthetic captures.
Run every command from the project folder. Allow about 5 minutes.

## 1. Generate the sample captures

```bash
.venv/bin/python -m packetlens.samples data/samples
```

Expected output (the counts are fixed because the generator is
deterministic):

```
normal.pcap: 33 packets, 0 expected alerts
port_scan.pcap: 93 packets, 2 expected alerts
host_sweep.pcap: 37 packets, 2 expected alerts
burst.pcap: 2268 packets, 0 expected alerts
edge_cases.pcap: 12 packets, 0 expected alerts
near_threshold.pcap: 118 packets, 0 expected alerts
```

`data/samples/manifest.json` lists the same expectations. If the files
already exist, the command refuses to overwrite them; add `--overwrite`.

## 2. Import captures

```bash
.venv/bin/python -m packetlens.ingest data/samples/normal.pcap data/output/normal.db
.venv/bin/python -m packetlens.ingest data/samples/port_scan.pcap data/output/port_scan.db
.venv/bin/python -m packetlens.ingest data/samples/host_sweep.pcap data/output/host_sweep.db
```

Talking points:
- Show that a second run of the same command refuses because the output
  exists.
- Show `.venv/bin/python -m packetlens.ingest README.md data/output/bad.db`:
  clean error, and no `bad.db` is created.

## 3. Look at the data with SQL

```bash
sqlite3 data/output/normal.db "SELECT protocol, l7_proto, l7_basis, COUNT(*) FROM packets GROUP BY 1,2,3"
sqlite3 data/output/port_scan.db "SELECT rule, severity, src_ip, dst_ip, metric_value FROM alerts"
```

Explain `l7_basis` (payload versus port guess) and why the scan alerts are
medium (peak 30 and 25 are below 2 × 20).

## 4. Dashboard

Run it from the project folder, so the theme in `.streamlit/config.toml`
(font, colours, localhost-only) is used:

```bash
.venv/bin/streamlit run packetlens/dashboard.py
```

The dashboard uses plain words: **messages** = packets, **devices** = IP
addresses, **services** = what a port is normally used for.

1. Pick `normal.pcap` under **Recording** in the sidebar. The green banner
   says no suspicious patterns were found. **Overview**: 33 messages,
   5 devices, a "Kinds of traffic" donut, the most active devices, and "What
   the traffic was for" (web, DNS, ping, ...).
2. Open the **Focus** line (it reads "Everything · 5 devices · …") and
   choose the service *Name lookup (DNS) · port 53*. Every number and chart
   updates to the 2 DNS messages, and the Focus line now shows that choice.
   Click **Clear focus**.
3. Switch to `port_scan.pcap`. The red row says 2 suspicious patterns were
   found, and the opening sentence names the flagged device in red.
4. **Network map**: read it left to right (who sent → what for → who
   received). The two scanners are red, and their red lines fan out across
   many services. Switch **Detail** between Simple and Detailed.
5. **Suspicious activity**: one card per finding, with a big number, a
   plain sentence, a dot chart (each dot is one attempt), what it means,
   whether it could be harmless, and the evidence. In the evidence, the
   **Result** column comes from the target's replies: here every IPv4
   attempt was answered with a refusal ("closed"), and the IPv6 target
   never answered ("no answer").
6. Under **Detection settings**, ask the audience to predict: with
   "Port scan: doors" set to `26`, which findings remain? Save: only the
   IPv4 scan (30 ports) remains; the IPv6 scan (25 ports) disappears. Set it
   back to 20 and save again.
7. Analyse `burst.pcap` from **Analyse a new recording** (or pick it under
   Recording). **Activity** shows one shaded 2-second burst, and there are no
   findings, because a big transfer is not a scan.
8. **Details → Ask a question**: run a ready-made question, then type
   `DELETE FROM packets` to show it is refused.
9. **Reports**: download the findings report and the XML export.
10. **History** (sidebar): one checkbox per saved analysis, all unticked.
    Removing needs at least one ticked analysis *and* the confirmation tick.
    (Do this last, or on copies.)

## 5. Command-line exports

```bash
.venv/bin/python -m packetlens.xml_export data/output/port_scan.db data/output/port_scan.xml
.venv/bin/python -m packetlens.report data/output/port_scan.db data/output/port_scan-report.html
.venv/bin/python -m packetlens.report data/output/normal.db data/output/normal-udp.html --protocol UDP
```

Open the HTML files in a browser. The "Scope" section states the filter.

## 6. Tests

```bash
.venv/bin/python -m pytest
```

## Clean up

The demo writes only to `data/output/` (ignored by git). Delete the demo
files there yourself when you are done.
