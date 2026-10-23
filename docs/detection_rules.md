# Detection rules

Code: [`packetlens/detection.py`](../packetlens/detection.py).
Tests: [`tests/test_detection.py`](../tests/test_detection.py).

PacketLens alerts are **suspicious-pattern indicators**. An alert says
"this traffic looks like what a scan typically produces", which is not proof
that anyone was attacking. Each alert records its evidence packets so a person
can check it.

## Terms

- **TCP SYN without ACK**: the first packet of a TCP connection attempt
  (`tcp_flags & 2 != 0` and `tcp_flags & 16 == 0`). A SYN+ACK (flags 18) is a
  server's *reply*, so it is not counted.
- **ICMP echo request**: a "ping" (IPv4 type 8, ICMPv6 type 128). Echo
  *replies* (0 / 129) are not counted.
- **Window**: a time span of `window_seconds`. Two events are in the same
  window when `later.ts − earlier.ts ≤ window_seconds`. The boundary is
  **inclusive**, so events exactly 10.0 s apart are inside a 10 s window, and
  10.001 s apart are not.
- **Episode**: consecutive window positions that all meet the threshold,
  merged into **one** alert. A 5-minute scan therefore gives one alert, not
  thousands.

## Rule 1: `port_scan`

**Question:** did one source try to connect to many different ports on the
same destination within a short time?

- Events: TCP SYN-without-ACK packets with both IPs and a destination port.
- Grouped by: `(src_ip, dst_ip)`.
- Counted: distinct `dst_port` values in the window.
- Defaults: `port_scan_ports = 20`, `port_scan_window = 10` s.

## Rule 2: `host_sweep`

**Question:** did one source try to reach many different hosts within a
short time?

- Events: TCP SYN-without-ACK, ICMP echo request, ICMPv6 echo request.
- Grouped by: `src_ip` (and `dst_ip` is stored as NULL in the alert).
- Counted: distinct `dst_ip` values in the window.
- Defaults: `host_sweep_hosts = 10`, `host_sweep_window = 10` s.

UDP and ARP are **not** counted (see "Not covered" below).

## Algorithm (both rules)

`find_episodes(events, threshold, window)`, a *sliding window* with two
pointers:

1. Sort the group's events by `(ts, packet id)`.
2. Move `right` forward one event at a time and add its target (port or
   host) to a counter.
3. Move `left` forward while `events[right].ts − events[left].ts > window`,
   removing those targets.
4. `distinct = number of different targets in the counter`.
5. If `distinct ≥ threshold`, the episode starts (or continues). When it
   drops below, the episode ends and becomes one alert.

The cost is O(n log n) for sorting plus O(n) for the scan per group.

Each alert stores:

| Field | Value |
|---|---|
| `start_ts` / `end_ts` | first / last event of the episode |
| `metric_value` | **peak** distinct count in any single window |
| `threshold`, `window_seconds` | settings used |
| `severity` | `high` if peak ≥ 2 × threshold, otherwise `medium` |
| `explanation` | plain-language sentence, including the total distinct targets over the episode |
| evidence | every event packet in the episode (`alert_evidence`) |

## Reruns and duplicates

`run_detection(db, config)` deletes all stored alerts and evidence and
inserts the fresh results **in one transaction**. Running it twice gives the
same rows. Running it with new thresholds replaces the old alerts. The
settings are saved in `metadata` and shown in the dashboard and report.

Detection always uses the **whole capture**. Dashboard filters only choose
which stored alerts to display (see [schema.md](schema.md#filter-semantics-queriespy-dashboard-report)).

## Worked examples (from the synthetic samples)

| Capture | What happens | Alerts (defaults) |
|---|---|---|
| `port_scan.pcap` | 203.0.113.66 sends SYNs to ports 20–49 of 198.51.100.20 at 0.1 s spacing (30 ports in 2.9 s) | `port_scan`, medium (peak 30 < 40) |
| | 2001:db8:bad::66 sends SYNs to 25 ports of 2001:db8::20 in 4.8 s | `port_scan`, medium |
| `host_sweep.pcap` | 203.0.113.77 pings 192.0.2.1–20 in 3.8 s | `host_sweep`, high (peak 20 ≥ 20) |
| | 30 s later, SYNs to port 22 on 12 hosts in 5.5 s | `host_sweep`, medium |
| `near_threshold.pcap` | 19 ports in 9 s | none (19 < 20) |
| | 10 ports, a 20 s gap, then 10 more ports | none (never 20 in one window) |
| | a server sending SYN+ACK to 30 ports | none (ACK set = reply) |
| | 9 hosts pinged | none (9 < 10) |
| | UDP to 40 ports | none (UDP not counted) |
| `burst.pcap` | 2000 data packets in about 2 s inside one conversation, plus 30 s of one ping per second | none (volume is not a scan) |

## False positives (legitimate traffic that can trigger)

- Vulnerability scanners and inventory tools run by administrators.
- Monitoring systems that ping or probe many hosts (Nagios-style checks).
- Service discovery, or a client trying many ports of a server it knows.
- Peer-to-peer software connecting to many peers (host sweep).
- A NAT gateway: many internal users appear as one source IP.

## False negatives (scans these rules miss)

- Slow scans that stay under the threshold per window.
- Scans spread across many source IPs (distributed scans).
- UDP scans, and TCP FIN/NULL/Xmas scans (no SYN).
- ARP sweeps (ARP rows have no IP fields in this schema).
- Anything in fragments after the first, or inside tunnels.

## Exercises

1. Open `tests/test_detection.py::test_port_scan_window_boundary`. Change
   `10.5` to `10.0`. Predict whether the test still passes, then run it.
2. Run detection on `near_threshold.db` with `port_scan_ports=19`. How many
   alerts appear and why? (Answer: at least one port scan for the 19-port
   pattern. Check the explanation text.)
3. Add UDP to the host-sweep events (one more `OR` line in
   `detect_host_sweeps`). Which sample now alerts? Undo it afterwards.
