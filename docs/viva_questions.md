# Viva questions

Each answer points to the code that implements it. Read the code to check
the answer instead of memorising it.

## Overall design

**1. What does PacketLens do, and what does it deliberately not do?**
It analyses a *saved* capture offline: PCAP → SQLite → summaries, rules,
dashboard, XML, report. It does no live capture, sends no packets, uses no
machine learning, and does no active scanning. The synthetic samples are
built in memory and written with `wrpcap`; nothing is transmitted.

**2. Why SQLite?**
It is one file per capture, needs no server, ships with Python (`sqlite3`),
and supports SQL `GROUP BY`/indexes for the analysis queries. One database =
one capture keeps the schema simple (`capture_info.id CHECK (id = 1)`).

**3. Walk through an import.** `ingest.ingest_capture`: parse (generator) →
`insert_packets` (batched, one transaction) → `rebuild_flows` →
`rebuild_hosts` → `run_detection` → `capture_info`, written to a
`.partial` file and hard-linked into place at the end.

**4. What happens if the import fails halfway?**
The exception reaches the `finally:` in `ingest_capture`, which deletes the
temporary file. The real filename never appeared, so nothing looks imported.
Tested by `test_invalid_capture_leaves_no_output`.

**5. How do you avoid overwriting files?**
`ingest` and `xml_export` refuse an existing target and publish with
`os.link` (fails if the name exists). `report.write_report` opens with mode
`"x"`.

## Parsing

**6. Why not use `TCP in packet`?**
Scapy's `in` searches every layer. An IP-in-IP packet contains an inner TCP
header, so the old code stored outer IPs with inner ports. The parser now
reads only the transport header directly after the outer IP header
(`_outer_network_layer`, `_parse_transport`). Test:
`test_ip_in_ip_keeps_outer_header_only`.

**7. How are ICMP error messages handled?**
They contain a quoted copy of the original packet. The packet is labelled
ICMP with its own type/code, and the quoted ports are ignored
(`test_icmp_error_does_not_use_quoted_ports`).

**8. What about fragments?**
Not reassembled. `is_fragment = 1`; only the first fragment (offset 0) gets
ports; later ones are `protocol='OTHER'` with `ip_proto` kept and NULL
ports, because their bytes are not a transport header.

**9. What is the difference between `length` and `wire_length`?**
`length` = bytes saved in the file; `wire_length` = original size from the
pcap record. They differ only for truncated captures. All byte totals use
`length`, so they say "captured bytes".

**10. How is the application protocol decided?**
`l7_basis='payload'` when content matches (Scapy parsed DNS with no leftover
bytes; HTTP request/response line; TLS record header). `l7_basis='port'` is
only a well-known-port guess. Otherwise NULL (unknown). See
`_identify_application`.

**11. Which IPv6 extension headers are supported?**
Hop-by-Hop, Routing, Destination Options, Fragment (`IPV6_EXTENSION_HEADERS`).
The parser follows the `nh` (next header) chain to the real transport.

## Storage and summaries

**12. What is a "flow" here? Is it a TCP session?**
No. It is an *endpoint conversation*: all packets with the same protocol and
the same pair of `(ip, port)` endpoints, in either direction, over the whole
capture. SYN/FIN do not split it.

**13. How do both directions end up in one flow?**
`flow_key` sorts the two endpoints; the smaller is A. The same rule is
written in SQL (`_SRC_IS_A` in `queries.py`) and tested to agree.

**14. Why is rebuilding flows twice safe?**
`DELETE FROM flows` then insert, inside one transaction.

**15. What happens to an old database after the schema change?**
`connect` checks `PRAGMA user_version`; a mismatch raises
`SchemaVersionError` and nothing is modified. Re-import into a new file.

## Queries and filters

**16. How do you guarantee the charts and tables agree?**
One function, `filter_sql`, builds every `WHERE` clause. Filtered hosts and
conversations are recomputed from filtered packets.
`test_all_views_describe_same_subset` checks the totals match for 8
filters.

**17. How do alerts interact with filters?**
Alerts are computed on the whole capture. Filters select alerts whose IPs
match, whose interval overlaps the time range, or that have an evidence
packet matching the other filters (`queries.alerts`).

**18. Is the SQL console safe?**
Three layers: SQLite read-only mode, an authorizer that allows only
`SELECT`/`READ`/`FUNCTION` actions (so `PRAGMA`, `ATTACH`, writes are
denied), and a progress handler that stops queries after 2 s. Results are
capped at 500 rows. Python's `sqlite3` refuses multiple statements. Tests
try 12 harmful statements and check the file hash is unchanged.

**19. Why not just check that the text starts with SELECT?**
`WITH x AS (...) DELETE ...` starts with `WITH`; `SELECT ...; DROP ...` starts
with SELECT; a SELECT can still be endlessly expensive. The authorizer
checks what SQLite would actually *do*, not the text.

## Detection

**20. Explain the port-scan rule.**
Events = TCP SYN without ACK; group by (src, dst); count distinct
destination ports in a sliding window (inclusive boundary); alert when
count ≥ threshold (default 20 in 10 s). Consecutive qualifying windows merge
into one alert.

**21. Why SYN without ACK?**
A SYN starts a connection attempt. SYN+ACK is the server's reply. Counting
replies would flag busy servers (`test_syn_ack_replies_are_not_scans`).

**22. What is the boundary behaviour?**
`later - earlier ≤ window` counts as same window. Tested with events exactly
10.0 s apart (alert) and 10.5 s apart (no alert).

**23. How do you avoid duplicate alerts?**
`run_detection` replaces all alerts in one transaction; episodes merge
consecutive windows; a `UNIQUE (rule, src_ip, dst_ip, start_ts)` constraint
backs it up.

**24. Give false positives and false negatives.**
See [detection_rules.md](detection_rules.md): monitoring tools and NAT
gateways (FP); slow, distributed, UDP, or FIN scans (FN).

**25. Is an alert proof of an attack?**
No. It is a suspicious-pattern indicator with evidence packets for a person
to review.

## Testing and limits

**26. How is the project tested?**
pytest with temporary files only (`tests/conftest.py`). Synthetic captures
from `samples.py` have a manifest of expected packet and alert counts, and
`test_end_to_end_counts_match_manifest` checks every capture.

**27. Why synthetic data?**
It is deterministic (fixed timestamps), safe (documentation IP ranges, no
real users), and every expected result is known in advance.

**28. What does the traffic chart *not* show?**
Congestion, capacity, packet loss, or retransmissions. It shows captured
packets/bytes per time bucket. "Burst indicator" just marks buckets above
a multiple of the mean.

**29. What would you improve next?**
Real TCP session tracking (SYN/FIN/RST state), fragment reassembly, a UDP
scan rule, multiple captures per database, pagination for very large
exports, and validation against labelled public datasets.
