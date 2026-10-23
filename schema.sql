-- PacketLens schema, version 2. One capture per database file.
-- Field meanings, units, and NULL rules are documented in docs/schema.md.
--
-- Timestamps (ts, start_ts, end_ts, first_seen, last_seen) are seconds
-- since the Unix epoch (UTC), stored as REAL with sub-second precision.
-- "length" / "byte_count" / "bytes_*" are CAPTURED bytes (what is in the
-- file). "wire_length" is the original on-wire length from the capture
-- header; it is larger than "length" only when the capture was truncated.

CREATE TABLE IF NOT EXISTS capture_info (
    -- Exactly one row describing the imported capture.
    id INTEGER PRIMARY KEY CHECK (id = 1),
    source_name TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    source_bytes INTEGER NOT NULL,
    packet_count INTEGER NOT NULL,
    imported_at TEXT NOT NULL,
    parser_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,

    src_mac TEXT,
    dst_mac TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    ip_version INTEGER CHECK (ip_version IN (4, 6)),
    ip_proto INTEGER,

    src_port INTEGER CHECK (src_port BETWEEN 0 AND 65535),
    dst_port INTEGER CHECK (dst_port BETWEEN 0 AND 65535),
    protocol TEXT NOT NULL
        CHECK (protocol IN ('TCP', 'UDP', 'ICMP', 'ICMPv6', 'ARP', 'OTHER')),

    length INTEGER NOT NULL CHECK (length >= 0),
    wire_length INTEGER NOT NULL CHECK (wire_length >= length),
    payload_length INTEGER,
    ttl INTEGER,
    is_fragment INTEGER NOT NULL DEFAULT 0 CHECK (is_fragment IN (0, 1)),

    tcp_flags INTEGER,
    tcp_seq INTEGER,
    tcp_ack INTEGER,
    tcp_window INTEGER,

    icmp_type INTEGER,
    icmp_code INTEGER,

    l7_proto TEXT,
    l7_basis TEXT CHECK (l7_basis IN ('payload', 'port')),
    info TEXT
);

CREATE INDEX IF NOT EXISTS idx_packets_ts
    ON packets(ts);

CREATE INDEX IF NOT EXISTS idx_packets_src_ip
    ON packets(src_ip);

CREATE INDEX IF NOT EXISTS idx_packets_dst_ip
    ON packets(dst_ip);

CREATE INDEX IF NOT EXISTS idx_packets_dst_port
    ON packets(dst_port);

CREATE INDEX IF NOT EXISTS idx_packets_protocol
    ON packets(protocol);

-- "flows" are ENDPOINT CONVERSATIONS: all packets between the same two
-- (IP, port) endpoints with the same protocol, over the whole capture.
-- They are not reconstructed TCP sessions: two separate connections that
-- reuse the same ports are counted as one conversation.
CREATE TABLE IF NOT EXISTS flows (
    flow_id INTEGER PRIMARY KEY,
    protocol TEXT NOT NULL,

    a_ip TEXT NOT NULL,
    a_port INTEGER NOT NULL,
    b_ip TEXT NOT NULL,
    b_port INTEGER NOT NULL,

    start_ts REAL NOT NULL,
    end_ts REAL NOT NULL,
    duration REAL NOT NULL CHECK (duration >= 0),

    packet_count INTEGER NOT NULL,
    byte_count INTEGER NOT NULL,
    packets_a_to_b INTEGER NOT NULL,
    packets_b_to_a INTEGER NOT NULL,
    bytes_a_to_b INTEGER NOT NULL,
    bytes_b_to_a INTEGER NOT NULL,

    UNIQUE (protocol, a_ip, a_port, b_ip, b_port)
);

CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY NOT NULL,
    pkts_sent INTEGER NOT NULL,
    pkts_recv INTEGER NOT NULL,
    bytes_sent INTEGER NOT NULL,
    bytes_recv INTEGER NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL
);

-- Detection results for the WHOLE capture. Rerunning detection replaces
-- every row, so the same analysis never produces duplicates.
CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    src_ip TEXT NOT NULL,
    dst_ip TEXT,
    start_ts REAL NOT NULL,
    end_ts REAL NOT NULL,
    metric_name TEXT NOT NULL,
    metric_value INTEGER NOT NULL,
    threshold INTEGER NOT NULL,
    window_seconds REAL NOT NULL,
    explanation TEXT NOT NULL,
    UNIQUE (rule, src_ip, dst_ip, start_ts)
);

-- Which stored packets support each alert.
CREATE TABLE IF NOT EXISTS alert_evidence (
    alert_id INTEGER NOT NULL
        REFERENCES alerts(alert_id) ON DELETE CASCADE,
    packet_id INTEGER NOT NULL
        REFERENCES packets(id),
    PRIMARY KEY (alert_id, packet_id)
);

-- Key/value notes, e.g. the detection settings used for the stored alerts.
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
