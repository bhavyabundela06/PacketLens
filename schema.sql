CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,

    src_mac TEXT,
    dst_mac TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    ip_version INTEGER,

    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,

    length INTEGER NOT NULL,
    payload_length INTEGER,
    ttl INTEGER,

    tcp_flags INTEGER,
    tcp_seq INTEGER,
    tcp_ack INTEGER,
    tcp_window INTEGER,

    l7_proto TEXT,
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