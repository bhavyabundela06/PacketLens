"""SQLite helpers: create the schema, insert packets, open databases safely."""

import sqlite3
from pathlib import Path


SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema.sql"

# Stored in SQLite's built-in "PRAGMA user_version". Version 1 is the
# original schema (no capture_info/alerts tables, user_version left at 0).
SCHEMA_VERSION = 2

PACKET_COLUMNS = (
    "ts", "src_mac", "dst_mac", "src_ip", "dst_ip", "ip_version",
    "ip_proto", "src_port", "dst_port", "protocol", "length",
    "wire_length", "payload_length", "ttl", "is_fragment",
    "tcp_flags", "tcp_seq", "tcp_ack", "tcp_window",
    "icmp_type", "icmp_code", "l7_proto", "l7_basis", "info",
)


class SchemaVersionError(Exception):
    """The database was made by a different PacketLens schema version."""


def create_database(db_path: str | Path) -> None:
    """Create a SQLite database using the project's schema."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    schema = SCHEMA_PATH.read_text(encoding="utf-8")

    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(schema)
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        connection.commit()
    finally:
        connection.close()


def insert_packets(db_path, records, batch_size=1000) -> int:
    """Insert parsed packets in batches and return the inserted count.

    Everything happens in one transaction: if any record fails, no
    packets are kept.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be positive")

    # Named placeholders (:ts, :src_ip, ...) keep values out of the SQL text.
    sql = (
        f"INSERT INTO packets ({', '.join(PACKET_COLUMNS)}) "
        f"VALUES ({', '.join(':' + name for name in PACKET_COLUMNS)})"
    )

    connection = sqlite3.connect(db_path)
    inserted = 0
    batch = []

    try:
        with connection:
            for record in records:
                batch.append(record)

                if len(batch) >= batch_size:
                    connection.executemany(sql, batch)
                    inserted += len(batch)
                    batch.clear()

            if batch:
                connection.executemany(sql, batch)
                inserted += len(batch)

        return inserted
    finally:
        connection.close()


def schema_version(connection) -> int:
    return connection.execute("PRAGMA user_version").fetchone()[0]


def check_schema(connection) -> None:
    """Raise SchemaVersionError unless the database uses SCHEMA_VERSION.

    Old databases are never changed automatically. Re-import the original
    capture with `python -m packetlens.ingest` to get the current schema.
    """
    version = schema_version(connection)

    if version != SCHEMA_VERSION:
        raise SchemaVersionError(
            f"Database schema version is {version or 1}, but this version "
            f"of PacketLens needs version {SCHEMA_VERSION}. The file was "
            "left unchanged. Re-import the original capture into a new "
            "database with: python -m packetlens.ingest CAPTURE NEW.db"
        )


def connect(db_path, read_only=False) -> sqlite3.Connection:
    """Open an existing PacketLens database and check its schema version.

    read_only=True opens SQLite in read-only mode, so no statement on this
    connection can change the file.
    """
    db_path = Path(db_path).resolve()

    if not db_path.is_file():
        raise FileNotFoundError(f"Database not found: {db_path}")

    if read_only:
        connection = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
    else:
        connection = sqlite3.connect(db_path)

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    try:
        check_schema(connection)
    except Exception:
        connection.close()
        raise

    return connection
