import sqlite3
from pathlib import Path


SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema.sql"


def create_database(db_path: str | Path) -> None:
    """Create a SQLite database using the project's schema."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    schema = SCHEMA_PATH.read_text(encoding="utf-8")

    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(schema)
        connection.commit()
    finally:
        connection.close()

def insert_packets(db_path, records, batch_size=1000) -> int:
    """Insert parsed packets in batches and return the inserted count."""
    if batch_size < 1:
        raise ValueError("batch_size must be positive")

    columns = (
        "ts", "src_mac", "dst_mac", "src_ip", "dst_ip", "ip_version",
        "src_port", "dst_port", "protocol", "length", "payload_length",
        "ttl", "tcp_flags", "tcp_seq", "tcp_ack", "tcp_window",
        "l7_proto", "info",
    )

    sql = (
        f"INSERT INTO packets ({', '.join(columns)}) "
        f"VALUES ({', '.join(':' + name for name in columns)})"
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