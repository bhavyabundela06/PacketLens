"""Import one PCAP/PCAPNG capture into a NEW SQLite database.

Steps: parse packets -> insert -> rebuild flows and hosts -> run the
detection rules -> record capture_info. All of this is written to a
temporary file next to the target, and the temporary file is renamed to
the requested name only after every step succeeded. A failed import
therefore never leaves a database that looks complete.
"""

import argparse
import hashlib
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from packetlens.database import create_database, insert_packets
from packetlens.detection import DetectionConfig, run_detection
from packetlens.flows import rebuild_flows
from packetlens.hosts import rebuild_hosts
from packetlens.parser import CaptureReadError, read_packets

PARSER_VERSION = "2"


class IngestError(Exception):
    """Raised when a capture cannot be imported."""


def file_sha256(path) -> str:
    digest = hashlib.sha256()

    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def _publish_without_overwrite(temporary: Path, final: Path) -> None:
    """Move temporary -> final, refusing to replace an existing file."""
    try:
        # A hard link fails if "final" already exists, even if another
        # program created it a moment ago.
        os.link(temporary, final)
    except FileExistsError:
        raise IngestError(f"Output already exists: {final}") from None
    except OSError:
        # Some filesystems (e.g. FAT USB drives) have no hard links.
        if final.exists():
            raise IngestError(f"Output already exists: {final}") from None
        os.replace(temporary, final)
        return

    temporary.unlink()


def ingest_capture(capture_path, db_path, detection_config=None,
                   source_name=None) -> dict:
    """Import capture_path into a new database at db_path.

    Returns counts for packets, flows, hosts, and alerts.
    source_name lets callers (e.g. the dashboard upload) record the
    user's original file name instead of a temporary path.
    """
    capture_path = Path(capture_path)
    db_path = Path(db_path)

    if not capture_path.is_file():
        raise IngestError(f"Capture not found: {capture_path}")

    if db_path.exists():
        raise IngestError(
            f"Output database already exists: {db_path}. "
            "Choose a new filename."
        )

    db_path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{db_path.name}.", suffix=".partial", dir=db_path.parent
    )
    os.close(handle)
    temporary = Path(temporary_name)
    temporary.unlink()  # create_database makes a fresh file at this path

    try:
        create_database(temporary)
        packet_count = insert_packets(temporary, read_packets(capture_path))
        flow_count = rebuild_flows(temporary)
        host_count = rebuild_hosts(temporary)
        alert_count = run_detection(
            temporary, detection_config or DetectionConfig()
        )

        connection = sqlite3.connect(temporary)
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO capture_info (
                        id, source_name, source_sha256, source_bytes,
                        packet_count, imported_at, parser_version
                    ) VALUES (1, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source_name or capture_path.name,
                        file_sha256(capture_path),
                        capture_path.stat().st_size,
                        packet_count,
                        datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        PARSER_VERSION,
                    ),
                )
        finally:
            connection.close()

        _publish_without_overwrite(temporary, db_path)
    except CaptureReadError as error:
        raise IngestError(str(error)) from error
    except sqlite3.Error as error:
        raise IngestError(f"Database error during import: {error}") from error
    finally:
        # Only our own temporary file is ever removed here.
        temporary.unlink(missing_ok=True)
        for suffix in ("-journal", "-wal", "-shm"):
            Path(str(temporary) + suffix).unlink(missing_ok=True)

    return {
        "packets": packet_count,
        "flows": flow_count,
        "hosts": host_count,
        "alerts": alert_count,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Import a PCAP capture into a new SQLite database."
    )
    parser.add_argument("capture", type=Path, help="input .pcap/.pcapng file")
    parser.add_argument("database", type=Path, help="new .db file to create")
    args = parser.parse_args(argv)

    try:
        counts = ingest_capture(args.capture, args.database)
    except IngestError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(f"Imported {counts['packets']} packets into {args.database}")
    print(f"Created {counts['flows']} flows")
    print(f"Created {counts['hosts']} host summaries")
    print(f"Created {counts['alerts']} alerts (default detection settings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
