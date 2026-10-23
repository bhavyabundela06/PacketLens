"""List and delete previously analysed captures (the dashboard's history).

A "capture" in the history is one .db file directly inside the output
folder. Deleting only ever touches such files (plus SQLite's own
-journal/-wal/-shm side files); paths outside the folder are refused.
"""

import sqlite3
from pathlib import Path

from packetlens.database import SCHEMA_VERSION


def list_captures(output_dir):
    """Return one dict per .db file in output_dir, newest first.

    status is 'ok', 'old' (older schema: needs re-import), or 'unreadable'.
    """
    output_dir = Path(output_dir)
    entries = []

    for path in sorted(output_dir.glob("*.db"), key=lambda p: p.stat().st_mtime,
                       reverse=True):
        entry = {"path": path, "file": path.name, "source_name": path.name,
                 "imported_at": None, "packets": None, "findings": None,
                 "status": "unreadable"}
        try:
            connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
            try:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version != SCHEMA_VERSION:
                    entry["status"] = "old"
                else:
                    row = connection.execute(
                        "SELECT source_name, imported_at, packet_count FROM capture_info"
                    ).fetchone()
                    entry["status"] = "ok"
                    if row:
                        entry["source_name"], entry["imported_at"], entry["packets"] = row
                    entry["findings"] = connection.execute(
                        "SELECT COUNT(*) FROM alerts").fetchone()[0]
            finally:
                connection.close()
        except sqlite3.DatabaseError:
            pass
        entries.append(entry)

    return entries


def delete_captures(paths, output_dir):
    """Permanently delete the given .db files from output_dir.

    Returns the number of databases deleted. Raises ValueError (and deletes
    nothing) if any path is not a .db file directly inside output_dir.
    """
    folder = Path(output_dir).resolve()
    targets = []

    for path in paths:
        path = Path(path).resolve()
        if path.parent != folder or path.suffix != ".db":
            raise ValueError(f"Refusing to delete {path}: not a database in {folder}")
        targets.append(path)

    deleted = 0
    for path in targets:
        if path.exists():
            path.unlink()
            deleted += 1
        for suffix in ("-journal", "-wal", "-shm"):
            Path(str(path) + suffix).unlink(missing_ok=True)

    return deleted
