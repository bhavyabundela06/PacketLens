"""Export the stored records of one database to an XML file.

Format (schema_version="2"):

    <packetlens schema_version="2">
      <capture> ...one element per capture_info column... </capture>
      <packets count="N"> <packet> <id>1</id> <ts>...</ts> ... </packet> </packets>
      <flows count="N"> <flow> ... </flow> </flows>
      <hosts count="N"> <host> ... </host> </hosts>
      <alerts count="N"> <alert> ... <evidence>1 2 3</evidence> </alert> </alerts>
    </packetlens>

- Every column becomes a child element in table column order.
- NULL values become an empty element with is_null="true".
- Text is escaped (&, <, >) so values can never break the structure.
- Characters that XML 1.0 forbids (most control characters, e.g. \\x00)
  are replaced with U+FFFD, and the element gets
  replaced_invalid_chars="<how many>". Nothing is silently dropped.

Rows are written one at a time, so memory use stays small even for large
captures. The file is written under a temporary name and only appears
under the final name once it is complete; an existing file is never
overwritten.
"""

import argparse
import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

from packetlens.database import SchemaVersionError, connect

XML_SCHEMA_VERSION = "2"

# Everything outside the XML 1.0 "Char" production.
INVALID_XML_CHARS = re.compile(
    "[^\u0009\u000a\u000d -퟿-�\U00010000-\U0010ffff]"
)

SECTIONS = (
    ("packets", "packet", "id"),
    ("flows", "flow", "flow_id"),
    ("hosts", "host", "ip"),
    ("alerts", "alert", "alert_id"),
)


def clean_xml_text(value):
    """Return (safe_text, number_of_replaced_characters)."""
    text, replaced = INVALID_XML_CHARS.subn("�", str(value))
    return escape(text), replaced


def _field(name, value, indent):
    if value is None:
        return f'{indent}<{name} is_null="true" />\n'

    text, replaced = clean_xml_text(value)
    attribute = f' replaced_invalid_chars="{replaced}"' if replaced else ""
    return f"{indent}<{name}{attribute}>{text}</{name}>\n"


def _write_row(output, item_name, row, indent="    "):
    output.write(f"{indent}<{item_name}>\n")
    for column in row.keys():
        output.write(_field(column, row[column], indent + "  "))


def export_xml(db_path, output_path):
    """Export capture info, packets, flows, hosts, and alerts to XML.

    Returns a dict of row counts per section.
    """
    db_path = Path(db_path).resolve()
    output_path = Path(output_path)

    if not db_path.is_file():
        raise FileNotFoundError(f"Database not found: {db_path}")

    if output_path.exists():
        raise FileExistsError(f"Output already exists: {output_path}")

    # Read-only mode prevents accidental changes to the database.
    connection = connect(db_path, read_only=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".partial",
        dir=output_path.parent,
    )
    temporary = Path(temporary_name)
    counts = {}

    try:
        # Keep all sections consistent while reading.
        connection.execute("BEGIN")

        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as output:
            output.write('<?xml version="1.0" encoding="utf-8"?>\n')
            output.write(
                f"<packetlens schema_version={quoteattr(XML_SCHEMA_VERSION)}>\n"
            )

            capture = connection.execute("SELECT * FROM capture_info").fetchone()
            if capture is not None:
                output.write("  <capture>\n")
                for column in capture.keys():
                    output.write(_field(column, capture[column], "    "))
                output.write("  </capture>\n")

            for table, item_name, order_column in SECTIONS:
                count = connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
                counts[table] = count
                output.write(f'  <{table} count="{count}">\n')

                # Table and column names come only from the fixed list above.
                rows = connection.execute(
                    f"SELECT * FROM {table} ORDER BY {order_column}"
                )

                for row in rows:
                    _write_row(output, item_name, row)

                    if table == "alerts":
                        evidence = connection.execute(
                            "SELECT packet_id FROM alert_evidence "
                            "WHERE alert_id = ? ORDER BY packet_id",
                            (row["alert_id"],),
                        ).fetchall()
                        ids = " ".join(str(item[0]) for item in evidence)
                        output.write(f"      <evidence>{ids}</evidence>\n")

                    output.write(f"    </{item_name}>\n")

                output.write(f"  </{table}>\n")

            output.write("</packetlens>\n")

        # A hard link refuses to replace a file created in the meantime.
        try:
            os.link(temporary, output_path)
        except FileExistsError:
            raise FileExistsError(
                f"Output already exists: {output_path}"
            ) from None
        except OSError:
            if output_path.exists():
                raise FileExistsError(
                    f"Output already exists: {output_path}"
                ) from None
            os.replace(temporary, output_path)
    finally:
        connection.close()
        temporary.unlink(missing_ok=True)

    return counts


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Export a PacketLens database to a new XML file."
    )
    parser.add_argument("database", type=Path)
    parser.add_argument("output", type=Path, help="new .xml file to create")
    args = parser.parse_args(argv)

    try:
        counts = export_xml(args.database, args.output)
    except (FileNotFoundError, FileExistsError, SchemaVersionError,
            sqlite3.DatabaseError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    summary = ", ".join(f"{count} {name}" for name, count in counts.items())
    print(f"Wrote {args.output}: {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
