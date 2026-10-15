import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path


def export_xml(db_path, output_path):
    """Export packets, flows, and hosts from SQLite to XML."""
    db_path = Path(db_path).resolve()
    output_path = Path(output_path)

    if not db_path.is_file():
        raise FileNotFoundError(f"Database not found: {db_path}")

    if output_path.exists():
        raise FileExistsError(f"Output already exists: {output_path}")

    # Read-only mode prevents accidental changes to the database.
    connection = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row

    root = ET.Element("packetlens", schema_version="1")
    counts = {}

    sections = (
        ("packets", "packet", "id"),
        ("flows", "flow", "flow_id"),
        ("hosts", "host", "ip"),
    )

    try:
        # Keep all three sections consistent while reading.
        connection.execute("BEGIN")

        for table, item_name, order_column in sections:
            section = ET.SubElement(root, table)
            count = 0

            # Table and column names come only from the fixed list above.
            rows = connection.execute(
                f"SELECT * FROM {table} ORDER BY {order_column}"
            )

            for row in rows:
                item = ET.SubElement(section, item_name)

                for column in row.keys():
                    field = ET.SubElement(item, column)
                    value = row[column]

                    if value is None:
                        field.set("is_null", "true")
                    else:
                        field.text = str(value)

                count += 1

            section.set("count", str(count))
            counts[table] = count
    finally:
        connection.close()

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # "xb" creates a new file and refuses to overwrite an existing one.
    with output_path.open("xb") as output:
        tree.write(output, encoding="utf-8", xml_declaration=True)

    return counts