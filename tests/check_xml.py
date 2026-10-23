import sqlite3
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from packetlens.xml_export import export_xml


from packetlens.ingest import ingest_capture

project_root = Path(__file__).resolve().parent.parent

# Self-contained: import the committed demo capture into a temporary database.
_temporary = tempfile.TemporaryDirectory()
db_path = Path(_temporary.name) / "demo.db"
ingest_capture(project_root / "data/samples/demo.pcap", db_path)

connection = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
connection.row_factory = sqlite3.Row

try:
    with tempfile.TemporaryDirectory() as temporary_directory:
        output = Path(temporary_directory) / "export.xml"

        counts = export_xml(db_path, output)
        assert counts == {"packets": 5, "flows": 2, "hosts": 2, "alerts": 0}

        # Reading it back also verifies that the XML is well formed.
        root = ET.parse(output).getroot()
        assert root.tag == "packetlens"
        assert root.get("schema_version") == "2"

        sections = (
            ("packets", "packet", "id"),
            ("flows", "flow", "flow_id"),
            ("hosts", "host", "ip"),
            ("alerts", "alert", "alert_id"),
        )

        for table, item_name, order_column in sections:
            section = root.find(table)
            assert section is not None

            rows = connection.execute(
                f"SELECT * FROM {table} ORDER BY {order_column}"
            ).fetchall()

            items = section.findall(item_name)
            assert len(items) == len(rows)
            assert section.get("count") == str(len(rows))

            for row, item in zip(rows, items):
                assert [f.tag for f in item if f.tag != "evidence"] == list(row.keys())

                for column in row.keys():
                    field = item.find(column)
                    assert field is not None

                    if row[column] is None:
                        assert field.get("is_null") == "true"
                        assert field.text is None
                    else:
                        assert field.get("is_null") is None
                        assert (field.text or "") == str(row[column])

        # A second export must refuse to overwrite the first.
        original_content = output.read_bytes()

        try:
            export_xml(db_path, output)
        except FileExistsError:
            pass
        else:
            raise AssertionError("Exporter overwrote an existing file")

        assert output.read_bytes() == original_content

    print("XML checks passed: counts, values, nulls, and overwrite protection.")
finally:
    connection.close()