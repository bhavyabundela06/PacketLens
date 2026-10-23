"""XML export: counts, values, NULLs, escaping, invalid chars, overwrite."""

import sqlite3
import xml.etree.ElementTree as ET

import pytest

from packetlens.database import SchemaVersionError, connect
from packetlens.xml_export import export_xml, main

SECTIONS = (
    ("packets", "packet", "id"),
    ("flows", "flow", "flow_id"),
    ("hosts", "host", "ip"),
    ("alerts", "alert", "alert_id"),
)


def check_matches_database(db, xml_path):
    root = ET.parse(xml_path).getroot()   # parsing proves it is well formed
    assert root.tag == "packetlens"
    assert root.get("schema_version") == "2"

    connection = connect(db, read_only=True)
    try:
        for table, item_name, order_column in SECTIONS:
            section = root.find(table)
            rows = connection.execute(
                f"SELECT * FROM {table} ORDER BY {order_column}").fetchall()
            items = section.findall(item_name)
            assert len(items) == len(rows) == int(section.get("count"))

            for row, item in zip(rows, items):
                fields = [f for f in item if f.tag != "evidence"]
                assert [f.tag for f in fields] == list(row.keys())
                for column in row.keys():
                    element = item.find(column)
                    if row[column] is None:
                        assert element.get("is_null") == "true"
                        assert element.text is None
                    else:
                        assert element.get("is_null") is None
                        assert element.text == str(row[column])
        return root
    finally:
        connection.close()


def test_demo_export(demo_db, tmp_path):
    output = tmp_path / "demo.xml"
    counts = export_xml(demo_db, output)
    assert counts == {"packets": 5, "flows": 2, "hosts": 2, "alerts": 0}
    root = check_matches_database(demo_db, output)
    assert root.find("capture/source_name").text == "demo.pcap"


def test_alerts_and_evidence_exported(scenario_db, tmp_path):
    db = scenario_db("port_scan")
    output = tmp_path / "scan.xml"
    export_xml(db, output)
    root = check_matches_database(db, output)
    evidence = root.find("alerts/alert/evidence").text.split()
    assert len(evidence) == 30


def test_ipv6_and_edge_cases_export(scenario_db, tmp_path):
    db = scenario_db("edge_cases")
    output = tmp_path / "edge.xml"
    export_xml(db, output)
    check_matches_database(db, output)


def test_escaping_and_invalid_characters(demo_db, tmp_path):
    copy = tmp_path / "copy.db"
    copy.write_bytes(demo_db.read_bytes())
    connection = sqlite3.connect(copy)
    connection.execute(
        "UPDATE packets SET info = ? WHERE id = 1",
        ("<script>&\"quote\"</script>\x00\x07end",),
    )
    connection.commit()
    connection.close()

    output = tmp_path / "escaped.xml"
    export_xml(copy, output)
    raw = output.read_text(encoding="utf-8")
    assert "<script>" not in raw
    info = ET.parse(output).getroot().find("packets/packet/info")
    assert info.text == '<script>&"quote"</script>��end'
    assert info.get("replaced_invalid_chars") == "2"


def test_refuses_overwrite(demo_db, tmp_path):
    output = tmp_path / "out.xml"
    export_xml(demo_db, output)
    original = output.read_bytes()
    with pytest.raises(FileExistsError):
        export_xml(demo_db, output)
    assert output.read_bytes() == original
    assert not list(tmp_path.glob("*.partial"))


def test_old_schema_rejected(tmp_path):
    old = tmp_path / "old.db"
    sqlite3.connect(old).execute("CREATE TABLE packets (id INTEGER)").connection.close()
    with pytest.raises(SchemaVersionError):
        export_xml(old, tmp_path / "out.xml")
    assert not (tmp_path / "out.xml").exists()


def test_cli(demo_db, tmp_path, capsys):
    output = tmp_path / "cli.xml"
    assert main([str(demo_db), str(output)]) == 0
    assert "5 packets" in capsys.readouterr().out
    assert main([str(demo_db), str(output)]) == 1
    assert "already exists" in capsys.readouterr().err
