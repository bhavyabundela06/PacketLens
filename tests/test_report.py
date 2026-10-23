"""HTML findings report: scope, escaping, and agreement with queries."""

import sqlite3
from html.parser import HTMLParser

import pytest

from packetlens import queries
from packetlens.database import connect
from packetlens.queries import PacketFilter
from packetlens.report import build_report, main, write_report


class TextCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text = []
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)

    def handle_data(self, data):
        self.text.append(data)


def parse(content):
    collector = TextCollector()
    collector.feed(content)
    return " ".join(collector.text), collector.tags


def test_report_contents(scenario_db):
    content = build_report(scenario_db("port_scan"))
    text, tags = parse(content)

    assert "port_scan.pcap" in text
    assert "none (whole capture)" in text
    assert "203.0.113.66" in text and "2001:db8:bad::66" in text
    assert "not proof" in text
    assert "Limitations" in text
    assert "script" not in tags


def test_report_agrees_with_filtered_queries(scenario_db):
    db = scenario_db("normal")
    packet_filter = PacketFilter(protocols=["UDP"])
    content = build_report(db, packet_filter)
    connection = connect(db, read_only=True)
    stats = queries.summary(connection, packet_filter)
    connection.close()

    assert f"<dt>Packets</dt><dd>{stats['packets']}</dd>" in content
    assert f"<dt>Captured bytes</dt><dd>{stats['captured_bytes']}</dd>" in content
    assert "protocol in UDP" in content


def test_report_with_zero_matches(scenario_db):
    content = build_report(scenario_db("normal"), PacketFilter(ip="203.0.113.250"))
    assert "<dt>Packets</dt><dd>0</dd>" in content
    assert "No rows for this scope" in content


def test_report_escapes_untrusted_text(demo_db, tmp_path):
    copy = tmp_path / "copy.db"
    copy.write_bytes(demo_db.read_bytes())
    connection = sqlite3.connect(copy)
    connection.execute("UPDATE capture_info SET source_name = ?",
                       ("<script>alert(1)</script>.pcap",))
    connection.commit()
    connection.close()

    content = build_report(copy, PacketFilter(ip="<img src=x onerror=alert(1)>"))
    _, tags = parse(content)
    assert "script" not in tags and "img" not in tags
    assert "&lt;script&gt;" in content


def test_write_report_refuses_overwrite(demo_db, tmp_path):
    output = tmp_path / "r.html"
    write_report(demo_db, output)
    with pytest.raises(FileExistsError):
        write_report(demo_db, output)


def test_cli(demo_db, tmp_path):
    assert main([str(demo_db), str(tmp_path / "r.html"), "--protocol", "TCP"]) == 0
    assert "protocol in TCP" in (tmp_path / "r.html").read_text()
    assert main([str(tmp_path / "missing.db"), str(tmp_path / "x.html")]) == 1
