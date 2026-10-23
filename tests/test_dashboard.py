"""Headless smoke tests of the Streamlit dashboard (streamlit.testing).

These run the real script and interact with widgets, but they do not
check layout or charts visually. A manual check in a browser is still
needed (see docs/demo_walkthrough.md).
"""

import shutil
import sqlite3

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

from .conftest import PROJECT_ROOT  # noqa: E402

SCRIPT = str(PROJECT_ROOT / "packetlens/dashboard.py")


@pytest.fixture
def folders(tmp_path, monkeypatch, sample_dir):
    output = tmp_path / "output"
    output.mkdir()
    monkeypatch.setenv("PACKETLENS_OUTPUT_DIR", str(output))
    monkeypatch.setenv("PACKETLENS_SAMPLE_DIR", str(sample_dir))
    return output


def run(app):
    app.run(timeout=30)
    assert not app.exception, [e.value for e in app.exception]
    return app


def dashboard_app():
    """The app as it looks after opening a recording from the cover page."""
    app = AppTest.from_file(SCRIPT)
    app.session_state["view"] = "dashboard"
    return app


def metric(app, label):
    return next(m.value for m in app.metric if m.label == label)


def markdown_text(app):
    return " ".join(m.value for m in app.markdown)


def test_welcome_screen_when_empty(folders):
    app = run(AppTest.from_file(SCRIPT))
    assert "See what happened" in markdown_text(app)
    assert len(app.tabs) == 0
    assert "port_scan.pcap" in app.pills(key="example_pick").options


def test_welcome_example_pill_analyses_once(folders):
    app = run(AppTest.from_file(SCRIPT))
    app.pills(key="example_pick").set_value("normal.pcap")
    run(app)
    assert len(list(folders.glob("*.db"))) == 1
    assert app.title[0].value == "normal.pcap"
    assert any("Analysed 33 messages" in s.value for s in app.success)

    run(app)   # an ordinary rerun must not analyse again
    assert len(list(folders.glob("*.db"))) == 1


def test_overview_status_lede_and_tabs(folders, scenario_db):
    shutil.copy(scenario_db("port_scan"), folders / "port_scan.db")
    app = run(dashboard_app())

    assert app.title[0].value == "port_scan.pcap"
    assert metric(app, "Messages") == "93"
    assert len(app.tabs) == 6
    text = markdown_text(app)
    assert "2 suspicious patterns found" in text
    assert "knocked on the doors of 1 other device, and 1 more device did something similar" in text
    headings = [m.value for m in app.markdown if m.value.startswith("### Port scan from")]
    assert len(headings) == 2


def test_no_alerts_banner(folders, scenario_db):
    shutil.copy(scenario_db("normal"), folders / "normal.db")
    app = run(dashboard_app())
    assert "No suspicious patterns found" in markdown_text(app)
    assert metric(app, "Devices") == "5"


def test_focus_filters_no_match_and_clear(folders, scenario_db):
    shutil.copy(scenario_db("port_scan"), folders / "port_scan.db")
    app = run(dashboard_app())

    app.selectbox(key="f_device").select("2001:db8:bad::66")
    run(app)
    assert metric(app, "Messages") == "25"

    # Only TCP exists in this recording, so it is the only kind offered.
    assert app.multiselect(key="f_types").options == ["Connections (TCP)"]
    app.slider(key="f_size").set_value((0, 10))   # no message is that small
    run(app)
    assert metric(app, "Messages") == "0"
    assert "No messages match this focus" in markdown_text(app)

    app.button(key="nm_clear").click()
    run(app)
    assert metric(app, "Messages") == "93"


def test_service_filter(folders, scenario_db):
    shutil.copy(scenario_db("normal"), folders / "normal.db")
    app = run(dashboard_app())
    app.selectbox(key="f_service").select(53)
    run(app)
    assert metric(app, "Messages") == "2"


def test_sidebar_analyse_and_rerun_does_not_duplicate(folders, scenario_db):
    shutil.copy(scenario_db("normal"), folders / "normal.db")
    app = run(dashboard_app())
    app.selectbox(key="sample").select("host_sweep.pcap")
    app.button(key="analyse").click()
    run(app)
    assert any("Analysed 37 messages" in s.value for s in app.success)
    assert len(list(folders.glob("*.db"))) == 2
    assert metric(app, "Messages") == "37"

    run(app)
    assert len(list(folders.glob("*.db"))) == 2


def test_analyse_without_choice_shows_error(folders, scenario_db):
    shutil.copy(scenario_db("normal"), folders / "normal.db")
    app = run(dashboard_app())
    app.button(key="analyse").click()
    run(app)
    assert any("Choose a file" in e.value for e in app.error)


def test_clear_history_needs_selection_and_confirmation(folders, scenario_db):
    shutil.copy(scenario_db("normal"), folders / "keep.db")
    shutil.copy(scenario_db("burst"), folders / "drop.db")
    app = run(dashboard_app())

    # Nothing is selected by default, so nothing can be deleted.
    assert app.button(key="delete_button").disabled
    app.checkbox(key="hist::drop.db").check()
    run(app)
    assert app.button(key="delete_button").disabled      # not confirmed yet
    app.checkbox(key="delete_sure").check()
    run(app)
    app.button(key="delete_button").click()
    run(app)

    assert [p.name for p in folders.glob("*.db")] == ["keep.db"]
    assert any("Removed 1 recording" in s.value for s in app.success)


def test_clear_all_history_returns_to_welcome(folders, scenario_db):
    shutil.copy(scenario_db("normal"), folders / "a.db")
    app = run(dashboard_app())
    app.checkbox(key="hist::a.db").check()
    app.checkbox(key="delete_sure").check()
    run(app)
    app.button(key="delete_button").click()
    run(app)
    assert list(folders.glob("*.db")) == []
    assert "See what happened" in markdown_text(app)


def test_old_schema_database_shows_error(folders):
    old = folders / "old.db"
    sqlite3.connect(old).execute("CREATE TABLE packets (id INTEGER)").connection.close()
    app = run(dashboard_app())
    assert any("older version" in e.value for e in app.error)


def test_not_a_database_shows_error(folders):
    (folders / "broken.db").write_bytes(b"this is not sqlite")
    app = run(dashboard_app())
    assert any("Cannot open" in e.value for e in app.error)


def test_readonly_console_refuses_delete(folders, scenario_db):
    shutil.copy(scenario_db("normal"), folders / "normal.db")
    app = run(dashboard_app())
    app.segmented_control(key="details_view").set_value("Ask a question")
    run(app)
    app.pills(key="canned").set_value("Write my own")
    run(app)
    next(t for t in app.text_area if t.label == "SQL").input("DELETE FROM packets")
    run(app)
    app.button(key="run_sql").click()
    run(app)
    assert any("refused" in e.value for e in app.error)
    assert metric(app, "Messages") == "33"


def test_ready_made_question_runs(folders, scenario_db):
    shutil.copy(scenario_db("normal"), folders / "normal.db")
    app = run(dashboard_app())
    app.segmented_control(key="details_view").set_value("Ask a question")
    run(app)
    app.button(key="run_sql").click()
    run(app)
    assert not app.error
    assert any("row" in c.value for c in app.caption)


def test_cover_page_is_the_start_and_lists_recordings(folders, scenario_db):
    shutil.copy(scenario_db("port_scan"), folders / "scan.db")
    shutil.copy(scenario_db("normal"), folders / "normal.db")
    app = run(AppTest.from_file(SCRIPT))

    text = markdown_text(app)
    assert "See what happened" in text and "Recent recordings" in text
    assert "2 findings" in text and "Nothing suspicious" in text
    assert len(app.tabs) == 0

    app.button(key="open::scan.db").click()
    run(app)
    assert app.title[0].value == "port_scan.pcap"
    assert len(app.tabs) == 6

    app.button(key="home_button").click()
    run(app)
    assert "Recent recordings" in markdown_text(app)


def test_old_recording_cannot_be_opened_from_cover(folders):
    sqlite3.connect(folders / "old.db").execute("CREATE TABLE x (y)").connection.close()
    app = run(AppTest.from_file(SCRIPT))
    assert app.button(key="open::old.db").disabled
