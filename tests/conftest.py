"""Shared pytest fixtures. Everything is written under pytest's tmp_path."""

import json
from pathlib import Path

import pytest
from scapy.utils import wrpcap

from packetlens.ingest import ingest_capture
from packetlens.samples import write_samples

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEMO_PCAP = PROJECT_ROOT / "data/samples/demo.pcap"


@pytest.fixture(scope="session")
def sample_dir(tmp_path_factory):
    """All synthetic scenario captures plus manifest.json."""
    directory = tmp_path_factory.mktemp("samples")
    write_samples(directory)
    return directory


@pytest.fixture(scope="session")
def manifest(sample_dir):
    return json.loads((sample_dir / "manifest.json").read_text())


@pytest.fixture(scope="session")
def scenario_db(sample_dir, tmp_path_factory):
    """Return a function: scenario name -> path of an imported database.

    Session-scoped and cached, so each capture is imported only once.
    Tests that modify a database must use their own copy (see make_db).
    """
    directory = tmp_path_factory.mktemp("dbs")
    cache = {}

    def get(name):
        if name not in cache:
            path = directory / f"{name}.db"
            ingest_capture(sample_dir / f"{name}.pcap", path)
            cache[name] = path
        return cache[name]

    return get


@pytest.fixture
def make_db(tmp_path):
    """Return a function: list of packets -> path of a fresh imported db."""
    counter = [0]

    def make(packets, config=None):
        counter[0] += 1
        capture = tmp_path / f"capture{counter[0]}.pcap"
        database = tmp_path / f"capture{counter[0]}.db"
        wrpcap(str(capture), packets)
        ingest_capture(capture, database, detection_config=config)
        return database

    return make


@pytest.fixture
def demo_db(tmp_path):
    """The committed five-packet demo capture, freshly imported."""
    database = tmp_path / "demo.db"
    ingest_capture(DEMO_PCAP, database)
    return database
