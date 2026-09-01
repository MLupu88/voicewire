from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "fixtures" / "m0-basic"


@pytest.fixture
def fixture_dir() -> Path:
    return FIXTURE_DIR


@pytest.fixture
def pcap_path(fixture_dir: Path) -> Path:
    return fixture_dir / "call.pcap"


@pytest.fixture
def trace_path(fixture_dir: Path) -> Path:
    return fixture_dir / "agent-trace.json"


@pytest.fixture
def capture_context_path(fixture_dir: Path) -> Path:
    return fixture_dir / "capture-context.json"


@pytest.fixture
def expected_report_path(fixture_dir: Path) -> Path:
    return fixture_dir / "expected-report.json"
