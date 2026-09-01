import pytest

from voicewire.core.capture_context_loader import CaptureContextFormatError, load_capture_context
from voicewire.models.capture_context import VantagePointKind


def test_no_manifest_yields_unspecified():
    context = load_capture_context(None)

    assert context.vantage_point_kind == VantagePointKind.unspecified
    assert context.supplied_by.method == "unspecified"


def test_known_manifest_is_loaded(capture_context_path):
    context = load_capture_context(capture_context_path)

    assert context.vantage_point_kind == VantagePointKind.agent_host
    assert context.vantage_point_label == "voice-agent-01"
    assert context.interface == "eth0"
    assert context.supplied_by.method == "fixture_manifest"


def test_manifest_missing_vantage_point_kind_raises(tmp_path):
    manifest = tmp_path / "capture-context.json"
    manifest.write_text('{"interface": "eth0"}', encoding="utf-8")

    with pytest.raises(CaptureContextFormatError):
        load_capture_context(manifest)


def test_manifest_unsupported_vantage_point_kind_raises(tmp_path):
    manifest = tmp_path / "capture-context.json"
    manifest.write_text('{"vantage_point": {"kind": "not_a_real_kind"}}', encoding="utf-8")

    with pytest.raises(CaptureContextFormatError):
        load_capture_context(manifest)
