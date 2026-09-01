import json

import pytest

from voicewire.adapters import trace_fixture
from voicewire.models.clock import AlignmentType


def _write_trace(tmp_path, data: dict) -> "Path":
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_generic_trace_ingestion(tmp_path):
    trace = _write_trace(
        tmp_path,
        {
            "call": {"sip_call_id": "call-1@example.test"},
            "clock": {"id": "fixture-clock", "type": "wall"},
            "events": [
                {"id": "evt-1", "type": "vad.speech_end", "timestamp": "2026-01-01T00:00:00.450000Z"},
            ],
        },
    )

    result = trace_fixture.extract(trace, artifact_id="artifact:test")

    assert result.sip_call_id == "call-1@example.test"
    assert result.clock_domain.id == "fixture-clock"
    assert len(result.events) == 1
    event = result.events[0]
    assert event.kind == "trace.vad.speech_end"
    assert event.source.locator == "event:evt-1"
    assert event.source.adapter == "trace_fixture"
    assert event.time.clock_id == "fixture-clock"


def test_ambiguous_event_type_is_not_strengthened(tmp_path):
    """A source reporting an ambiguous event like 'first_audio' must not be
    silently normalized into a stronger, more specific claim such as
    'tts.first_audio_received'. Adapters normalize syntax, never semantics."""
    trace = _write_trace(
        tmp_path,
        {
            "call": {"sip_call_id": "call-1@example.test"},
            "clock": {"id": "fixture-clock", "type": "wall"},
            "events": [
                {"id": "evt-1", "type": "first_audio", "timestamp": "2026-01-01T00:00:00.500000Z"},
            ],
        },
    )

    result = trace_fixture.extract(trace, artifact_id="artifact:test")

    assert len(result.events) == 1
    assert result.events[0].kind == "trace.first_audio"
    assert "tts" not in result.events[0].kind
    assert "received" not in result.events[0].kind


def test_no_alignment_declared_leaves_alignment_none(tmp_path):
    trace = _write_trace(
        tmp_path,
        {
            "call": {"sip_call_id": "call-1@example.test"},
            "clock": {"id": "fixture-clock", "type": "wall"},
            "events": [],
        },
    )

    result = trace_fixture.extract(trace, artifact_id="artifact:test")

    assert result.alignment_to_capture_clock is None


def test_explicit_offset_alignment_is_parsed(tmp_path):
    trace = _write_trace(
        tmp_path,
        {
            "call": {"sip_call_id": "call-1@example.test"},
            "clock": {
                "id": "fixture-clock",
                "type": "wall",
                "alignment_to_capture_clock": {"type": "explicit_offset", "offset_seconds": 1.5},
            },
            "events": [],
        },
    )

    result = trace_fixture.extract(trace, artifact_id="artifact:test")

    assert result.alignment_to_capture_clock is not None
    assert result.alignment_to_capture_clock.type == AlignmentType.explicit_offset
    assert result.alignment_to_capture_clock.offset_seconds == 1.5


def test_missing_events_field_raises(tmp_path):
    trace = _write_trace(tmp_path, {"clock": {"id": "fixture-clock", "type": "wall"}})

    with pytest.raises(trace_fixture.TraceFixtureFormatError):
        trace_fixture.extract(trace, artifact_id="artifact:test")


def test_missing_call_section_is_tolerated(tmp_path):
    trace = _write_trace(tmp_path, {"clock": {"id": "fixture-clock", "type": "wall"}, "events": []})

    result = trace_fixture.extract(trace, artifact_id="artifact:test")

    assert result.sip_call_id is None
