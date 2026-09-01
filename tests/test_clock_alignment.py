from datetime import datetime, timezone

import pytest

from voicewire.core.timing import duration_seconds
from voicewire.models.clock import AlignmentType, ClockAlignment, UnresolvedClockAlignmentError
from voicewire.models.evidence import EvidenceEvent, EvidenceSource, EvidenceTime


def _event(clock_id: str, iso_timestamp: str) -> EvidenceEvent:
    return EvidenceEvent(
        id=f"evidence:test-{clock_id}-{iso_timestamp}",
        kind="test.event",
        source=EvidenceSource(artifact_id="artifact:test", adapter="test", adapter_version="0", locator="x:1"),
        time=EvidenceTime(
            clock_id=clock_id,
            timestamp=datetime.fromisoformat(iso_timestamp),
            precision="unknown",
            basis="source_reported",
        ),
        attributes={},
    )


def test_same_clock_domain_needs_no_alignment():
    a = _event("clock-a", "2026-01-01T00:00:00+00:00")
    b = _event("clock-a", "2026-01-01T00:00:01+00:00")

    assert duration_seconds(a, b) == pytest.approx(1.0)


def test_exact_alignment_permits_cross_domain_duration():
    a = _event("clock-a", "2026-01-01T00:00:00+00:00")
    b = _event("clock-b", "2026-01-01T00:00:02+00:00")
    alignment = ClockAlignment(
        from_clock_id="clock-a", to_clock_id="clock-b", type=AlignmentType.exact, declared_by="test_manifest"
    )

    assert duration_seconds(a, b, alignment) == pytest.approx(2.0)


def test_explicit_offset_alignment_applies_offset():
    a = _event("clock-a", "2026-01-01T00:00:00+00:00")
    b = _event("clock-b", "2026-01-01T00:00:02+00:00")
    alignment = ClockAlignment(
        from_clock_id="clock-a",
        to_clock_id="clock-b",
        type=AlignmentType.explicit_offset,
        offset_seconds=0.5,
        declared_by="test_manifest",
    )

    # a expressed in clock-b is 00:00:00.5; b is at 00:00:02 -> 1.5s apart.
    assert duration_seconds(a, b, alignment) == pytest.approx(1.5)


def test_unresolved_alignment_rejects_cross_domain_duration():
    a = _event("clock-a", "2026-01-01T00:00:00+00:00")
    b = _event("clock-b", "2026-01-01T00:00:02+00:00")
    alignment = ClockAlignment.unresolved("clock-a", "clock-b")

    with pytest.raises(UnresolvedClockAlignmentError):
        duration_seconds(a, b, alignment)


def test_cross_domain_duration_without_any_alignment_raises():
    a = _event("clock-a", "2026-01-01T00:00:00+00:00")
    b = _event("clock-b", "2026-01-01T00:00:02+00:00")

    with pytest.raises(ValueError):
        duration_seconds(a, b, None)


def test_explicit_offset_without_offset_seconds_is_rejected():
    with pytest.raises(ValueError):
        ClockAlignment(from_clock_id="a", to_clock_id="b", type=AlignmentType.explicit_offset)


def test_exact_alignment_with_offset_seconds_is_rejected():
    with pytest.raises(ValueError):
        ClockAlignment(from_clock_id="a", to_clock_id="b", type=AlignmentType.exact, offset_seconds=1.0)


def test_unresolved_alignment_offset_to_apply_raises():
    alignment = ClockAlignment.unresolved("a", "b")
    with pytest.raises(UnresolvedClockAlignmentError):
        alignment.offset_to_apply()


def test_exact_alignment_without_declared_by_is_rejected():
    """An alignment claim must say where it came from -- an `exact` type
    with no declaration attached is not a valid ClockAlignment."""
    with pytest.raises(ValueError):
        ClockAlignment(from_clock_id="a", to_clock_id="b", type=AlignmentType.exact)


def test_explicit_offset_without_declared_by_is_rejected():
    with pytest.raises(ValueError):
        ClockAlignment(
            from_clock_id="a", to_clock_id="b", type=AlignmentType.explicit_offset, offset_seconds=1.0
        )


def test_unresolved_alignment_with_declared_by_is_rejected():
    """unresolved means no declaration exists; declared_by must not be set."""
    with pytest.raises(ValueError):
        ClockAlignment(from_clock_id="a", to_clock_id="b", type=AlignmentType.unresolved, declared_by="test_manifest")


def test_unresolved_helper_carries_no_declaration():
    alignment = ClockAlignment.unresolved("a", "b")
    assert alignment.declared_by is None
