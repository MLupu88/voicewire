"""Cross-clock-domain timing.

This is the only place in VoiceWire that is allowed to turn two EvidenceEvent
timestamps into a duration. It is written so that an unresolved alignment
cannot silently produce a number: `ClockAlignment.offset_to_apply()` raises
`UnresolvedClockAlignmentError` for an unresolved alignment, and there is no
other path to a duration that skips it.
"""

from __future__ import annotations

from voicewire.models.clock import ClockAlignment
from voicewire.models.evidence import EvidenceEvent


def duration_seconds(event_a: EvidenceEvent, event_b: EvidenceEvent, alignment: ClockAlignment | None = None) -> float:
    """Seconds from `event_a` to `event_b` (may be negative).

    If both events are in the same clock domain, no alignment is needed.
    Otherwise `alignment` must resolve the pair (`exact` or
    `explicit_offset`); an `unresolved` alignment raises
    UnresolvedClockAlignmentError rather than returning a number.
    """
    clock_a = event_a.time.clock_id
    clock_b = event_b.time.clock_id

    if clock_a == clock_b:
        return (event_b.time.timestamp - event_a.time.timestamp).total_seconds()

    if alignment is None:
        raise ValueError(
            f"events are in different clock domains ({clock_a!r} vs {clock_b!r}) "
            "but no alignment was supplied"
        )
    if {alignment.from_clock_id, alignment.to_clock_id} != {clock_a, clock_b}:
        raise ValueError(
            f"alignment ({alignment.from_clock_id!r} -> {alignment.to_clock_id!r}) "
            f"does not relate the two events' clock domains ({clock_a!r}, {clock_b!r})"
        )

    offset = alignment.offset_to_apply()  # raises UnresolvedClockAlignmentError if unresolved
    if alignment.from_clock_id == clock_a:
        a_in_b_clock = event_a.time.timestamp.timestamp() + offset
        return event_b.time.timestamp.timestamp() - a_in_b_clock
    b_in_a_clock = event_b.time.timestamp.timestamp() + offset
    return b_in_a_clock - event_a.time.timestamp.timestamp()
