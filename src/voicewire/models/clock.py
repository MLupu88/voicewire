"""Clock domains and alignments.

Every timestamp in VoiceWire belongs to a declared clock domain. Two
timestamps from different clock domains may only be compared or subtracted
after an explicit alignment has been declared. There is no automatic clock
synchronization in VoiceWire: `unresolved` is a legitimate, permanent answer
for a given pair of clocks, not a placeholder waiting to be filled in by a
smarter algorithm.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, model_validator

PCAP_CAPTURE_CLOCK_ID = "pcap.capture_clock"


class ClockType(str, Enum):
    wall = "wall"
    monotonic = "monotonic"
    capture = "capture"


class ClockDomain(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    type: ClockType
    description: Optional[str] = None


PCAP_CAPTURE_CLOCK = ClockDomain(
    id=PCAP_CAPTURE_CLOCK_ID,
    type=ClockType.capture,
    description="Capture-host clock recorded by tshark as each frame's timestamp.",
)


class AlignmentType(str, Enum):
    exact = "exact"
    explicit_offset = "explicit_offset"
    unresolved = "unresolved"


class ClockAlignment(BaseModel):
    """Whether/how two clock domains may be compared.

    This is a fact about clocks, not about where evidence was captured from.
    A known capture vantage point (`CaptureContext`) never implies anything
    about clock alignment, and an alignment declaration never implies
    anything about vantage point -- they are independent facts with
    independent provenance. See CaptureContext.supplied_by for the vantage
    point's own provenance field; `declared_by` here is this model's
    equivalent for the alignment itself.
    """

    model_config = ConfigDict(frozen=True)

    from_clock_id: str
    to_clock_id: str
    type: AlignmentType
    offset_seconds: Optional[float] = None
    justification: Optional[str] = None
    # Provenance of the alignment declaration itself (e.g.
    # "trace_clock.alignment_to_capture_clock"). Required for `exact` and
    # `explicit_offset` -- an alignment claim must say where it came from,
    # just as CaptureContext.supplied_by does for vantage point. Must be
    # absent for `unresolved`: there is no declaration to attribute.
    declared_by: Optional[str] = None

    @model_validator(mode="after")
    def _fields_match_type(self) -> "ClockAlignment":
        if self.type == AlignmentType.explicit_offset:
            if self.offset_seconds is None:
                raise ValueError("explicit_offset alignment requires offset_seconds")
            if self.declared_by is None:
                raise ValueError("explicit_offset alignment requires declared_by (its own provenance)")
        else:
            if self.offset_seconds is not None:
                raise ValueError("offset_seconds is only meaningful for explicit_offset alignment")

        if self.type == AlignmentType.exact and self.declared_by is None:
            raise ValueError("exact alignment requires declared_by (its own provenance)")
        if self.type == AlignmentType.unresolved and self.declared_by is not None:
            raise ValueError("unresolved alignment must not carry declared_by -- there is no declaration")
        return self

    @classmethod
    def unresolved(cls, from_clock_id: str, to_clock_id: str) -> "ClockAlignment":
        return cls(
            from_clock_id=from_clock_id,
            to_clock_id=to_clock_id,
            type=AlignmentType.unresolved,
        )

    def offset_to_apply(self) -> float:
        """Seconds to add to a `from_clock_id` timestamp to express it in `to_clock_id`.

        Raises for anything other than a resolvable alignment -- callers must
        not be able to obtain a number for an unresolved alignment.
        """
        if self.type == AlignmentType.exact:
            return 0.0
        if self.type == AlignmentType.explicit_offset:
            assert self.offset_seconds is not None
            return self.offset_seconds
        raise UnresolvedClockAlignmentError(
            f"clock alignment between {self.from_clock_id!r} and {self.to_clock_id!r} "
            "is unresolved; cross-domain timing is not permitted"
        )


class UnresolvedClockAlignmentError(Exception):
    """Raised when code attempts to derive a cross-clock-domain duration
    without a resolved (exact or explicit_offset) alignment."""
