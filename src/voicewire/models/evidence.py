"""EvidenceEvent: a fact directly supplied or extracted from a source artifact.

An EvidenceEvent is not an interpretation. It is the adapter's normalized
rendering of something a source artifact literally contained (a SIP message,
an RTP packet, a trace-reported event). Any conclusion an algorithm draws
*about* evidence belongs in DerivedObservation, never here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


class EvidenceSource(BaseModel):
    model_config = ConfigDict(frozen=True)

    artifact_id: str
    adapter: str
    adapter_version: str
    # Locates this event within its source artifact, e.g. "frame:123" or
    # "event:evt-1". Stable and re-derivable from the artifact alone.
    locator: str


class EvidenceTime(BaseModel):
    model_config = ConfigDict(frozen=True)

    clock_id: str
    timestamp: datetime
    # e.g. "microsecond", "millisecond", "second", "unknown"
    precision: str
    # e.g. "capture_timestamp", "source_reported"
    basis: str


class EvidenceEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    # e.g. "sip.message", "rtp.packet", "trace.<source-defined-type>"
    kind: str
    source: EvidenceSource
    time: EvidenceTime
    attributes: dict[str, Any]
    # Opaque pointer/snapshot of the raw extracted data behind this event,
    # for provenance/audit. Not meant for programmatic interpretation.
    raw_ref: Optional[str] = None

    def sort_key(self) -> tuple:
        return (self.time.clock_id, self.time.timestamp.isoformat(), self.kind, self.id)
