"""DerivedObservation: a fact produced by an algorithm reasoning over evidence.

This is intentionally a distinct type from EvidenceEvent. A future example is
`media.audio_activity_start`: no source artifact reports that literally, some
algorithm decides it. Every DerivedObservation must be traceable back to the
EvidenceEvents it was derived from, and to the method/version that produced
it, so a derived fact is never mistaken for source evidence.

M0 does not produce any real derived observations -- there is no audio
activity detection yet -- but the type exists so the architecture's shape is
correct from the start.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from voicewire.models.evidence import EvidenceTime


class Derivation(BaseModel):
    model_config = ConfigDict(frozen=True)

    method: str
    method_version: str
    source_evidence_ids: tuple[str, ...]


class DerivedObservation(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    kind: str
    time: EvidenceTime
    attributes: dict[str, Any]
    derivation: Derivation
