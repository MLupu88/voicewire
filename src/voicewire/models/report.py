"""AnalysisReport: the canonical, machine-readable product output of VoiceWire.

This is the sole boundary CLI/rendering code may consume. It carries enough
reproducibility information (tool/runtime versions, input hashes) that the
same VoiceWire version run against identical inputs produces a semantically
identical report.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from voicewire.models.artifact import Artifact
from voicewire.models.capture_context import CaptureContext
from voicewire.models.clock import ClockAlignment, ClockDomain
from voicewire.models.correlation import Correlation
from voicewire.models.derived import DerivedObservation
from voicewire.models.evidence import EvidenceEvent

REPORT_SCHEMA_VERSION = "0.1.0"


class RuntimeInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    python_version: str
    tshark_version: str
    voicewire_version: str


class AnalysisReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    report_schema_version: str = REPORT_SCHEMA_VERSION
    voicewire_version: str
    # A standing reminder embedded in the artifact itself: this report is
    # evidence and reconstruction, not diagnosis.
    scope_note: str = (
        "This report establishes evidence truth (hashed artifacts, normalized "
        "SIP/RTP/trace evidence, explicit clock alignment, explicit correlation). "
        "It does not contain a latency or fault diagnosis."
    )
    runtime: RuntimeInfo
    inputs: tuple[Artifact, ...]
    capture_context: CaptureContext
    clock_domains: tuple[ClockDomain, ...]
    clock_alignments: tuple[ClockAlignment, ...]
    evidence_events: tuple[EvidenceEvent, ...]
    derived_observations: tuple[DerivedObservation, ...] = ()
    correlations: tuple[Correlation, ...]

    def to_json(self) -> str:
        return self.model_dump_json(indent=2) + "\n"
