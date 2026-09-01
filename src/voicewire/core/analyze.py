"""Core analysis orchestration.

This module is the only place that assembles an AnalysisReport. The CLI is a
thin caller of `run_analysis` -- it must not contain analysis logic itself,
so that any future consumer (tests, a future non-CLI entry point) gets the
exact same behavior.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from voicewire.adapters import tshark as tshark_adapter
from voicewire.adapters import trace_fixture as trace_adapter
from voicewire.core.capture_context_loader import load_capture_context
from voicewire.core.correlate import correlate_sdp_media_to_rtp_streams, correlate_trace_call_to_sip_dialog
from voicewire.core.hashing import sha256_file
from voicewire.models.artifact import Artifact, ArtifactFormat
from voicewire.models.clock import PCAP_CAPTURE_CLOCK, ClockAlignment
from voicewire.models.report import AnalysisReport, RuntimeInfo
from voicewire.version import __version__


@dataclass(frozen=True)
class AnalysisInputs:
    pcap_path: Path
    trace_path: Path
    capture_context_path: Optional[Path] = None


def _build_artifact(path: Path, *, format: ArtifactFormat) -> Artifact:
    sha256 = sha256_file(path)
    return Artifact.create(
        name=path.name,
        path=str(path),
        format=format,
        size_bytes=path.stat().st_size,
        sha256=sha256,
    )


def run_analysis(inputs: AnalysisInputs) -> AnalysisReport:
    pcap_artifact = _build_artifact(inputs.pcap_path, format=ArtifactFormat.pcap)
    trace_artifact = _build_artifact(inputs.trace_path, format=ArtifactFormat.json_trace)

    capture_context = load_capture_context(inputs.capture_context_path)

    sip_rtp_events = tshark_adapter.extract_sip_rtp_evidence(
        inputs.pcap_path, artifact_id=pcap_artifact.id
    )
    trace_result = trace_adapter.extract(inputs.trace_path, artifact_id=trace_artifact.id)

    clock_domains = tuple(
        sorted([PCAP_CAPTURE_CLOCK, trace_result.clock_domain], key=lambda c: c.id)
    )

    if trace_result.alignment_to_capture_clock is not None:
        alignment = trace_result.alignment_to_capture_clock
    else:
        alignment = ClockAlignment.unresolved(
            from_clock_id=trace_result.clock_domain.id,
            to_clock_id=PCAP_CAPTURE_CLOCK.id,
        )
    clock_alignments = (alignment,)

    all_events = sip_rtp_events + trace_result.events
    evidence_events = tuple(sorted(all_events, key=lambda e: e.sort_key()))

    trace_correlations = correlate_trace_call_to_sip_dialog(
        trace_sip_call_id=trace_result.sip_call_id,
        evidence_events=list(evidence_events),
    )
    # Purely PCAP-evidence-derived: independent of whether a trace was even
    # supplied, or of what it declares.
    sdp_rtp_correlations = correlate_sdp_media_to_rtp_streams(list(evidence_events))
    correlations = tuple(
        sorted(trace_correlations + sdp_rtp_correlations, key=lambda c: (c.kind, c.id))
    )

    runtime = RuntimeInfo(
        python_version=platform.python_version(),
        tshark_version=tshark_adapter.get_tshark_version(),
        voicewire_version=__version__,
    )

    return AnalysisReport(
        voicewire_version=__version__,
        runtime=runtime,
        inputs=(pcap_artifact, trace_artifact),
        capture_context=capture_context,
        clock_domains=clock_domains,
        clock_alignments=clock_alignments,
        evidence_events=evidence_events,
        derived_observations=(),
        correlations=correlations,
    )
