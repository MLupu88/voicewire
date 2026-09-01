"""Capture vantage point and clock alignment are independent facts.

A known capture vantage point (`CaptureContext`) never implies anything
about whether clock domains are comparable, and a resolved `ClockAlignment`
never implies anything about where the PCAP was captured from. These live
in separate inputs (a capture-context manifest vs. the trace's own `clock`
section) with separate provenance (`CaptureContext.supplied_by` vs.
`ClockAlignment.declared_by`), and this test proves all four combinations
of (vantage known/unspecified) x (alignment resolved/unresolved) actually
occur independently through `run_analysis`.
"""

import json

from voicewire.core.analyze import AnalysisInputs, run_analysis
from voicewire.models.clock import AlignmentType
from voicewire.models.capture_context import VantagePointKind


def _trace_without_alignment(tmp_path, sip_call_id: str):
    trace = {
        "call": {"sip_call_id": sip_call_id},
        "clock": {"id": "fixture-clock", "type": "wall"},  # no alignment_to_capture_clock
        "events": [],
    }
    path = tmp_path / "trace-no-alignment.json"
    path.write_text(json.dumps(trace), encoding="utf-8")
    return path


def test_known_vantage_with_unresolved_alignment(pcap_path, capture_context_path, tmp_path):
    """A capture-context manifest is supplied (vantage known) but the trace
    declares no clock alignment -- alignment must stay unresolved regardless."""
    trace_path = _trace_without_alignment(tmp_path, "voicewire-m0@example.test")

    report = run_analysis(
        AnalysisInputs(pcap_path=pcap_path, trace_path=trace_path, capture_context_path=capture_context_path)
    )

    assert report.capture_context.vantage_point_kind == VantagePointKind.agent_host
    alignment = report.clock_alignments[0]
    assert alignment.type == AlignmentType.unresolved
    assert alignment.declared_by is None


def test_unspecified_vantage_with_exact_alignment(pcap_path, trace_path):
    """No capture-context manifest is supplied (vantage unspecified) but the
    trace itself declares an exact alignment -- alignment must resolve
    regardless of vantage point being unknown."""
    report = run_analysis(
        AnalysisInputs(pcap_path=pcap_path, trace_path=trace_path, capture_context_path=None)
    )

    assert report.capture_context.vantage_point_kind == VantagePointKind.unspecified
    alignment = report.clock_alignments[0]
    assert alignment.type == AlignmentType.exact
    assert alignment.declared_by is not None


def test_known_vantage_with_exact_alignment(pcap_path, trace_path, capture_context_path):
    """Both facts can also both be known at once -- neither excludes the other."""
    report = run_analysis(
        AnalysisInputs(pcap_path=pcap_path, trace_path=trace_path, capture_context_path=capture_context_path)
    )

    assert report.capture_context.vantage_point_kind == VantagePointKind.agent_host
    assert report.clock_alignments[0].type == AlignmentType.exact


def test_unspecified_vantage_with_unresolved_alignment(pcap_path, tmp_path):
    """And both facts can be unknown at once."""
    trace_path = _trace_without_alignment(tmp_path, "voicewire-m0@example.test")

    report = run_analysis(
        AnalysisInputs(pcap_path=pcap_path, trace_path=trace_path, capture_context_path=None)
    )

    assert report.capture_context.vantage_point_kind == VantagePointKind.unspecified
    assert report.clock_alignments[0].type == AlignmentType.unresolved
