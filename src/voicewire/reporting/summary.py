"""Plain-text CLI summary rendering.

Presentation only. All facts here are read straight off an already-built
AnalysisReport -- nothing is computed here that isn't already in the report.
"""

from __future__ import annotations

from voicewire.models.report import AnalysisReport


def render_summary(report: AnalysisReport, *, report_path: str) -> str:
    sip_call_id = None
    for correlation in report.correlations:
        if correlation.kind == "trace_call_to_sip_dialog":
            sip_call_id = correlation.right_ref.removeprefix("sip:call_id:")
            break

    sip_count = sum(1 for e in report.evidence_events if e.kind == "sip.message")
    rtp_count = sum(1 for e in report.evidence_events if e.kind == "rtp.packet")
    trace_count = sum(1 for e in report.evidence_events if e.kind.startswith("trace."))

    alignment = report.clock_alignments[0] if report.clock_alignments else None

    lines = [
        "VoiceWire",
        "",
        "Artifacts",
        "  PCAP      ✓",
        "  Trace     ✓",
        "",
        "Call",
        f"  SIP Call-ID  {sip_call_id or 'not correlated'}",
        "",
        "Evidence",
        f"  SIP events    {sip_count}",
        f"  RTP packets   {rtp_count}",
        f"  Trace events  {trace_count}",
        "",
        "Clock alignment",
    ]
    if alignment is not None:
        lines.append(f"  {alignment.from_clock_id} ↔ {alignment.to_clock_id}")
        lines.append(f"  {alignment.type.value}")
    else:
        lines.append("  (none declared)")
    lines += [
        "",
        "Capture",
        f"  vantage point  {report.capture_context.vantage_point_kind.value}",
        f"  interface      {report.capture_context.interface or 'unknown'}",
        "",
        f"{report_path} written",
    ]
    return "\n".join(lines)
