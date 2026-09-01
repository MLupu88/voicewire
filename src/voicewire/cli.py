"""VoiceWire CLI. Thin: parses arguments, calls core.analyze, renders output.

No analysis logic lives here -- AnalysisReport is the boundary this command
consumes, exactly like any other consumer would.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from voicewire.core.analyze import AnalysisInputs, run_analysis
from voicewire.reporting.summary import render_summary

app = typer.Typer(add_completion=False, help="Evidence-driven diagnostics for voice AI systems.")


@app.callback()
def _voicewire() -> None:
    """Evidence-driven diagnostics for voice AI systems."""


@app.command()
def analyze(
    pcap: Path = typer.Argument(..., exists=True, readable=True, help="Path to a SIP/RTP PCAP file."),
    trace: Path = typer.Option(..., "--trace", exists=True, readable=True, help="Path to an agent trace JSON file."),
    capture_context: Optional[Path] = typer.Option(
        None,
        "--capture-context",
        exists=True,
        readable=True,
        help="Optional JSON manifest declaring the PCAP's capture vantage point. "
        "Omit if unknown -- VoiceWire will not guess it.",
    ),
    output: Path = typer.Option(Path("report.json"), "--output", help="Where to write the analysis report."),
) -> None:
    """Analyze a PCAP + agent trace pair and produce an evidence-truth report.json."""
    report = run_analysis(
        AnalysisInputs(pcap_path=pcap, trace_path=trace, capture_context_path=capture_context)
    )
    output.write_text(report.to_json(), encoding="utf-8")
    typer.echo(render_summary(report, report_path=str(output)))


if __name__ == "__main__":
    app()
