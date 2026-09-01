import json

from typer.testing import CliRunner

from voicewire.cli import app

runner = CliRunner()


def _normalize(report_dict: dict) -> dict:
    """Strip environment-dependent runtime fields before comparing against
    the checked-in expected report. Everything else -- evidence, IDs,
    correlations, clock alignment, capture context -- must match exactly."""
    normalized = json.loads(json.dumps(report_dict))
    normalized["runtime"]["python_version"] = "<normalized>"
    normalized["runtime"]["tshark_version"] = "<normalized>"
    # `path` reflects whatever string was passed on the command line
    # (absolute in this test, repo-root-relative when the fixture's
    # expected-report.json was generated) -- it is not part of an
    # artifact's identity (id/sha256/name are), so it is excluded here.
    for artifact in normalized["inputs"]:
        artifact["path"] = "<normalized>"
    return normalized


def test_cli_analyze_end_to_end(pcap_path, trace_path, capture_context_path, expected_report_path, tmp_path):
    output_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "analyze",
            str(pcap_path),
            "--trace",
            str(trace_path),
            "--capture-context",
            str(capture_context_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "VoiceWire" in result.output
    assert "voicewire-m0@example.test" in result.output
    assert f"{output_path} written" in result.output

    assert output_path.exists()
    actual_report = json.loads(output_path.read_text())
    expected_report = json.loads(expected_report_path.read_text())

    # The report references input paths as given on the command line; the
    # fixture's checked-in expected report was generated from the same
    # repo-root-relative paths pytest also uses, so they should match too.
    assert _normalize(actual_report) == _normalize(expected_report)


def test_cli_reports_evidence_counts_in_summary(pcap_path, trace_path, capture_context_path, tmp_path):
    output_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "analyze",
            str(pcap_path),
            "--trace",
            str(trace_path),
            "--capture-context",
            str(capture_context_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "SIP events    5" in result.output
    assert "RTP packets   5" in result.output
    assert "Trace events  3" in result.output
    assert "vantage point  agent_host" in result.output


def test_cli_without_capture_context_is_unspecified(pcap_path, trace_path, tmp_path):
    output_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        ["analyze", str(pcap_path), "--trace", str(trace_path), "--output", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(output_path.read_text())
    assert report["capture_context"]["vantage_point_kind"] == "unspecified"
