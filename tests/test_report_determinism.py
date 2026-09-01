from voicewire.core.analyze import AnalysisInputs, run_analysis


def _inputs(pcap_path, trace_path, capture_context_path) -> AnalysisInputs:
    return AnalysisInputs(
        pcap_path=pcap_path, trace_path=trace_path, capture_context_path=capture_context_path
    )


def test_same_inputs_produce_identical_report(pcap_path, trace_path, capture_context_path):
    inputs = _inputs(pcap_path, trace_path, capture_context_path)

    first = run_analysis(inputs)
    second = run_analysis(inputs)

    assert first.model_dump() == second.model_dump()


def test_evidence_event_ids_are_stable_across_runs(pcap_path, trace_path, capture_context_path):
    inputs = _inputs(pcap_path, trace_path, capture_context_path)

    first = run_analysis(inputs)
    second = run_analysis(inputs)

    assert [e.id for e in first.evidence_events] == [e.id for e in second.evidence_events]


def test_report_carries_reproducibility_metadata(pcap_path, trace_path, capture_context_path):
    report = run_analysis(_inputs(pcap_path, trace_path, capture_context_path))

    assert report.report_schema_version
    assert report.voicewire_version
    assert report.runtime.python_version
    assert report.runtime.tshark_version
    assert len(report.inputs) == 2
    assert {a.format.value for a in report.inputs} == {"pcap", "json_trace"}
