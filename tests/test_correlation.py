from datetime import datetime, timezone

from voicewire.core.correlate import correlate_sdp_media_to_rtp_streams, correlate_trace_call_to_sip_dialog
from voicewire.models.correlation import CorrelationMethod
from voicewire.models.evidence import EvidenceEvent, EvidenceSource, EvidenceTime


def _sip_event(call_id: str, locator: str, **extra_attributes) -> EvidenceEvent:
    return EvidenceEvent(
        id=f"evidence:{locator}",
        kind="sip.message",
        source=EvidenceSource(artifact_id="artifact:pcap", adapter="tshark", adapter_version="4.2.2", locator=locator),
        time=EvidenceTime(
            clock_id="pcap.capture_clock",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            precision="microsecond",
            basis="capture_timestamp",
        ),
        attributes={"call_id": call_id, **extra_attributes},
    )


def _sip_event_with_sdp(call_id: str, locator: str, *, address: str, port: int, payload_types: list[int]) -> EvidenceEvent:
    return _sip_event(
        call_id,
        locator,
        sdp_connection_address=address,
        sdp_media_port=port,
        sdp_media_payload_types=payload_types,
    )


def _rtp_event(locator: str, *, src_ip: str, src_port: str, dst_ip: str, dst_port: str, payload_type: int, ssrc: str) -> EvidenceEvent:
    return EvidenceEvent(
        id=f"evidence:{locator}",
        kind="rtp.packet",
        source=EvidenceSource(artifact_id="artifact:pcap", adapter="tshark", adapter_version="4.2.2", locator=locator),
        time=EvidenceTime(
            clock_id="pcap.capture_clock",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            precision="microsecond",
            basis="capture_timestamp",
        ),
        attributes={
            "ssrc": ssrc,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "payload_type": payload_type,
        },
    )


def test_exact_match_produces_correlation():
    events = [_sip_event("call-1@example.test", "frame:1"), _sip_event("call-2@example.test", "frame:2")]

    correlations = correlate_trace_call_to_sip_dialog(
        trace_sip_call_id="call-1@example.test", evidence_events=events
    )

    assert len(correlations) == 1
    assert correlations[0].supporting_evidence_ids == ("evidence:frame:1",)


def test_no_match_produces_no_correlation():
    events = [_sip_event("call-2@example.test", "frame:2")]

    correlations = correlate_trace_call_to_sip_dialog(
        trace_sip_call_id="call-1@example.test", evidence_events=events
    )

    assert correlations == []


def test_no_trace_call_id_produces_no_correlation():
    events = [_sip_event("call-1@example.test", "frame:1")]

    correlations = correlate_trace_call_to_sip_dialog(trace_sip_call_id=None, evidence_events=events)

    assert correlations == []


def test_sdp_endpoint_match_correlates_rtp_stream_to_sip_dialog():
    sip_offer = _sip_event_with_sdp("call-1@example.test", "frame:1", address="10.0.0.1", port=30000, payload_types=[0])
    sip_answer = _sip_event_with_sdp("call-1@example.test", "frame:2", address="10.0.0.2", port=30002, payload_types=[0])
    rtp = _rtp_event("frame:4", src_ip="10.0.0.1", src_port="30000", dst_ip="10.0.0.2", dst_port="30002", payload_type=0, ssrc="0xabc")

    correlations = correlate_sdp_media_to_rtp_streams([sip_offer, sip_answer, rtp])

    assert len(correlations) == 1
    correlation = correlations[0]
    assert correlation.kind == "sdp_media_to_rtp_stream"
    assert correlation.method == CorrelationMethod.exact_sdp_endpoint_match
    assert correlation.left_ref == "sip:call_id:call-1@example.test"
    assert correlation.right_ref == "rtp:stream:0xabc"
    assert set(correlation.supporting_evidence_ids) == {"evidence:frame:1", "evidence:frame:2", "evidence:frame:4"}


def test_mismatched_port_produces_no_correlation():
    sip_offer = _sip_event_with_sdp("call-1@example.test", "frame:1", address="10.0.0.1", port=30000, payload_types=[0])
    rtp = _rtp_event("frame:4", src_ip="10.0.0.1", src_port="99999", dst_ip="10.0.0.2", dst_port="30002", payload_type=0, ssrc="0xabc")

    correlations = correlate_sdp_media_to_rtp_streams([sip_offer, rtp])

    assert correlations == []


def test_mismatched_payload_type_produces_no_correlation():
    sip_offer = _sip_event_with_sdp("call-1@example.test", "frame:1", address="10.0.0.1", port=30000, payload_types=[8])
    rtp = _rtp_event("frame:4", src_ip="10.0.0.1", src_port="30000", dst_ip="10.0.0.2", dst_port="30002", payload_type=0, ssrc="0xabc")

    correlations = correlate_sdp_media_to_rtp_streams([sip_offer, rtp])

    assert correlations == []


def test_different_dialogs_are_not_merged_even_with_matching_endpoints():
    """Two distinct SIP dialogs whose SDP happens to declare the exact same
    endpoint/payload type must not be silently merged into one correlation --
    each dialog gets its own record, keyed by Call-ID."""
    sip_call_a = _sip_event_with_sdp("call-a@example.test", "frame:1", address="10.0.0.1", port=30000, payload_types=[0])
    sip_call_b = _sip_event_with_sdp("call-b@example.test", "frame:2", address="10.0.0.1", port=30000, payload_types=[0])
    rtp = _rtp_event("frame:4", src_ip="10.0.0.1", src_port="30000", dst_ip="10.0.0.2", dst_port="30002", payload_type=0, ssrc="0xabc")

    correlations = correlate_sdp_media_to_rtp_streams([sip_call_a, sip_call_b, rtp])

    assert len(correlations) == 2
    call_ids = {c.left_ref for c in correlations}
    assert call_ids == {"sip:call_id:call-a@example.test", "sip:call_id:call-b@example.test"}


def test_sdp_rtp_correlation_is_deterministic_across_calls():
    sip_offer = _sip_event_with_sdp("call-1@example.test", "frame:1", address="10.0.0.1", port=30000, payload_types=[0])
    rtp = _rtp_event("frame:4", src_ip="10.0.0.1", src_port="30000", dst_ip="10.0.0.2", dst_port="30002", payload_type=0, ssrc="0xabc")

    first = correlate_sdp_media_to_rtp_streams([sip_offer, rtp])
    second = correlate_sdp_media_to_rtp_streams([sip_offer, rtp])

    assert [c.id for c in first] == [c.id for c in second]
