from voicewire.adapters import tshark


def test_tshark_version_detected():
    version = tshark.get_tshark_version()
    assert version and version != "unknown"


def test_extracts_sip_and_rtp_from_real_fixture_pcap(pcap_path):
    events = tshark.extract_sip_rtp_evidence(pcap_path, artifact_id="artifact:pcap-test")

    sip_events = [e for e in events if e.kind == "sip.message"]
    rtp_events = [e for e in events if e.kind == "rtp.packet"]

    assert len(sip_events) == 5  # INVITE, 200, ACK, BYE, 200
    assert len(rtp_events) == 5


def test_sip_call_id_extracted(pcap_path):
    events = tshark.extract_sip_rtp_evidence(pcap_path, artifact_id="artifact:pcap-test")
    sip_events = [e for e in events if e.kind == "sip.message"]

    call_ids = {e.attributes["call_id"] for e in sip_events}
    assert call_ids == {"voicewire-m0@example.test"}


def test_sip_events_retain_frame_provenance(pcap_path):
    events = tshark.extract_sip_rtp_evidence(pcap_path, artifact_id="artifact:pcap-test")
    invite = next(e for e in events if e.attributes.get("method") == "INVITE")

    assert invite.source.locator == "frame:1"
    assert invite.source.artifact_id == "artifact:pcap-test"
    assert invite.source.adapter == "tshark"
    assert invite.raw_ref is not None
    assert "sip.Call-ID" in invite.raw_ref


def test_rtp_evidence_fields(pcap_path):
    events = tshark.extract_sip_rtp_evidence(pcap_path, artifact_id="artifact:pcap-test")
    rtp_events = sorted(
        (e for e in events if e.kind == "rtp.packet"),
        key=lambda e: e.attributes["sequence_number"],
    )

    first = rtp_events[0]
    assert first.attributes["ssrc"] == "0xcafebabe"
    assert first.attributes["sequence_number"] == 1000
    assert first.attributes["payload_type"] == 0
    assert first.attributes["rtp_timestamp"] == 8000
    assert first.attributes["src_port"] == "30000"
    assert first.attributes["dst_port"] == "30002"
    assert first.source.locator.startswith("frame:")


def test_sdp_media_fields_normalized_on_invite(pcap_path):
    events = tshark.extract_sip_rtp_evidence(pcap_path, artifact_id="artifact:pcap-test")
    invite = next(e for e in events if e.attributes.get("method") == "INVITE")

    assert invite.attributes["sdp_media_type"] == "audio"
    assert invite.attributes["sdp_media_port"] == 30000
    assert invite.attributes["sdp_media_proto"] == "RTP/AVP"
    assert invite.attributes["sdp_media_payload_types"] == [0]
    assert invite.attributes["sdp_connection_address"] == "127.0.0.1"


def test_sdp_media_fields_normalized_on_200_ok(pcap_path):
    events = tshark.extract_sip_rtp_evidence(pcap_path, artifact_id="artifact:pcap-test")
    ok_200 = next(e for e in events if e.attributes.get("status_code") == "200" and e.attributes.get("cseq_method") == "INVITE")

    assert ok_200.attributes["sdp_media_port"] == 30002
    assert ok_200.attributes["sdp_media_payload_types"] == [0]
    assert ok_200.attributes["sdp_connection_address"] == "127.0.0.1"


def test_sdp_fields_absent_on_messages_without_a_body(pcap_path):
    events = tshark.extract_sip_rtp_evidence(pcap_path, artifact_id="artifact:pcap-test")
    ack = next(e for e in events if e.attributes.get("method") == "ACK")

    assert "sdp_media_port" not in ack.attributes


def test_extraction_is_deterministic_across_runs(pcap_path):
    first = tshark.extract_sip_rtp_evidence(pcap_path, artifact_id="artifact:pcap-test")
    second = tshark.extract_sip_rtp_evidence(pcap_path, artifact_id="artifact:pcap-test")

    assert [e.id for e in first] == [e.id for e in second]
    assert [e.model_dump() for e in first] == [e.model_dump() for e in second]
