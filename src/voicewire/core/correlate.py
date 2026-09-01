"""Explicit, non-fuzzy correlation between evidence.

M0 supports exactly two correlation methods, both exact-match:

- `correlate_trace_call_to_sip_dialog`: the trace's declared SIP Call-ID
  against a SIP Call-ID observed in the PCAP's SIP evidence.
- `correlate_sdp_media_to_rtp_streams`: an SDP-negotiated media endpoint
  (address, port, payload type) against an observed RTP stream's endpoint
  and payload type -- purely from PCAP evidence, independent of whether a
  trace was even supplied. This is what lets a future milestone ask "which
  RTP stream belongs to which SIP dialog's negotiated media" without
  inventing that association itself.

If there is no exact match, VoiceWire reports zero correlations -- it does
not guess at a "closest" dialog or stream.
"""

from __future__ import annotations

from typing import Optional

from voicewire.core.ids import stable_id
from voicewire.models.correlation import Correlation, CorrelationMethod
from voicewire.models.evidence import EvidenceEvent


def correlate_trace_call_to_sip_dialog(
    *, trace_sip_call_id: Optional[str], evidence_events: list[EvidenceEvent]
) -> list[Correlation]:
    if not trace_sip_call_id:
        return []

    matching_ids = sorted(
        event.id
        for event in evidence_events
        if event.kind == "sip.message" and event.attributes.get("call_id") == trace_sip_call_id
    )
    if not matching_ids:
        return []

    correlation_id = stable_id("correlation", "trace_call_to_sip_dialog", trace_sip_call_id)
    return [
        Correlation(
            id=correlation_id,
            kind="trace_call_to_sip_dialog",
            method=CorrelationMethod.exact_sip_call_id_match,
            left_ref=f"trace:call:{trace_sip_call_id}",
            right_ref=f"sip:call_id:{trace_sip_call_id}",
            supporting_evidence_ids=tuple(matching_ids),
        )
    ]


def _rtp_endpoint_matches_sdp_media(rtp_event: EvidenceEvent, sdp_event: EvidenceEvent) -> bool:
    address = sdp_event.attributes.get("sdp_connection_address")
    port = sdp_event.attributes.get("sdp_media_port")
    payload_types = set(sdp_event.attributes.get("sdp_media_payload_types", ()))
    if address is None or port is None or not payload_types:
        return False
    if rtp_event.attributes.get("payload_type") not in payload_types:
        return False
    port_str = str(port)
    src_matches = (
        rtp_event.attributes.get("src_ip") == address and rtp_event.attributes.get("src_port") == port_str
    )
    dst_matches = (
        rtp_event.attributes.get("dst_ip") == address and rtp_event.attributes.get("dst_port") == port_str
    )
    return src_matches or dst_matches


def correlate_sdp_media_to_rtp_streams(evidence_events: list[EvidenceEvent]) -> list[Correlation]:
    """Correlate each observed RTP stream (grouped by SSRC) to the SIP
    dialog whose SDP negotiated a matching media endpoint and payload type.

    Grouping RTP evidence by (SIP Call-ID, SSRC) rather than emitting one
    correlation per RTP packet keeps this to one record per logical media
    stream. Grouping the match by Call-ID (rather than just SSRC) avoids
    silently merging two different dialogs that happened to reuse the same
    SSRC or port -- exact match only, no cross-dialog guessing.
    """
    sip_events_with_sdp = [
        event
        for event in evidence_events
        if event.kind == "sip.message" and "sdp_media_port" in event.attributes
    ]
    rtp_events_by_ssrc: dict[str, list[EvidenceEvent]] = {}
    for event in evidence_events:
        if event.kind != "rtp.packet":
            continue
        ssrc = event.attributes.get("ssrc")
        if ssrc is not None:
            rtp_events_by_ssrc.setdefault(ssrc, []).append(event)

    correlations: list[Correlation] = []
    for ssrc in sorted(rtp_events_by_ssrc):
        stream_events = rtp_events_by_ssrc[ssrc]
        supporting_ids_by_call_id: dict[str, set[str]] = {}
        for sdp_event in sip_events_with_sdp:
            call_id = sdp_event.attributes.get("call_id")
            if not call_id:
                continue
            matched_rtp_ids = {
                rtp_event.id
                for rtp_event in stream_events
                if _rtp_endpoint_matches_sdp_media(rtp_event, sdp_event)
            }
            if matched_rtp_ids:
                bucket = supporting_ids_by_call_id.setdefault(call_id, set())
                bucket.add(sdp_event.id)
                bucket.update(matched_rtp_ids)

        for call_id in sorted(supporting_ids_by_call_id):
            correlation_id = stable_id("correlation", "sdp_media_to_rtp_stream", call_id, ssrc)
            correlations.append(
                Correlation(
                    id=correlation_id,
                    kind="sdp_media_to_rtp_stream",
                    method=CorrelationMethod.exact_sdp_endpoint_match,
                    left_ref=f"sip:call_id:{call_id}",
                    right_ref=f"rtp:stream:{ssrc}",
                    supporting_evidence_ids=tuple(sorted(supporting_ids_by_call_id[call_id])),
                )
            )
    return correlations
