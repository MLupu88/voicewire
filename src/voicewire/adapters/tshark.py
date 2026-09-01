"""TShark adapter: SIP/RTP evidence extraction from a PCAP.

VoiceWire does not parse SIP or RTP itself. TShark understands the packet;
this adapter only reshapes TShark's own structured output into VoiceWire's
EvidenceEvent shape, retaining frame-level provenance. If TShark cannot
identify a protocol, VoiceWire does not try to identify it either.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from voicewire.core.ids import stable_id
from voicewire.models.clock import PCAP_CAPTURE_CLOCK_ID
from voicewire.models.evidence import EvidenceEvent, EvidenceSource, EvidenceTime

ADAPTER_NAME = "tshark"

# Enables tshark's heuristic RTP dissector: without it, RTP over an arbitrary
# UDP port pair (no preceding SDP negotiation tshark can see, or SDP tshark
# chooses not to trust) is not recognized as RTP at all.
_TSHARK_ARGS = ["-o", "rtp.heuristic_rtp:TRUE"]

_VERSION_RE = re.compile(r"TShark \(Wireshark\)\s+([0-9]+\.[0-9]+\.[0-9]+)")


class TSharkNotFoundError(RuntimeError):
    pass


class TSharkExecutionError(RuntimeError):
    pass


def find_tshark() -> str:
    path = shutil.which("tshark")
    if path is None:
        raise TSharkNotFoundError(
            "tshark was not found on PATH. VoiceWire relies on TShark for all "
            "SIP/RTP packet dissection and does not implement its own parser."
        )
    return path


def get_tshark_version() -> str:
    tshark = find_tshark()
    result = subprocess.run(
        [tshark, "--version"], capture_output=True, text=True, check=True
    )
    first_line = result.stdout.splitlines()[0] if result.stdout else ""
    match = _VERSION_RE.search(first_line)
    if match:
        return match.group(1)
    return first_line.strip() or "unknown"


def _flatten(node: dict[str, Any]) -> dict[str, Any]:
    """Flatten tshark's nested `<field>_tree` JSON structure into one dict
    keyed by fully-qualified tshark field name."""
    flat: dict[str, Any] = {}
    for key, value in node.items():
        if isinstance(value, dict):
            flat.update(_flatten(value))
        else:
            flat[key] = value
    return flat


def _addr_and_ports(layers: dict[str, Any]) -> dict[str, Optional[str]]:
    ip_flat = _flatten(layers.get("ip", {})) or _flatten(layers.get("ipv6", {}))
    udp_flat = _flatten(layers.get("udp", {}))
    return {
        "src_ip": ip_flat.get("ip.src") or ip_flat.get("ipv6.src"),
        "dst_ip": ip_flat.get("ip.dst") or ip_flat.get("ipv6.dst"),
        "src_port": udp_flat.get("udp.srcport"),
        "dst_port": udp_flat.get("udp.dstport"),
    }


def _sdp_media_attributes(flat: dict[str, Any]) -> dict[str, Any]:
    """Normalize the minimum SDP media-negotiation fields needed to later
    correlate an RTP stream to the SDP that negotiated it.

    `sdp.media` is tshark's own already-dissected "m=" line, e.g.
    "audio 30000 RTP/AVP 0". tshark exposes the media type/port/proto as
    distinct fields but has no distinct field for the trailing numeric
    payload-type list, so that list is read by splitting tshark's own field
    value -- not by re-parsing SDP syntax tshark didn't already validate.

    M0 assumes a single `m=` line per SDP body (true of this fixture); a
    body with multiple media lines would collide here, since tshark's flat
    JSON does not index repeated fields. That is a documented M0 limitation,
    not a silent one.
    """
    media_line = flat.get("sdp.media")
    if not media_line:
        return {}

    attributes: dict[str, Any] = {}
    if flat.get("sdp.media.media"):
        attributes["sdp_media_type"] = flat["sdp.media.media"]
    if flat.get("sdp.media.port"):
        attributes["sdp_media_port"] = int(flat["sdp.media.port"])
    if flat.get("sdp.media.proto"):
        attributes["sdp_media_proto"] = flat["sdp.media.proto"]
    payload_types = [token for token in media_line.split()[3:] if token.isdigit()]
    if payload_types:
        attributes["sdp_media_payload_types"] = [int(p) for p in payload_types]
    if flat.get("sdp.connection_info.address"):
        attributes["sdp_connection_address"] = flat["sdp.connection_info.address"]
    return attributes


def _build_sip_event(
    *, artifact_id: str, adapter_version: str, frame_number: str, timestamp: datetime, layers: dict[str, Any]
) -> EvidenceEvent:
    flat = _flatten(layers["sip"])
    endpoints = _addr_and_ports(layers)
    attributes: dict[str, Any] = {}
    if flat.get("sip.Call-ID"):
        attributes["call_id"] = flat["sip.Call-ID"]
    if flat.get("sip.Method"):
        attributes["method"] = flat["sip.Method"]
    if flat.get("sip.Status-Code"):
        attributes["status_code"] = flat["sip.Status-Code"]
    if flat.get("sip.CSeq.seq"):
        attributes["cseq_number"] = flat["sip.CSeq.seq"]
    if flat.get("sip.CSeq.method"):
        attributes["cseq_method"] = flat["sip.CSeq.method"]
    attributes.update({k: v for k, v in endpoints.items() if v is not None})
    attributes.update(_sdp_media_attributes(flat))

    locator = f"frame:{frame_number}"
    return EvidenceEvent(
        id=stable_id("evidence", artifact_id, ADAPTER_NAME, locator, "sip.message"),
        kind="sip.message",
        source=EvidenceSource(
            artifact_id=artifact_id,
            adapter=ADAPTER_NAME,
            adapter_version=adapter_version,
            locator=locator,
        ),
        time=EvidenceTime(
            clock_id=PCAP_CAPTURE_CLOCK_ID,
            timestamp=timestamp,
            precision="microsecond",
            basis="capture_timestamp",
        ),
        attributes=attributes,
        raw_ref=json.dumps(flat, sort_keys=True),
    )


def _build_rtp_event(
    *, artifact_id: str, adapter_version: str, frame_number: str, timestamp: datetime, layers: dict[str, Any]
) -> EvidenceEvent:
    flat = _flatten(layers["rtp"])
    endpoints = _addr_and_ports(layers)
    attributes: dict[str, Any] = {}
    if flat.get("rtp.ssrc") is not None:
        attributes["ssrc"] = flat["rtp.ssrc"]
    if flat.get("rtp.seq") is not None:
        attributes["sequence_number"] = int(flat["rtp.seq"])
    if flat.get("rtp.p_type") is not None:
        attributes["payload_type"] = int(flat["rtp.p_type"])
    if flat.get("rtp.timestamp") is not None:
        attributes["rtp_timestamp"] = int(flat["rtp.timestamp"])
    if flat.get("rtp.marker") is not None:
        attributes["marker"] = flat["rtp.marker"] == "1"
    attributes.update({k: v for k, v in endpoints.items() if v is not None})

    locator = f"frame:{frame_number}"
    return EvidenceEvent(
        id=stable_id("evidence", artifact_id, ADAPTER_NAME, locator, "rtp.packet"),
        kind="rtp.packet",
        source=EvidenceSource(
            artifact_id=artifact_id,
            adapter=ADAPTER_NAME,
            adapter_version=adapter_version,
            locator=locator,
        ),
        time=EvidenceTime(
            clock_id=PCAP_CAPTURE_CLOCK_ID,
            timestamp=timestamp,
            precision="microsecond",
            basis="capture_timestamp",
        ),
        attributes=attributes,
        raw_ref=json.dumps(flat, sort_keys=True),
    )


def extract_sip_rtp_evidence(pcap_path: Path, *, artifact_id: str) -> list[EvidenceEvent]:
    """Run tshark against `pcap_path` and return normalized SIP/RTP evidence.

    Raises TSharkExecutionError if tshark fails to run against the file.
    """
    tshark = find_tshark()
    adapter_version = get_tshark_version()
    cmd = [tshark, "-r", str(pcap_path), *_TSHARK_ARGS, "-T", "json", "-Y", "sip || rtp"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise TSharkExecutionError(
            f"tshark failed on {pcap_path} (exit {result.returncode}): {result.stderr.strip()}"
        )

    packets = json.loads(result.stdout) if result.stdout.strip() else []
    events: list[EvidenceEvent] = []
    for packet in packets:
        layers = packet["_source"]["layers"]
        frame_number = layers["frame"]["frame.number"]
        time_epoch = float(layers["frame"]["frame.time_epoch"])
        timestamp = datetime.fromtimestamp(time_epoch, tz=timezone.utc)

        if "sip" in layers:
            events.append(
                _build_sip_event(
                    artifact_id=artifact_id,
                    adapter_version=adapter_version,
                    frame_number=frame_number,
                    timestamp=timestamp,
                    layers=layers,
                )
            )
        elif "rtp" in layers:
            events.append(
                _build_rtp_event(
                    artifact_id=artifact_id,
                    adapter_version=adapter_version,
                    frame_number=frame_number,
                    timestamp=timestamp,
                    layers=layers,
                )
            )
    return events
