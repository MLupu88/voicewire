"""Generates the synthetic M0 fixture PCAP (call.pcap).

This script is a fixture-authoring tool, NOT a VoiceWire runtime dependency.
It uses scapy purely to hand-assemble deterministic SIP/RTP packets and is
never imported by the `voicewire` package. Re-running it regenerates
call.pcap byte-for-byte identically (fixed synthetic addresses, ports, and
timestamps -- nothing wall-clock-derived).

Usage:
    python3 fixtures/m0-basic/generate_fixture.py

Requires `scapy` installed in the environment running this script (see
fixtures/m0-basic/README.md for why this dependency is kept out of
pyproject.toml).
"""

from __future__ import annotations

import struct
from pathlib import Path

from scapy.all import Ether, IP, UDP, Raw, wrpcap

# Fixed synthetic base time: 2026-01-01T00:00:00Z. Arbitrary but constant,
# so regenerating this fixture is deterministic.
T0 = 1767225600.0

CALLER_IP = "127.0.0.1"
CALLER_SIP_PORT = 5061
CALLER_RTP_PORT = 30000
AGENT_IP = "127.0.0.1"
AGENT_SIP_PORT = 5060
AGENT_RTP_PORT = 30002

CALL_ID = "voicewire-m0@example.test"


def sip_packet(*, src_port: int, dst_port: int, t: float, message: str):
    pkt = (
        Ether()
        / IP(src=CALLER_IP, dst=AGENT_IP)
        / UDP(sport=src_port, dport=dst_port)
        / Raw(load=message.encode("ascii"))
    )
    pkt.time = t
    return pkt


def rtp_packet(*, src_port: int, dst_port: int, t: float, seq: int, rtp_ts: int, ssrc: int, marker: bool = False):
    first_byte = 0x80  # version=2, padding=0, extension=0, CSRC count=0
    second_byte = (0x80 if marker else 0x00) | 0x00  # marker bit | payload type 0 (PCMU)
    header = struct.pack("!BBHII", first_byte, second_byte, seq, rtp_ts, ssrc)
    payload = bytes([0xFF]) * 160  # 20ms of PCMU silence at 8kHz
    pkt = (
        Ether()
        / IP(src=CALLER_IP, dst=AGENT_IP)
        / UDP(sport=src_port, dport=dst_port)
        / Raw(load=header + payload)
    )
    pkt.time = t
    return pkt


def build_sip_message(*, method_or_status: str, via_port: int, extra_headers: str, body: str = "") -> str:
    headers = (
        f"{method_or_status}\r\n"
        f"Via: SIP/2.0/UDP {CALLER_IP}:{via_port};branch=z9hG4bK-{via_port}\r\n"
        f"Call-ID: {CALL_ID}\r\n"
        f"{extra_headers}"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    )
    return headers + body


def main() -> None:
    packets = []

    invite = build_sip_message(
        method_or_status=f"INVITE sip:agent@{AGENT_IP}:{AGENT_SIP_PORT} SIP/2.0",
        via_port=CALLER_SIP_PORT,
        extra_headers=(
            f"From: <sip:caller@example.test>;tag=caller-tag\r\n"
            f"To: <sip:agent@example.test>\r\n"
            "CSeq: 1 INVITE\r\n"
            f"Contact: <sip:caller@{CALLER_IP}:{CALLER_SIP_PORT}>\r\n"
            "Content-Type: application/sdp\r\n"
        ),
        body=(
            "v=0\r\n"
            f"o=caller 1 1 IN IP4 {CALLER_IP}\r\n"
            "s=voicewire-m0\r\n"
            f"c=IN IP4 {CALLER_IP}\r\n"
            "t=0 0\r\n"
            f"m=audio {CALLER_RTP_PORT} RTP/AVP 0\r\n"
        ),
    )
    packets.append(sip_packet(src_port=CALLER_SIP_PORT, dst_port=AGENT_SIP_PORT, t=T0 + 0.000, message=invite))

    ok_200 = build_sip_message(
        method_or_status="SIP/2.0 200 OK",
        via_port=CALLER_SIP_PORT,
        extra_headers=(
            f"From: <sip:caller@example.test>;tag=caller-tag\r\n"
            f"To: <sip:agent@example.test>;tag=agent-tag\r\n"
            "CSeq: 1 INVITE\r\n"
            f"Contact: <sip:agent@{AGENT_IP}:{AGENT_SIP_PORT}>\r\n"
            "Content-Type: application/sdp\r\n"
        ),
        body=(
            "v=0\r\n"
            f"o=agent 1 1 IN IP4 {AGENT_IP}\r\n"
            "s=voicewire-m0\r\n"
            f"c=IN IP4 {AGENT_IP}\r\n"
            "t=0 0\r\n"
            f"m=audio {AGENT_RTP_PORT} RTP/AVP 0\r\n"
        ),
    )
    packets.append(sip_packet(src_port=AGENT_SIP_PORT, dst_port=CALLER_SIP_PORT, t=T0 + 0.100, message=ok_200))

    ack = build_sip_message(
        method_or_status=f"ACK sip:agent@{AGENT_IP}:{AGENT_SIP_PORT} SIP/2.0",
        via_port=CALLER_SIP_PORT,
        extra_headers=(
            f"From: <sip:caller@example.test>;tag=caller-tag\r\n"
            f"To: <sip:agent@example.test>;tag=agent-tag\r\n"
            "CSeq: 1 ACK\r\n"
        ),
    )
    packets.append(sip_packet(src_port=CALLER_SIP_PORT, dst_port=AGENT_SIP_PORT, t=T0 + 0.150, message=ack))

    # A short synthetic RTP stream, caller -> agent, 5 packets of 20ms PCMU.
    ssrc = 0xCAFEBABE
    for i in range(5):
        packets.append(
            rtp_packet(
                src_port=CALLER_RTP_PORT,
                dst_port=AGENT_RTP_PORT,
                t=T0 + 0.500 + i * 0.020,
                seq=1000 + i,
                rtp_ts=8000 + i * 160,
                ssrc=ssrc,
                marker=(i == 0),
            )
        )

    bye = build_sip_message(
        method_or_status=f"BYE sip:agent@{AGENT_IP}:{AGENT_SIP_PORT} SIP/2.0",
        via_port=CALLER_SIP_PORT,
        extra_headers=(
            f"From: <sip:caller@example.test>;tag=caller-tag\r\n"
            f"To: <sip:agent@example.test>;tag=agent-tag\r\n"
            "CSeq: 2 BYE\r\n"
        ),
    )
    packets.append(sip_packet(src_port=CALLER_SIP_PORT, dst_port=AGENT_SIP_PORT, t=T0 + 1.100, message=bye))

    bye_ok = build_sip_message(
        method_or_status="SIP/2.0 200 OK",
        via_port=CALLER_SIP_PORT,
        extra_headers=(
            f"From: <sip:caller@example.test>;tag=caller-tag\r\n"
            f"To: <sip:agent@example.test>;tag=agent-tag\r\n"
            "CSeq: 2 BYE\r\n"
        ),
    )
    packets.append(sip_packet(src_port=AGENT_SIP_PORT, dst_port=CALLER_SIP_PORT, t=T0 + 1.150, message=bye_ok))

    out_path = Path(__file__).parent / "call.pcap"
    wrpcap(str(out_path), packets)
    print(f"wrote {out_path} ({len(packets)} packets)")


if __name__ == "__main__":
    main()
