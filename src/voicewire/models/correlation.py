"""Correlation: an explicit, evidence-backed relationship between two facts.

M0 implements exactly two correlation methods, both exact-match, neither
fuzzy nor timing-based:

- `exact_sip_call_id_match`: a trace's declared SIP Call-ID against a SIP
  Call-ID observed in the PCAP.
- `exact_sdp_endpoint_match`: an SDP-negotiated media endpoint (address,
  port, payload type -- all read from a SIP message's own SDP body) against
  an observed RTP stream's endpoint and payload type.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class CorrelationMethod(str, Enum):
    exact_sip_call_id_match = "exact_sip_call_id_match"
    exact_sdp_endpoint_match = "exact_sdp_endpoint_match"


class Correlation(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    # e.g. "trace_call_to_sip_dialog"
    kind: str
    method: CorrelationMethod
    left_ref: str
    right_ref: str
    supporting_evidence_ids: tuple[str, ...]
