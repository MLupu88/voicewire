"""CaptureContext: where a PCAP was observed from, stated explicitly.

VoiceWire never infers a capture vantage point from packet contents. If no
vantage point is supplied out-of-band (e.g. via a fixture manifest), the
context is explicitly `unspecified` -- never guessed, never defaulted to a
"most likely" value.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict


class VantagePointKind(str, Enum):
    agent_host = "agent_host"
    sbc = "sbc"
    media_gateway = "media_gateway"
    caller_side = "caller_side"
    other = "other"
    unspecified = "unspecified"


class SuppliedBy(BaseModel):
    model_config = ConfigDict(frozen=True)

    # e.g. "fixture_manifest", "unspecified"
    method: str


class CaptureContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    vantage_point_kind: VantagePointKind
    vantage_point_label: Optional[str] = None
    interface: Optional[str] = None
    supplied_by: SuppliedBy

    @classmethod
    def unspecified(cls) -> "CaptureContext":
        return cls(
            vantage_point_kind=VantagePointKind.unspecified,
            vantage_point_label=None,
            interface=None,
            supplied_by=SuppliedBy(method="unspecified"),
        )
