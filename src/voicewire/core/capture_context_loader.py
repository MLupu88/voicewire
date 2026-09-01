"""Loads an optional, explicitly-supplied CaptureContext manifest.

VoiceWire never infers a PCAP's capture vantage point from packet contents.
If the caller does not supply a manifest, the capture context is
`unspecified` -- that is a correct, final answer, not a gap to fill in later.
"""

from __future__ import annotations

import json
from pathlib import Path

from voicewire.models.capture_context import CaptureContext, SuppliedBy, VantagePointKind


class CaptureContextFormatError(ValueError):
    pass


def load_capture_context(manifest_path: Path | None) -> CaptureContext:
    if manifest_path is None:
        return CaptureContext.unspecified()

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    vantage_point = data.get("vantage_point", {})
    kind_raw = vantage_point.get("kind")
    if not kind_raw:
        raise CaptureContextFormatError("capture context manifest missing vantage_point.kind")
    try:
        kind = VantagePointKind(kind_raw)
    except ValueError as exc:
        raise CaptureContextFormatError(f"unsupported vantage_point.kind {kind_raw!r}") from exc

    supplied_by_raw = data.get("supplied_by", {})
    method = supplied_by_raw.get("method", "fixture_manifest")

    return CaptureContext(
        vantage_point_kind=kind,
        vantage_point_label=vantage_point.get("label"),
        interface=data.get("interface"),
        supplied_by=SuppliedBy(method=method),
    )
