"""Generic trace-fixture adapter.

This ingests VoiceWire's tiny synthetic trace fixture format (see
fixtures/m0-basic/README.md). It is deliberately not a "VoiceWire tracing
standard" -- it exists only to exercise the evidence architecture.

Rule: adapters normalize syntax aggressively and semantics conservatively.
If a source event is called "first_audio", it stays `trace.first_audio`. It
is never silently strengthened into a stronger claim such as
`trace.tts_first_audio_received`, because the source did not say that.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from voicewire.core.ids import stable_id
from voicewire.models.clock import AlignmentType, ClockAlignment, ClockDomain, ClockType, PCAP_CAPTURE_CLOCK_ID
from voicewire.models.evidence import EvidenceEvent, EvidenceSource, EvidenceTime

ADAPTER_NAME = "trace_fixture"
ADAPTER_VERSION = "0.1.0"


class TraceFixtureFormatError(ValueError):
    pass


@dataclass(frozen=True)
class TraceExtractionResult:
    sip_call_id: Optional[str]
    clock_domain: ClockDomain
    alignment_to_capture_clock: Optional[ClockAlignment]
    events: list[EvidenceEvent]


def _require(data: dict[str, Any], *path: str) -> Any:
    node: Any = data
    for key in path:
        if not isinstance(node, dict) or key not in node:
            raise TraceFixtureFormatError(f"trace fixture missing required field: {'.'.join(path)}")
        node = node[key]
    return node


# Identifies exactly which field of the trace fixture asserted the
# alignment -- this is the alignment's own provenance, independent of (and
# never a substitute for) a CaptureContext's `supplied_by`.
_ALIGNMENT_DECLARED_BY = "trace_fixture:clock.alignment_to_capture_clock"


def _parse_alignment(clock_id: str, raw: dict[str, Any]) -> ClockAlignment:
    alignment_type = raw.get("type")
    if alignment_type == "exact":
        return ClockAlignment(
            from_clock_id=clock_id,
            to_clock_id=PCAP_CAPTURE_CLOCK_ID,
            type=AlignmentType.exact,
            justification=raw.get("justification"),
            declared_by=_ALIGNMENT_DECLARED_BY,
        )
    if alignment_type == "explicit_offset":
        if "offset_seconds" not in raw:
            raise TraceFixtureFormatError("explicit_offset alignment requires offset_seconds")
        return ClockAlignment(
            from_clock_id=clock_id,
            to_clock_id=PCAP_CAPTURE_CLOCK_ID,
            type=AlignmentType.explicit_offset,
            offset_seconds=float(raw["offset_seconds"]),
            justification=raw.get("justification"),
            declared_by=_ALIGNMENT_DECLARED_BY,
        )
    raise TraceFixtureFormatError(
        f"unsupported clock alignment type {alignment_type!r}; expected 'exact' or 'explicit_offset' "
        "(omit alignment_to_capture_clock entirely to leave it unresolved)"
    )


def extract(trace_path: Path, *, artifact_id: str) -> TraceExtractionResult:
    raw_text = trace_path.read_text(encoding="utf-8")
    data = json.loads(raw_text)

    sip_call_id = None
    call_section = data.get("call")
    if isinstance(call_section, dict):
        sip_call_id = call_section.get("sip_call_id")

    clock_raw = _require(data, "clock")
    clock_id = _require(clock_raw, "id")
    clock_type_raw = _require(clock_raw, "type")
    try:
        clock_type = ClockType(clock_type_raw)
    except ValueError as exc:
        raise TraceFixtureFormatError(f"unsupported clock type {clock_type_raw!r}") from exc
    clock_domain = ClockDomain(id=clock_id, type=clock_type)

    alignment = None
    alignment_raw = clock_raw.get("alignment_to_capture_clock")
    if alignment_raw is not None:
        alignment = _parse_alignment(clock_id, alignment_raw)

    events: list[EvidenceEvent] = []
    for raw_event in _require(data, "events"):
        event_id = _require(raw_event, "id")
        event_type = _require(raw_event, "type")
        timestamp_raw = _require(raw_event, "timestamp")
        try:
            timestamp: datetime = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise TraceFixtureFormatError(f"event {event_id!r} has unparseable timestamp {timestamp_raw!r}") from exc

        # Preserve source-defined event type verbatim as a namespaced kind.
        # This is the only "normalization": syntax (adding a `trace.` prefix
        # so evidence kinds are globally distinguishable), never semantics.
        kind = f"trace.{event_type}"

        extra_attributes = {
            k: v for k, v in raw_event.items() if k not in ("id", "type", "timestamp")
        }

        locator = f"event:{event_id}"
        events.append(
            EvidenceEvent(
                id=stable_id("evidence", artifact_id, ADAPTER_NAME, locator, kind),
                kind=kind,
                source=EvidenceSource(
                    artifact_id=artifact_id,
                    adapter=ADAPTER_NAME,
                    adapter_version=ADAPTER_VERSION,
                    locator=locator,
                ),
                time=EvidenceTime(
                    clock_id=clock_id,
                    timestamp=timestamp,
                    precision="unknown",
                    basis="source_reported",
                ),
                attributes=extra_attributes,
                raw_ref=json.dumps(raw_event, sort_keys=True),
            )
        )

    return TraceExtractionResult(
        sip_call_id=sip_call_id,
        clock_domain=clock_domain,
        alignment_to_capture_clock=alignment,
        events=events,
    )
