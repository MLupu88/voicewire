# Evidence model (M0)

This document describes the domain model in `src/voicewire/models/` and the
epistemic rules it exists to enforce.

## Epistemic rules (permanent)

- Observed ≠ inferred.
- Unknown ≠ zero.
- Unaligned ≠ approximately aligned.
- Unobserved ≠ slow.
- Audio observable at a packet-capture point ≠ audio heard by the caller.
- Localization ≠ root cause.
- Adapters normalize syntax aggressively and semantics conservatively.
- Never strengthen source-event semantics without justification.
- Every derived fact must remain traceable to source evidence.
- VoiceWire must be comfortable saying: "Exact internal cause: UNOBSERVABLE
  FROM SUPPLIED EVIDENCE."

## Artifact

An input file VoiceWire was given, identified by content hash, not by name
or path:

```
Artifact
  id          deterministic: derived from (format, sha256)
  name        original filename, for display only
  path        the path it was supplied at, for display only
  format      pcap | json_trace
  size_bytes
  sha256
```

Two files with identical bytes and the same declared format always get the
same `id`, regardless of what they're named or where they live. `path`/
`name` are provenance-for-humans, not identity.

## CaptureContext

Where a PCAP was captured from — always either **declared** (via an
explicit manifest) or **`unspecified`**. Never inferred from packet
contents.

```
CaptureContext
  vantage_point_kind    agent_host | sbc | media_gateway | caller_side
                         | other | unspecified
  vantage_point_label   optional human label
  interface             optional, e.g. "eth0"
  supplied_by.method    e.g. "fixture_manifest" | "unspecified"
```

## EvidenceEvent

A fact an adapter read directly off a source artifact. Not an inference.

```
EvidenceEvent
  id           deterministic: derived from (artifact_id, adapter, locator, kind)
  kind         "sip.message" | "rtp.packet" | "trace.<source-defined-type>"
  source
    artifact_id
    adapter          e.g. "tshark", "trace_fixture"
    adapter_version
    locator          re-derivable pointer into the artifact, e.g. "frame:12"
                     or "event:evt-3"
  time
    clock_id
    timestamp
    precision        "microsecond" | "millisecond" | "unknown" | ...
    basis            "capture_timestamp" | "source_reported"
  attributes         adapter-normalized fields (call_id, ssrc, ...)
  raw_ref            opaque snapshot of the raw extracted data, for audit
```

Trace event kinds are namespaced (`trace.` + the source's own type string)
but never reworded. If a trace reports `first_audio`, the evidence kind is
`trace.first_audio` — never promoted to something more specific like
`trace.tts_first_audio_received`, because the source didn't say that.

## DerivedObservation

A fact an *algorithm* concluded from evidence — deliberately a different
type from `EvidenceEvent`. M0 does not produce any real derived
observations (there is no audio-activity detection yet); the type exists so
a future one (e.g. `media.audio_activity_start`) has a correct home from day
one.

```
DerivedObservation
  id
  kind
  time
  attributes
  derivation
    method
    method_version
    source_evidence_ids     which EvidenceEvents this came from
```

## ClockDomain / ClockAlignment

Every timestamp belongs to a named clock domain (e.g.
`pcap.capture_clock`, or a trace's own `fixture-clock`). Comparing
timestamps across domains requires an explicit `ClockAlignment`:

```
ClockAlignment
  from_clock_id
  to_clock_id
  type              exact | explicit_offset | unresolved
  offset_seconds    required iff type == explicit_offset
  justification     optional human-readable reasoning
  declared_by       required iff type in (exact, explicit_offset);
                    forbidden iff type == unresolved
```

`declared_by` is the alignment's own provenance -- e.g.
`trace_fixture:clock.alignment_to_capture_clock`, identifying exactly which
input asserted the alignment. This is deliberately the same shape as
`CaptureContext.supplied_by`, and deliberately a *separate* field on a
*separate* model:

**Capture context and clock alignment are independent facts and neither
implies the other.** A `CaptureContext` says WHERE evidence was observed
(e.g. `vantage_point_kind = agent_host`). A `ClockAlignment` says
WHETHER/HOW two clock domains may be compared. Knowing where a PCAP was
captured from tells you nothing about whether its clock matches a trace's
clock, and an exact clock alignment tells you nothing about where the PCAP
was captured from. In `fixtures/m0-basic`, these two facts happen to both be
known (declared in two separate files -- `capture-context.json` and
`agent-trace.json`'s own `clock` section) purely because the fixture
generator controlled both; `tests/test_capture_context_clock_independence.py`
exercises all four combinations of (vantage known/unspecified) x (alignment
resolved/unresolved) through `run_analysis` to prove neither is derived from
the other.

`unresolved` is a legitimate, permanent state for a given pair of clocks in
M0 — VoiceWire does not attempt automatic clock synchronization. See
`voicewire.core.timing.duration_seconds`, the only function allowed to turn
two events into a duration: it raises `UnresolvedClockAlignmentError` rather
than returning a number when the alignment doesn't resolve.

## Correlation

An explicit, evidence-backed relationship between two facts:

```
Correlation
  id
  kind                       e.g. "trace_call_to_sip_dialog"
  method                     e.g. "exact_sip_call_id_match"
  left_ref / right_ref       e.g. "trace:call:<id>" / "sip:call_id:<id>"
  supporting_evidence_ids
```

M0 implements exactly two methods, both exact-match, neither fuzzy nor
timing-based:

- `exact_sip_call_id_match` (`kind = "trace_call_to_sip_dialog"`): a trace's
  declared SIP Call-ID against SIP evidence's Call-ID.
- `exact_sdp_endpoint_match` (`kind = "sdp_media_to_rtp_stream"`): an
  SDP-negotiated media endpoint (address, port, payload type) against an
  observed RTP stream's endpoint and payload type. `left_ref` is
  `"sip:call_id:<id>"`, `right_ref` is `"rtp:stream:<ssrc>"`, and
  `supporting_evidence_ids` cites both the SIP evidence whose SDP body
  declared the matching endpoint and every RTP evidence event in the
  matched stream. This is derived purely from PCAP evidence (SIP, SDP, and
  RTP), independent of whether a trace is even supplied -- it exists so a
  future milestone doing conversational-turn reconstruction does not have
  to invent this SIP-dialog-to-RTP-stream association itself; see
  `voicewire.core.correlate.correlate_sdp_media_to_rtp_streams`.

The SDP fields needed for this (`sdp_media_port`, `sdp_media_proto`,
`sdp_media_payload_types`, `sdp_connection_address`) are normalized as
attributes directly on the `sip.message` `EvidenceEvent` that carries the
SDP body (SDP travels inside a SIP message in these fixtures, so it is not
a separate evidence kind) -- so this correlation, and anything built on top
of it, never needs to parse the opaque `raw_ref` string to find them. M0
assumes a single `m=` media line per SDP body; see
`voicewire.adapters.tshark._sdp_media_attributes` for that documented
limitation.

## AnalysisReport

The sole machine-readable output, and the only thing the CLI (or any future
consumer) is allowed to read from:

```
AnalysisReport
  report_schema_version
  voicewire_version
  scope_note                 a standing reminder: evidence, not diagnosis
  runtime
    python_version
    tshark_version
    voicewire_version
  inputs                     Artifact[]
  capture_context
  clock_domains
  clock_alignments
  evidence_events
  derived_observations       empty in M0
  correlations
```

## The trace fixture format

VoiceWire does not define or market a "tracing standard." The format below
is a minimal synthetic fixture format used only to exercise this
architecture — see `fixtures/m0-basic/README.md` for the concrete example.

```json
{
  "call": { "sip_call_id": "..." },
  "clock": {
    "id": "fixture-clock",
    "type": "wall",
    "alignment_to_capture_clock": { "type": "exact" }
  },
  "events": [
    { "id": "evt-1", "type": "vad.speech_end", "timestamp": "2026-09-01T06:00:04.000Z" }
  ]
}
```

`alignment_to_capture_clock` is optional. Omitting it leaves the alignment
between the trace's clock and `pcap.capture_clock` `unresolved`.
