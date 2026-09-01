# Architecture (M0)

## The invariant

```
EVIDENCE → RECONSTRUCTION → DIAGNOSIS
```

M0 implements only the first stage, and the plumbing needed to keep the
later stages honest: `SOURCE EVIDENCE → DERIVED OBSERVATIONS →
RECONSTRUCTION → DIAGNOSTIC FINDINGS`. There is no reconstruction or
diagnosis logic in this codebase yet.

## Module map

```
src/voicewire/
  models/           Immutable domain model (pydantic, frozen)
    artifact.py        Artifact, ArtifactFormat
    capture_context.py CaptureContext, VantagePointKind, SuppliedBy
    clock.py            ClockDomain, ClockAlignment, AlignmentType,
                         UnresolvedClockAlignmentError
    evidence.py         EvidenceEvent, EvidenceSource, EvidenceTime
    derived.py          DerivedObservation, Derivation
    correlation.py      Correlation, CorrelationMethod
    report.py           AnalysisReport, RuntimeInfo

  adapters/          Turn a source artifact into EvidenceEvents
    tshark.py           SIP/RTP evidence via the tshark binary
    trace_fixture.py    Generic JSON trace ingestion

  core/              Orchestration; no CLI/rendering concerns
    hashing.py          sha256_file
    ids.py              stable_id (deterministic, content/locator-derived)
    capture_context_loader.py  Loads an optional CaptureContext manifest
    correlate.py         Exact-match trace<->SIP-dialog correlation
    timing.py             The only path allowed to compute a cross-clock
                           duration
    analyze.py            run_analysis(): the sole AnalysisReport builder

  reporting/
    summary.py           Plain-text CLI summary, reads only from AnalysisReport

  cli.py               Typer CLI: parses args, calls run_analysis, writes
                         report.json, prints the summary. No analysis logic.
```

## Why adapters are separate from the core model

An adapter's job is narrow: take one artifact and produce `EvidenceEvent`s
(and, for the trace adapter, a declared clock + optional alignment). It does
not correlate across artifacts, does not decide what's "important," and
does not compute anything. All of that lives in `core/`, which is the only
place that assembles a full `AnalysisReport`.

This means a future third adapter (say, a different agent-platform trace
format) plugs in at the same seam without touching `core/analyze.py`'s
shape — it just needs to produce the same `EvidenceEvent` shape the trace
adapter does.

## Identity and determinism

Every ID in this codebase (`Artifact.id`, `EvidenceEvent.id`,
`Correlation.id`) is derived deterministically from stable inputs — content
hash, adapter name, and locator — via `core/ids.stable_id`. No random UUIDs.
This is what makes `report.json` reproducible: the same VoiceWire version
run against the same input bytes produces the same IDs and the same
evidence, every time (see `tests/test_report_determinism.py` and
`tests/test_tshark_extraction.py::test_extraction_is_deterministic_across_runs`).

The one legitimately non-reproducible part of a report is
`runtime.python_version` / `runtime.tshark_version` — those describe the
machine that ran the analysis, not the analysis itself, so the fixture
regression test (`tests/test_cli_e2e.py`) excludes them from its comparison.

## Clock domains and alignment

Every `EvidenceEvent.time.clock_id` names a clock domain. Two events from
different domains cannot be subtracted directly — `core/timing.py`'s
`duration_seconds` requires a `ClockAlignment`, and a `ClockAlignment` with
`type=unresolved` makes `offset_to_apply()` raise
`UnresolvedClockAlignmentError` rather than returning a number. This is
enforced structurally, not by convention — there is no second code path that
skips the check.

## Capture context

`CaptureContext.vantage_point_kind` is either a declared value (loaded from
an explicit manifest via `--capture-context`) or `unspecified`. Nothing in
the TShark adapter or `core/analyze.py` ever inspects packet contents to
guess a vantage point.

**This is independent of clock alignment.** A known vantage point does not
imply, and is never used to derive, a resolved `ClockAlignment` -- they are
loaded from different inputs (an optional `--capture-context` manifest vs.
the trace's own `clock` section) and carry their own separate provenance
(`CaptureContext.supplied_by` vs. `ClockAlignment.declared_by`). See
`tests/test_capture_context_clock_independence.py`, which runs all four
combinations of (vantage known/unspecified) x (alignment
resolved/unresolved) through `run_analysis`.

## Correlation

M0 implements exactly two correlations (`core/correlate.py`), both exact
match, neither fuzzy nor timing-based:

- `trace_call_to_sip_dialog` -- the trace's declared SIP Call-ID against SIP
  evidence's Call-ID.
- `sdp_media_to_rtp_stream` -- an SDP-negotiated media endpoint (address,
  port, payload type, normalized onto the SIP evidence that carried the SDP
  body) against an observed RTP stream's endpoint and payload type. Derived
  purely from PCAP evidence, independent of whether a trace is even
  supplied. This exists so that a future milestone's conversational-turn
  reconstruction is handed "which RTP stream belongs to which SIP dialog's
  negotiated media" as an M0 fact, rather than having to derive that
  lower-layer association itself.

If there's no exact match, the report has zero correlations of that kind —
that is a correct, final answer for M0, not a bug.

## What TShark does vs. what VoiceWire does

TShark: SIP/RTP/SDP dissection, protocol-correct field extraction, per-frame
timestamps. VoiceWire: reshaping that into `EvidenceEvent`s with explicit
provenance, and (starting in a later milestone) reasoning about what those
events mean for a conversational turn. VoiceWire does not parse SIP or RTP
itself, and M0 does not decode, inspect, or reason about audio content at
all.
