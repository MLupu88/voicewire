# CLAUDE.md — VoiceWire guardrails

This file governs how work on VoiceWire is done, by any contributor, human
or AI. It takes precedence over convenience, speed, and "looks impressive."

## The permanent architectural invariant

```
EVIDENCE → RECONSTRUCTION → DIAGNOSIS
```

Never backwards. A diagnosis may never be produced or implied without
traceable reconstruction behind it, and reconstruction may never be produced
without traceable evidence behind it.

Within that, keep this finer distinction intact everywhere in the code:

```
SOURCE EVIDENCE
      ↓
DERIVED OBSERVATIONS
      ↓
RECONSTRUCTION
      ↓
DIAGNOSTIC FINDINGS
```

`EvidenceEvent` is source evidence. `DerivedObservation` is something an
algorithm concluded about evidence. These are different types for a reason —
never merge them, never let one silently become the other.

## The sixteen rules

1. **Evidence → Reconstruction → Diagnosis.** Every finding must be
   traceable back through reconstruction to the evidence it rests on.
2. **Never strengthen source semantics silently.** If a source calls
   something `first_audio`, it stays `first_audio`. Do not rename it to a
   more specific, stronger claim (e.g. `tts_first_audio_received`) because
   that's probably what it means. If you're not sure, that uncertainty is
   the fact worth preserving.
3. **Never manufacture missing timing.** No interpolation, no "probably
   happened around here," no filling gaps with assumptions.
4. **Unknown ≠ zero.** A missing measurement is not a zero-duration event.
   Absence of evidence is its own explicit state.
5. **Unaligned clocks cannot silently be compared.** Cross-clock-domain
   durations require a resolved `ClockAlignment` (`exact` or
   `explicit_offset`). `unresolved` must make the computation structurally
   unavailable (raise, not return a number) — see
   `voicewire.models.clock.UnresolvedClockAlignmentError` and
   `voicewire.core.timing.duration_seconds`.
6. **Audio observable at a capture point ≠ audio heard by the caller.**
   Never conflate what a packet capture saw with what a human perceived.
7. **Localization ≠ root cause.** Identifying which boundary a fault
   crossed is not the same as explaining why it happened there.
8. **Preserve raw provenance.** Every `EvidenceEvent` carries a `source`
   (artifact, adapter, adapter_version, locator) and ideally a `raw_ref`.
   Never build an event you can't trace back to what produced it.
9. **Derived observations must name their method, version, and source
   evidence IDs.** No unattributed conclusions.
10. **Use TShark rather than reimplementing packet dissection.** VoiceWire
    does not parse SIP or RTP itself. If TShark can't identify a protocol,
    VoiceWire doesn't try to either.
11. **Core stays vendor-neutral.** No agent-platform-specific assumptions
    baked into the core model or adapters beyond what a generic fixture
    format requires.
12. **Core logic must not live in CLI/rendering code.** `AnalysisReport` is
    the boundary. The CLI (and any future consumer) only reads it.
13. **No SaaS/cloud architecture without a later milestone explicitly
    calling for it.** No web server, no database, no accounts, no live
    ingestion, unless a milestone contract says so.
14. **Public fixtures must be synthetic/sanitized.** No real call data, no
    real customer identifiers, ever, in a fixture committed to this repo.
15. **Do not casually alter the evidence schema.** `EvidenceEvent`,
    `DerivedObservation`, `ClockAlignment`, `Correlation`, and
    `AnalysisReport` are the load-bearing contracts. Changing their shape is
    a deliberate, reviewed decision, not a side effect of an unrelated
    feature.
16. **LLMs may eventually explain proven findings but must not manufacture
    diagnostic truth.** Any future LLM-assisted explanation layer narrates
    what the evidence and reconstruction already established — it does not
    get to invent or strengthen a finding on its own authority.

## Practical corollaries

- If you're about to reimplement something TShark already does, stop.
- If you're about to compare two timestamps from different clock domains
  without an alignment object, stop.
- If you're about to add a field that asserts more confidence than the
  adapter actually has, don't. It is correct and expected for VoiceWire to
  say: **"Exact internal cause: UNOBSERVABLE FROM SUPPLIED EVIDENCE."**
- If a milestone's scope section says something is out of scope and you
  think it's needed anyway, stop and explain rather than silently building
  it.
