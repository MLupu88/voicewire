# Roadmap

## M0 — Evidence Truth (this milestone)

Establish the evidence-truth foundation: hashed artifacts, TShark-extracted
SIP/RTP evidence, generic trace ingestion, explicit clock domains and
alignment, explicit non-fuzzy correlation, and a deterministic, versioned
`report.json`. No diagnosis. See `docs/architecture.md` and
`docs/evidence-model.md` for what was actually built.

## M1 and beyond (not started, not scoped in detail here)

Everything below is explicitly **out of scope** for M0 and has not been
designed yet. Listing it here is not a commitment to build it in this shape
— it's a placeholder for where the product thesis points next, to be
scoped properly when M1 actually starts.

- Cross-layer conversational turn reconstruction (tying SIP/RTP evidence and
  agent-trace evidence together into a coherent turn timeline).
- Real `DerivedObservation`s — starting with the audio-activity boundary the
  evidence model already has a home for (`media.audio_activity_start` and
  similar), produced by an explicit, versioned method.
- Fault-boundary localization: which observable boundary a conversational
  turn's latency or failure crossed.
- Evidence-backed diagnosis, with the standing constraint that VoiceWire
  must be willing to say "Exact internal cause: UNOBSERVABLE FROM SUPPLIED
  EVIDENCE" rather than overclaim.
- Additional trace adapters for real agent platforms (only once a concrete
  need and a willing integration target exist — no adapter for its own
  sake).
- An LLM-assisted explanation layer over *already-proven* findings (rule 16
  in `CLAUDE.md`: it narrates, it does not manufacture diagnostic truth).

## Explicitly not on this roadmap without a dedicated future decision

SaaS/cloud ingestion, a web server or REST API, a database, accounts/teams/
billing, a dashboard or web UI, live packet capture, SRTP decryption,
WebRTC support, a plugin marketplace, or a custom SIP/RTP stack. Any of
these showing up in a diff without a milestone contract calling for it is a
scope violation, not a shortcut.
