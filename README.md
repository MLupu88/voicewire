# VoiceWire

Evidence-driven diagnostics for voice AI systems. (Working codename —
unchanged.)

## Thesis

```
packet/media evidence
        +
agent evidence
        ↓
cross-layer conversational reconstruction
        ↓
fault-boundary localization
        ↓
evidence-backed diagnosis
```

Wireshark/TShark is adjacent infrastructure, not the product's competitor.

TShark answers: *"What happened on the wire?"*

VoiceWire should eventually answer: *"Why did this voice-agent turn feel
slow or broken, and across which observable boundary did latency/failure
accumulate?"*

If a compelling VoiceWire finding can be reproduced from the PCAP alone, we
have probably failed to prove the interesting part of the product.

Two standing tests every future milestone is held to:

> If the first VoiceWire report does not tell us something useful that
> Wireshark alone and the agent trace alone could not tell us, M1 has
> failed.

> If VoiceWire claims anything stronger than the supplied evidence can
> prove, it has failed even if the conclusion happens to be correct.

## What M0 is

M0 does **not** implement voice-agent diagnosis. It builds the evidence-truth
foundation that any future diagnosis must be trustworthy on top of:
independently hashed input artifacts, TShark-extracted SIP/RTP evidence,
generic trace ingestion, explicit clock domains and alignment, explicit
(non-fuzzy) correlation, and a deterministic, versioned `report.json`.

See `CLAUDE.md` for the permanent architectural rules this project is held
to, and `docs/roadmap.md` for what comes after M0.

## Usage

```bash
pip install -e ".[dev]"
voicewire analyze fixtures/m0-basic/call.pcap \
  --trace fixtures/m0-basic/agent-trace.json \
  --capture-context fixtures/m0-basic/capture-context.json
```

(`--capture-context` is optional; omit it and the report's capture context
is `unspecified` rather than guessed.)

This writes `report.json` and prints a short evidence summary. It does not
print, and does not compute, a latency or fault diagnosis.

Requires Python >= 3.11 and a `tshark` binary on `PATH`.

## Repository layout

- `src/voicewire/models/` — the core evidence data model (see
  `docs/evidence-model.md`).
- `src/voicewire/adapters/` — TShark (SIP/RTP) and trace-fixture ingestion.
- `src/voicewire/core/` — orchestration, hashing, correlation, clock timing.
- `src/voicewire/cli.py` — thin Typer CLI over `core.analyze.run_analysis`.
- `fixtures/m0-basic/` — the one synthetic fixture M0 ships with.
- `docs/` — architecture, evidence model, and roadmap notes.

## License

Not yet decided. See `LICENSE_STATUS.md`. Do not treat the absence of a
`LICENSE` file as public-domain or MIT-equivalent — it means the opposite:
all rights are reserved until a license is explicitly chosen.

## Contributing

See `CONTRIBUTING.md`.
