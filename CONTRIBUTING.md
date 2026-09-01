# Contributing to VoiceWire

VoiceWire is an implementation-worker-driven project with GitHub as the
source of truth. Before contributing, read `CLAUDE.md` in full — its rules
are not suggestions.

## Development setup

Requires Python >= 3.11 and a `tshark` binary on `PATH`.

```bash
pip install -e ".[dev]"
pytest -q
```

The end-to-end test suite runs the real `tshark` binary against
`fixtures/m0-basic/call.pcap` — it is never mocked out. If `tshark` is
missing, install it (`apt-get install tshark` on Debian/Ubuntu, or use the
provided devcontainer) rather than skipping or stubbing the test.

## Ground rules

- **Evidence → Reconstruction → Diagnosis, never backwards.** Any change
  that lets a "finding" appear without traceable evidence behind it will be
  rejected regardless of how useful it looks.
- **Do not add dependencies without a concrete, current-milestone purpose.**
  In particular, do not reimplement SIP/RTP parsing — that's TShark's job.
- **Do not casually change the evidence schema** (`EvidenceEvent`,
  `DerivedObservation`, `ClockAlignment`, `Correlation`, `AnalysisReport`).
  These are load-bearing contracts; changing their shape needs a deliberate,
  reviewed rationale, not just a passing test suite.
- **Adapters normalize syntax aggressively, semantics conservatively.** If a
  source's event type is ambiguous, keep it ambiguous in the output.
- **Public fixtures must be synthetic.** Never commit real call data,
  real customer identifiers, or anything derived from a production capture.
- **No SaaS/cloud scope creep.** No web server, database, accounts, or live
  ingestion unless a milestone contract explicitly calls for it.
- If a change seems to require stepping outside the current milestone's
  scope, stop and raise it rather than quietly expanding scope.

## Tests

Every new adapter, model, or core behavior needs a test. Cross-clock-domain
behavior specifically needs both a positive case (resolved alignment
produces a number) and a negative case (unresolved alignment raises rather
than silently returning something).

## Commit / branch discipline

Work on the branch you were assigned. Do not open a PR, merge, or publish a
release unless explicitly asked to.
