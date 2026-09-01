"""DerivedObservation is not produced by any M0 pipeline, but its shape and
provenance requirements must already be correct. This test constructs one
directly to prove that."""

from datetime import datetime, timezone

from voicewire.models.derived import Derivation, DerivedObservation
from voicewire.models.evidence import EvidenceTime


def test_derived_observation_requires_traceable_provenance():
    observation = DerivedObservation(
        id="derived:example",
        kind="media.audio_activity_start",
        time=EvidenceTime(
            clock_id="pcap.capture_clock",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            precision="millisecond",
            basis="derived",
        ),
        attributes={},
        derivation=Derivation(
            method="energy_threshold_vad",
            method_version="0.0.0-not-implemented",
            source_evidence_ids=("evidence:some-rtp-packet",),
        ),
    )

    assert observation.derivation.method_version
    assert observation.derivation.source_evidence_ids
