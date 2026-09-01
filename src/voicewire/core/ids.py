"""Deterministic, content/locator-derived identity helpers.

VoiceWire never assigns random IDs to evidence-bearing objects. Identity must
be reproducible: re-running the same adapter against the same source
artifact must yield the same IDs, so that reports are diffable and
"same inputs -> same output" can be verified mechanically.
"""

from __future__ import annotations

import hashlib


def stable_id(namespace: str, *parts: str) -> str:
    """Build a deterministic id from a namespace and an ordered set of parts.

    The hash input is delimited so that ("ab", "c") and ("a", "bc") cannot
    collide.
    """
    digest = hashlib.sha256()
    digest.update(namespace.encode("utf-8"))
    for part in parts:
        digest.update(b"\x00")
        digest.update(part.encode("utf-8"))
    return f"{namespace}:{digest.hexdigest()[:24]}"
