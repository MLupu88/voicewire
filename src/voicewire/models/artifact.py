"""Artifact: an input file registered and hashed by VoiceWire.

An Artifact is source evidence about *what was supplied*, not about what it
contains. Content interpretation belongs to adapters, downstream.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict

from voicewire.core.ids import stable_id


class ArtifactFormat(str, Enum):
    pcap = "pcap"
    json_trace = "json_trace"


class Artifact(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    path: str
    format: ArtifactFormat
    size_bytes: int
    sha256: str

    @classmethod
    def create(
        cls,
        *,
        name: str,
        path: str,
        format: ArtifactFormat,
        size_bytes: int,
        sha256: str,
    ) -> "Artifact":
        # Identity is derived from content (sha256) and declared format only,
        # never from filename/path, so identical bytes always yield the same
        # artifact id regardless of where they happen to live on disk.
        artifact_id = stable_id("artifact", format.value, sha256)
        return cls(
            id=artifact_id,
            name=name,
            path=path,
            format=format,
            size_bytes=size_bytes,
            sha256=sha256,
        )
