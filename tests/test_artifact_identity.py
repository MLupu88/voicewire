from voicewire.core.hashing import sha256_file
from voicewire.models.artifact import Artifact, ArtifactFormat


def _artifact_for(path, format: ArtifactFormat) -> Artifact:
    return Artifact.create(
        name=path.name,
        path=str(path),
        format=format,
        size_bytes=path.stat().st_size,
        sha256=sha256_file(path),
    )


def test_identical_content_yields_identical_artifact_id(tmp_path):
    content = b"identical bytes\n"
    path_a = tmp_path / "a.json"
    path_b = tmp_path / "subdir"
    path_b.mkdir()
    path_b = path_b / "different_name.json"
    path_a.write_bytes(content)
    path_b.write_bytes(content)

    artifact_a = _artifact_for(path_a, ArtifactFormat.json_trace)
    artifact_b = _artifact_for(path_b, ArtifactFormat.json_trace)

    assert artifact_a.id == artifact_b.id
    assert artifact_a.sha256 == artifact_b.sha256


def test_different_content_yields_different_artifact_id(tmp_path):
    path_a = tmp_path / "a.json"
    path_b = tmp_path / "b.json"
    path_a.write_bytes(b"content one")
    path_b.write_bytes(b"content two")

    artifact_a = _artifact_for(path_a, ArtifactFormat.json_trace)
    artifact_b = _artifact_for(path_b, ArtifactFormat.json_trace)

    assert artifact_a.id != artifact_b.id


def test_same_content_different_format_yields_different_artifact_id(tmp_path):
    path = tmp_path / "a.dat"
    path.write_bytes(b"same bytes")

    as_pcap = _artifact_for(path, ArtifactFormat.pcap)
    as_trace = _artifact_for(path, ArtifactFormat.json_trace)

    assert as_pcap.id != as_trace.id
