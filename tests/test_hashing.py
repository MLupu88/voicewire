import hashlib

from voicewire.core.hashing import sha256_file


def test_sha256_file_matches_reference(tmp_path):
    content = b"voicewire test content\n" * 1000
    path = tmp_path / "sample.bin"
    path.write_bytes(content)

    assert sha256_file(path) == hashlib.sha256(content).hexdigest()


def test_sha256_file_deterministic_across_calls(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"same bytes")

    assert sha256_file(path) == sha256_file(path)
