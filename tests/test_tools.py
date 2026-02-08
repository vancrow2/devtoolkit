from pathlib import Path

from app import format_json, sha256_for_file


def test_format_json_success() -> None:
    ok, out = format_json('{"a":1,"b":2}')
    assert ok is True
    assert '"a": 1' in out
    assert '"b": 2' in out


def test_format_json_error() -> None:
    ok, out = format_json('{"a":}')
    assert ok is False
    assert "Hibás JSON" in out


def test_sha256_for_file(tmp_path: Path) -> None:
    target = tmp_path / "sample.txt"
    target.write_text("abc", encoding="utf-8")
    assert (
        sha256_for_file(target)
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
