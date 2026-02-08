from pathlib import Path

from app import (
    decode_and_pretty_json_from_base64,
    decode_base64,
    decode_base64_robust,
    encode_base64,
    format_json,
    sha256_for_file,
)


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


def test_base64_normal_decode() -> None:
    ok, decoded = decode_base64_robust("dGVzenQ=")
    assert ok is True
    assert decoded == "teszt"


def test_base64url_decode() -> None:
    raw = "eyJhIjoxfQ"
    ok, decoded = decode_base64_robust(raw)
    assert ok is True
    assert decoded == '{"a":1}'


def test_base64_json_pretty() -> None:
    encoded = encode_base64('{"b":2,"a":1}')
    ok, status, payload = decode_and_pretty_json_from_base64(encoded)
    assert ok is True
    assert status == "JSON ok"
    assert payload == '{\n  "b": 2,\n  "a": 1\n}'


def test_base64_invalid_error() -> None:
    ok, decoded = decode_base64_robust("@@@not-base64@@@")
    assert ok is False
    assert "Érvénytelen" in decoded
