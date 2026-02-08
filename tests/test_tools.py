from pathlib import Path

from app import (
    build_error_thread_extract,
    decode_and_pretty_json_from_base64,
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
    assert status == "OK"
    assert payload == '{\n  "b": 2,\n  "a": 1\n}'


def test_base64_invalid_error() -> None:
    ok, decoded = decode_base64_robust("@@@not-base64@@@")
    assert ok is False
    assert "Érvénytelen" in decoded


def test_error_thread_extract_all_errors_and_threads() -> None:
    raw = """2026-02-08 10:00:00 LEVEL=Info ThreadId=11 Message=Start
2026-02-08 10:00:01 LEVEL=Error ThreadId=11 Message=Első hiba
2026-02-08 10:00:02 LEVEL=Info ThreadId=11 Message=Followup
2026-02-08 10:00:03 LEVEL=Error ThreadId=12 Message=Második hiba
2026-02-08 10:00:04 LEVEL=Info ThreadId=12 Message=After
"""
    err_count, thread_count, out = build_error_thread_extract(raw)
    assert err_count == 2
    assert thread_count == 2
    assert "===== ERROR #1" in out
    assert "===== ERROR #2" in out
    assert "ThreadId=11" in out
    assert "ThreadId=12" in out
    assert "----------------------------------------" in out


def test_error_thread_extract_no_error() -> None:
    raw = "2026-02-08 10:00:00 LEVEL=Info ThreadId=11 Message=Start"
    err_count, thread_count, out = build_error_thread_extract(raw)
    assert err_count == 0
    assert thread_count == 0
    assert "Nincs Error" in out


def test_error_thread_extract_pipe_delimited_log_format() -> None:
    raw = """Verbose|2/8/2026 10:43:56 AM|19236|S|S|...\nError|2/8/2026 10:43:56 AM|19236|S|S|HSE-L|SSL_VSRE_004_L-A bejelentkezési azonosító érvénytelen.\nInformation|2/8/2026 10:43:56 AM|19236|5|T|PERF(EROR)|[Login]00:00.719\nWarning|2/8/2026 10:43:56 AM|19236|S|S|Failed login exception:SSL_VSRE_004_L-A bejelentkezési azonosító érvénytelen.\n"""
    err_count, thread_count, out = build_error_thread_extract(raw)
    assert err_count == 1
    assert thread_count == 1
    assert "ThreadId=19236" in out
    assert "SSL_VSRE_004_L" in out
