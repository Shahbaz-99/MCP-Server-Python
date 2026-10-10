from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_hub.config import Settings, masked_dump
from mcp_hub.errors import AccessDenied, to_public_message
from mcp_hub.logging import JsonFormatter, configure_logging, correlation_id, log_fields, redact


def test_defaults_are_safe() -> None:
    s = Settings()
    assert s.http.host == "127.0.0.1"
    assert s.http.allow_public_bind is False
    assert s.auth.enabled is False
    assert s.github.enable_write is False


def test_env_overrides_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("log_level: DEBUG\nhttp:\n  port: 9000\n", encoding="utf-8")
    monkeypatch.setenv("MCP_HUB_CONFIG_FILE", str(cfg))
    assert Settings().http.port == 9000
    monkeypatch.setenv("MCP_HUB_LOG_LEVEL", "ERROR")
    assert Settings().log_level == "ERROR"


def test_init_kwarg_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_HUB_LOG_LEVEL", "ERROR")
    assert Settings(log_level="WARNING").log_level == "WARNING"


def test_invalid_config_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(log_level="LOUD")
    with pytest.raises(ValidationError):
        Settings(unknown_key=1)  # type: ignore[call-arg]


def test_secrets_masked() -> None:
    s = Settings(github={"token": "ghp_" + "a" * 30})
    dumped = json.dumps(masked_dump(s))
    assert "ghp_" not in dumped


def test_auth_requires_fields() -> None:
    with pytest.raises(ValueError, match=r"auth\.enabled"):
        Settings(auth={"enabled": True}).check_startup_invariants()


def test_auth_issuer_must_be_https() -> None:
    bad = Settings(
        auth={
            "enabled": True,
            "issuer": "http://evil.example",
            "audience": "a",
            "resource_url": "r",
        }
    )
    with pytest.raises(ValueError, match="https"):
        bad.check_startup_invariants()
    ok = Settings(
        auth={"enabled": True, "issuer": "http://localhost:9", "audience": "a", "resource_url": "r"}
    )
    ok.check_startup_invariants()


def test_yaml_must_be_mapping(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("- a\n", encoding="utf-8")
    monkeypatch.setenv("MCP_HUB_CONFIG_FILE", str(cfg))
    with pytest.raises(ValueError, match="mapping"):
        Settings()


def test_redaction() -> None:
    out = redact({"Authorization": "Bearer abc.def.ghi", "note": "tok ghp_" + "b" * 30})
    assert out["Authorization"] == "[REDACTED]"
    assert "ghp_" not in out["note"]


def test_log_formatter_redacts() -> None:
    rec = logging.LogRecord("x", logging.INFO, "f", 1, "Bearer secret.value.here", None, None)
    rec.fields = {"password": "hunter2"}
    line = JsonFormatter().format(rec)
    assert "secret.value" not in line
    assert "hunter2" not in line


def test_log_formatter_exc_and_correlation() -> None:
    token = correlation_id.set("req-1")
    try:
        try:
            raise RuntimeError("boom Bearer abc.def.ghi")
        except RuntimeError:
            rec = logging.LogRecord("x", logging.ERROR, "f", 1, "m", None, sys.exc_info())
        data = json.loads(JsonFormatter().format(rec))
    finally:
        correlation_id.reset(token)
    assert data["correlation_id"] == "req-1"
    assert "abc.def.ghi" not in data["exc"]


def test_configure_logging_writes_stderr_only(capfd: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")
    log_fields(logging.getLogger("t"), logging.INFO, "hello", api_key="zzz", n=1)
    out, err = capfd.readouterr()
    assert out == ""
    assert "hello" in err
    assert "zzz" not in err


def test_redact_nested_sequences() -> None:
    assert redact([("a", {"token": "x"})]) == [["a", {"token": "[REDACTED]"}]]


def test_error_masking() -> None:
    assert to_public_message(AccessDenied("no"))[0] == "access_denied"
    code, msg = to_public_message(RuntimeError("db password=x"))
    assert code == "internal_error"
    assert "password" not in msg
