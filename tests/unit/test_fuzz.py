"""Property-based tests: hostile input must end in a HubError or a safe result, never a crash."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any

import pytest
import sqlglot
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlglot import exp

from mcp_hub.config import AuthSettings
from mcp_hub.errors import HubError
from mcp_hub.logging import redact_text
from mcp_hub.plugins.rest_connector import _render_path
from mcp_hub.plugins.rest_connector.ssrf import check_url, is_public
from mcp_hub.plugins.sample.paths import resolve_safe, validate_relative
from mcp_hub.plugins.sql.guard import _FORBIDDEN_NODES, validate_select
from mcp_hub.security.apikeys import KeyStore
from mcp_hub.security.auth import HubTokenVerifier

FAST = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])

# Text biased towards the characters that matter for path, SQL and URL tricks.
NASTY = st.text(
    alphabet=st.sampled_from(list("./\\:;'\"()-*%?#&=$ \t\n\x00aAzZ09_~`@!,|{}<>")), max_size=60
)
ANY_TEXT = st.one_of(NASTY, st.text(max_size=80))


# ---- filesystem sandbox ---------------------------------------------------------------------


@pytest.fixture(scope="module")
def sandbox() -> Any:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "root"
        (root / "sub").mkdir(parents=True)
        (root / "sub" / "f.txt").write_text("x")
        (Path(tmp) / "outside.txt").write_text("secret")
        yield root


@FAST
@given(rel=ANY_TEXT)
def test_path_guard_never_escapes_root(sandbox: Path, rel: str) -> None:
    try:
        result = resolve_safe(sandbox, rel)
    except HubError:
        return  # rejected: fine
    assert result.is_relative_to(sandbox.resolve())


@FAST
@given(rel=ANY_TEXT)
def test_path_validation_only_raises_hub_errors(rel: str) -> None:
    try:
        parts = validate_relative(rel)
    except HubError:
        return
    assert ".." not in parts and all(":" not in p and "\x00" not in p for p in parts)


# ---- SQL guard ------------------------------------------------------------------------------

SQL_FRAGMENTS = st.sampled_from(
    [
        "SELECT",
        "FROM",
        "WHERE",
        "t",
        "a",
        "1",
        ";",
        "--",
        "/*",
        "*/",
        "DROP",
        "TABLE",
        "DELETE",
        "INSERT",
        "INTO",
        "UPDATE",
        "SET",
        "WITH",
        "AS",
        "(",
        ")",
        "UNION",
        "ALL",
        "PRAGMA",
        "ATTACH",
        "DATABASE",
        "pg_sleep(1)",
        "nextval('s')",
        "load_extension('x')",
        "FOR UPDATE",
        "RETURNING",
        "COPY",
        "CREATE",
        "VACUUM",
        "EXPLAIN",
        "ANALYZE",
        "'",
        '"',
        ",",
        "*",
        "=",
        "?",
        "$1",
    ]
)
SQL_TEXT = st.lists(SQL_FRAGMENTS, min_size=0, max_size=14).map(" ".join)


@FAST
@given(sql=st.one_of(SQL_TEXT, ANY_TEXT), dialect=st.sampled_from(["sqlite", "postgres"]))
def test_sql_guard_output_is_always_one_clean_select(sql: str, dialect: str) -> None:
    try:
        out = validate_select(sql, dialect)
    except HubError:
        return
    trees = [t for t in sqlglot.parse(out, read=dialect) if t is not None]
    assert len(trees) == 1
    root = trees[0]
    assert isinstance(root, exp.Select | exp.SetOperation)
    assert not any(isinstance(n, _FORBIDDEN_NODES) for n in root.walk())
    assert ";" not in out.replace("';'", "")  # no statement separator survives (outside literals)


# ---- URL / SSRF -----------------------------------------------------------------------------


@FAST
@given(url=ANY_TEXT)
def test_url_check_only_raises_hub_errors(url: str) -> None:
    try:
        parts = check_url(url, allowed_hosts=["api.example.com"], allow_http=False)
    except HubError:
        return
    assert parts.hostname == "api.example.com" and parts.scheme == "https"
    assert parts.username is None and parts.password is None


@FAST
@given(ip=st.ip_addresses(v=4) | st.ip_addresses(v=6))
def test_is_public_agrees_with_stdlib_for_every_address(ip: Any) -> None:
    result = is_public(ip)
    if result:
        assert ip.is_global and not ip.is_multicast
        assert not ip.is_private and not ip.is_loopback and not ip.is_link_local
        assert not ip.is_reserved and not ip.is_unspecified


@FAST
@given(value=ANY_TEXT)
def test_path_template_values_never_add_segments_or_queries(value: str) -> None:
    try:
        out = _render_path("https://api.example.com/users/{id}/profile", {"id": value})
    except HubError:
        return
    assert out.count("/") == 5  # scheme '//', host, users, <id>, profile: nothing added
    assert "?" not in out and "#" not in out and " " not in out


# ---- auth: arbitrary tokens never crash and never authenticate -------------------------------


@pytest.fixture(scope="module")
def verifier() -> Any:
    tmp = tempfile.mkdtemp()
    store = KeyStore(Path(tmp) / "k.json")
    cfg = AuthSettings(
        enabled=True,
        issuer="https://idp.example.com",
        audience="https://mcp.example.com/mcp",
        resource_url="https://mcp.example.com/mcp",
        jwks_url="https://idp.example.com/jwks",
        api_key_file=Path(tmp) / "k.json",
    )
    return HubTokenVerifier(cfg, keystore=store)


@FAST
@given(token=ANY_TEXT)
def test_random_tokens_are_rejected_without_exceptions(verifier: Any, token: str) -> None:
    assert asyncio.run(verifier.verify_token(token)) is None


@FAST
@given(
    parts=st.lists(
        st.text(alphabet=st.characters(codec="ascii", exclude_characters="\x00"), max_size=30),
        min_size=2,
        max_size=4,
    )
)
def test_random_api_key_shaped_tokens_are_rejected(verifier: Any, parts: list[str]) -> None:
    assert asyncio.run(verifier.verify_token("mcph_" + "_".join(parts))) is None


# ---- log redaction --------------------------------------------------------------------------

SECRETS = st.one_of(
    st.from_regex(r"ghp_[A-Za-z0-9]{36}", fullmatch=True),
    st.from_regex(r"github_pat_[A-Za-z0-9_]{40,60}", fullmatch=True),
    st.from_regex(
        r"eyJ[A-Za-z0-9_-]{10,40}\.[A-Za-z0-9_-]{10,40}\.[A-Za-z0-9_-]{10,40}", fullmatch=True
    ),
    st.from_regex(r"postgres://[a-z]{3,8}:[A-Za-z0-9]{6,12}@db\.example/app", fullmatch=True),
)


@FAST
@given(secret=SECRETS, before=st.text(max_size=20), after=st.text(max_size=20))
def test_redaction_removes_known_secret_shapes_wherever_they_appear(
    secret: str, before: str, after: str
) -> None:
    text = f"{before} {secret} {after}"
    out = redact_text(text)
    if secret.startswith("postgres://"):
        assert secret.split(":")[2].split("@")[0] not in out  # password part gone
    else:
        assert secret not in out
    assert "[REDACTED]" in out
