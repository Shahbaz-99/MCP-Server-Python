"""HTTP authentication and authorization, negative cases first."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from tests.security.conftest import KID, RESOURCE, Http, Issuer


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _result_text(resp: Any) -> str:
    """Extract the JSON-RPC body whether the server answered with JSON or one SSE event."""
    text: str = resp.text
    for line in text.splitlines():
        if line.startswith("data:"):
            return line[5:].strip()
    return text


def _json(resp: Any) -> dict[str, Any]:
    return json.loads(_result_text(resp))  # type: ignore[no-any-return]


async def test_no_token_401_with_resource_metadata(http: Http) -> None:
    r = await http.rpc("tools/list")
    assert r.status_code == 401
    www = r.headers["www-authenticate"]
    assert www.startswith("Bearer")
    assert "resource_metadata=" in www
    assert "/.well-known/oauth-protected-resource" in www


async def test_protected_resource_metadata_is_served_without_auth(http: Http) -> None:
    r = await http.client.get("/.well-known/oauth-protected-resource/mcp")
    assert r.status_code == 200
    meta = r.json()
    assert meta["resource"].rstrip("/") == RESOURCE
    assert meta["authorization_servers"]


@pytest.mark.parametrize("bad", ["", "garbage", "a.b.c", "Bearer", "mcph_", "mcph_x_y", "mcph__"])
async def test_malformed_tokens_rejected(http: Http, bad: str) -> None:
    r = await http.client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream", "Authorization": f"Bearer {bad}"},
    )
    assert r.status_code == 401


async def test_valid_jwt_lists_tools(http: Http, issuer: Issuer) -> None:
    r = await http.rpc("tools/list", token=issuer.mint())
    assert r.status_code == 200, r.text
    names = {t["name"] for t in _json(r)["result"]["tools"]}
    assert {"echo", "current_time"} <= names


@pytest.mark.parametrize(
    "case",
    [
        "wrong_audience",
        "wrong_issuer",
        "expired",
        "signed_by_other_key",
        "missing_exp",
        "missing_aud",
        "missing_iss",
        "unknown_kid",
        "no_kid",
        "alg_none",
        "hs256_confusion",
    ],
)
async def test_invalid_jwts_rejected(
    http: Http, issuer: Issuer, other_key: RSAPrivateKey, case: str
) -> None:
    pub_pem = issuer.key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    payload = {"iss": issuer.url, "aud": RESOURCE, "sub": "x", "exp": 9999999999}

    def hand_made(alg: str, secret: bytes | None) -> str:
        """Build a token by hand: PyJWT refuses to sign HS256 with a PEM key, attackers do not."""
        head = _b64(json.dumps({"alg": alg, "kid": KID, "typ": "JWT"}).encode())
        body = _b64(json.dumps(payload).encode())
        signing_input = f"{head}.{body}".encode()
        sig = b"" if secret is None else hmac.new(secret, signing_input, hashlib.sha256).digest()
        return f"{head}.{body}.{_b64(sig)}"

    makers: dict[str, Callable[[], str]] = {
        "wrong_audience": lambda: issuer.mint(aud="https://other.example/mcp"),
        "wrong_issuer": lambda: issuer.mint(iss="https://evil.example"),
        "expired": lambda: issuer.mint(exp_delta=-3600),
        "signed_by_other_key": lambda: issuer.mint(key=other_key),
        "missing_exp": lambda: issuer.mint(drop=("exp",)),
        "missing_aud": lambda: issuer.mint(drop=("aud",)),
        "missing_iss": lambda: issuer.mint(drop=("iss",)),
        "unknown_kid": lambda: issuer.mint(kid="nope"),
        "no_kid": lambda: issuer.mint(kid=None),
        "alg_none": lambda: hand_made("none", None),
        # classic algorithm confusion: HS256 signed with the PUBLIC key as the HMAC secret
        "hs256_confusion": lambda: hand_made("HS256", pub_pem),
    }
    r = await http.rpc("tools/list", token=makers[case]())
    assert r.status_code == 401, (case, r.text)


async def test_unknown_kid_does_not_hammer_jwks_endpoint(http: Http, issuer: Issuer) -> None:
    before = len(issuer.hits)
    for i in range(25):
        r = await http.rpc("tools/list", token=issuer.mint(kid=f"random-{i}"))
        assert r.status_code == 401
    assert len(issuer.hits) - before <= 2  # refresh is rate limited, not once per request


async def test_missing_scope_denied_at_tool(http: Http, issuer: Issuer) -> None:
    r = await http.call_tool("echo", {"message": "x"}, issuer.mint(scope="other:thing"))
    assert r.status_code == 200
    result = _json(r)["result"]
    assert result["isError"] is True
    assert "scope" in result["content"][0]["text"]


async def test_scope_allows_tool(http: Http, issuer: Issuer) -> None:
    r = await http.call_tool("echo", {"message": "hello"}, issuer.mint(scope="sample:read"))
    result = _json(r)["result"]
    assert result["isError"] is False
    assert result["content"][0]["text"] == "hello"


async def test_scp_list_claim_supported(http: Http, issuer: Issuer) -> None:
    tok = issuer.mint(scope="", scp=["sample:read"])
    r = await http.call_tool("echo", {"message": "hi"}, tok)
    assert _json(r)["result"]["isError"] is False


# ---- API keys -------------------------------------------------------------------------------


async def test_api_key_works_and_is_scoped(http: Http) -> None:
    key, _ = http.keys.create("ci", ["sample:read"])
    r = await http.call_tool("echo", {"message": "k"}, key)
    assert _json(r)["result"]["isError"] is False
    narrow, _ = http.keys.create("none", ["github:read"])
    r = await http.call_tool("echo", {"message": "k"}, narrow)
    assert _json(r)["result"]["isError"] is True


async def test_api_key_revocation_is_immediate(http: Http) -> None:
    key, rec = http.keys.create("temp", ["sample:read"])
    assert (await http.rpc("tools/list", token=key)).status_code == 200
    assert http.keys.revoke(rec.id)
    assert (await http.rpc("tools/list", token=key)).status_code == 401


async def test_api_key_expired_wrong_secret_unknown(http: Http) -> None:
    key, _rec = http.keys.create("short", ["sample:read"], expires_days=0.00001)
    import asyncio

    await asyncio.sleep(1.2)
    assert (await http.rpc("tools/list", token=key)).status_code == 401
    good, _rec2 = http.keys.create("ok", ["sample:read"])
    tampered = good[:-3] + ("AAA" if not good.endswith("AAA") else "BBB")
    assert (await http.rpc("tools/list", token=tampered)).status_code == 401
    assert (await http.rpc("tools/list", token=f"mcph_deadbeef_{'x' * 40}")).status_code == 401


async def test_corrupt_key_file_fails_closed(http: Http, key_file: Any) -> None:
    key, _ = http.keys.create("a", ["sample:read"])
    assert (await http.rpc("tools/list", token=key)).status_code == 200
    key_file.write_text("{not json", encoding="utf-8")
    assert (await http.rpc("tools/list", token=key)).status_code == 401


async def test_tokens_never_logged(
    http: Http, issuer: Issuer, caplog: pytest.LogCaptureFixture
) -> None:
    tok = issuer.mint()
    key, _ = http.keys.create("l", ["sample:read"])
    with caplog.at_level(logging.DEBUG):
        await http.call_tool("echo", {"message": "x"}, tok)
        await http.call_tool("echo", {"message": "x"}, key)
        await http.rpc("tools/list", token=tok + "tampered")
    blob = caplog.text
    assert tok not in blob
    assert key not in blob
    assert key.split("_", 2)[2] not in blob


async def test_audit_record_written(
    http: Http, issuer: Issuer, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="mcp_hub.audit"):
        await http.call_tool("echo", {"message": "audit-me"}, issuer.mint())
    rec = next(r for r in caplog.records if r.name == "mcp_hub.audit")
    fields = rec.fields  # type: ignore[attr-defined]
    assert fields["identity"] == "user-1" and fields["tool"] == "echo"
    assert "audit-me" not in caplog.text  # only the argument hash is recorded
