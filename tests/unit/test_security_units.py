"""JWKS cache, token verifier and key store edge cases (fail-closed behaviour)."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_hub.config import AuthSettings
from mcp_hub.errors import ConfigError, UpstreamError, ValidationFailed
from mcp_hub.security.apikeys import KeyStore, validate_scopes
from mcp_hub.security.auth import HubTokenVerifier
from mcp_hub.security.jwks import JwksCache

ISS = "https://idp.example.com"
RES = "https://mcp.example.com/mcp"


def _jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    d = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    d.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return d  # type: ignore[no-any-return]


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeResp:
    def __init__(self, status: int = 200, data: Any = None, content: bytes | None = None) -> None:
        self.status_code = status
        self._data = data
        self.content = content if content is not None else json.dumps(data).encode()

    def json(self) -> Any:
        return self._data


def _patch_http(monkeypatch: pytest.MonkeyPatch, routes: dict[str, Any]) -> list[str]:
    calls: list[str] = []

    class FakeClient:
        def __init__(self, **_: Any) -> None:
            pass

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *a: Any) -> None:
            return None

        def get(self, url: str, **_: Any) -> FakeResp:
            calls.append(url)
            r = routes[url]
            if isinstance(r, Exception):
                raise r
            return r  # type: ignore[no-any-return]

    monkeypatch.setattr(httpx, "Client", FakeClient)
    return calls


def test_jwks_discovery_and_caching(monkeypatch: pytest.MonkeyPatch, rsa_key: Any) -> None:
    calls = _patch_http(
        monkeypatch,
        {
            f"{ISS}/.well-known/openid-configuration": FakeResp(
                data={"issuer": ISS, "jwks_uri": f"{ISS}/keys"}
            ),
            f"{ISS}/keys": FakeResp(data={"keys": [_jwk(rsa_key, "k1")]}),
        },
    )
    cache = JwksCache(issuer=ISS + "/", jwks_url=None, ttl_seconds=600)
    assert cache.get_key("k1") is not None
    assert cache.get_key("k1") is not None  # served from cache
    assert len(calls) == 2  # discovery + keys, once
    with pytest.raises(UpstreamError):
        cache.get_key("other")  # unknown kid, inside the refresh window: no new fetch
    assert len(calls) == 2


def test_one_bad_jwk_does_not_discard_good_keys(
    monkeypatch: pytest.MonkeyPatch, rsa_key: Any
) -> None:
    _patch_http(
        monkeypatch,
        {
            f"{ISS}/k": FakeResp(
                data={"keys": [{"kty": "bogus", "kid": "x"}, _jwk(rsa_key, "good")]}
            )
        },
    )
    cache = JwksCache(issuer=ISS, jwks_url=f"{ISS}/k", ttl_seconds=60)
    assert cache.get_key("good") is not None


def test_jwks_refetch_when_stale_or_new_kid(monkeypatch: pytest.MonkeyPatch, rsa_key: Any) -> None:
    calls = _patch_http(
        monkeypatch, {f"{ISS}/k": FakeResp(data={"keys": [_jwk(rsa_key, "a"), _jwk(rsa_key, "b")]})}
    )
    cache = JwksCache(issuer=ISS, jwks_url=f"{ISS}/k", ttl_seconds=1, min_refresh_seconds=0)
    cache.get_key("a")
    cache.get_key("b")
    assert len(calls) == 1
    cache._fetched_at -= 10  # make stale
    cache.get_key("a")
    assert len(calls) == 2


@pytest.mark.parametrize(
    "routes",
    [
        {"https://i/.well-known/openid-configuration": FakeResp(status=500, data={})},
        {"https://i/.well-known/openid-configuration": FakeResp(data={"issuer": "https://evil"})},
        {"https://i/.well-known/openid-configuration": FakeResp(data={"issuer": "https://i"})},
        {"https://i/.well-known/openid-configuration": FakeResp(data=["x"])},
        {
            "https://i/.well-known/openid-configuration": FakeResp(
                data={"issuer": "https://i", "jwks_uri": "https://i/k"}
            ),
            "https://i/k": FakeResp(data={"keys": []}),
        },
        {
            "https://i/.well-known/openid-configuration": FakeResp(
                data={"issuer": "https://i", "jwks_uri": "https://i/k"}
            ),
            "https://i/k": FakeResp(data={"keys": [{"kty": "bogus", "kid": "x"}, "not-a-dict"]}),
        },
        {
            "https://i/.well-known/openid-configuration": FakeResp(
                data={"issuer": "https://i", "jwks_uri": "https://i/k"}
            ),
            "https://i/k": FakeResp(content=b"x" * 2_000_000, data={"keys": []}),
        },
        {"https://i/.well-known/openid-configuration": httpx.ConnectError("down")},
    ],
)
def test_jwks_failures_fail_closed(monkeypatch: pytest.MonkeyPatch, routes: dict[str, Any]) -> None:
    _patch_http(monkeypatch, routes)
    cache = JwksCache(issuer="https://i", jwks_url=None, ttl_seconds=60)
    with pytest.raises(UpstreamError):
        cache.get_key("k")


# ---- verifier -------------------------------------------------------------------------------


def _verifier(rsa_key: Any, tmp_path: Path, **cfg: Any) -> tuple[HubTokenVerifier, KeyStore]:
    settings = AuthSettings(
        enabled=True, issuer=ISS, audience=RES, resource_url=RES, jwks_url=f"{ISS}/k", **cfg
    )
    cache = JwksCache(issuer=ISS, jwks_url=f"{ISS}/k", ttl_seconds=60, min_refresh_seconds=0)
    store = KeyStore(tmp_path / "k.json")
    return HubTokenVerifier(settings, keystore=store, jwks=cache), store


def _mint(rsa_key: Any, **over: Any) -> str:
    claims = {"iss": ISS, "aud": RES, "sub": "u", "exp": int(time.time()) + 60, "scope": "a b"}
    claims.update(over)
    for k in [k for k, v in claims.items() if v is None]:
        del claims[k]
    return jwt.encode(claims, rsa_key, algorithm="RS256", headers={"kid": "k1"})


async def test_verifier_accepts_and_maps_claims(
    monkeypatch: pytest.MonkeyPatch, rsa_key: Any, tmp_path: Path
) -> None:
    _patch_http(monkeypatch, {f"{ISS}/k": FakeResp(data={"keys": [_jwk(rsa_key, "k1")]})})
    v, _ = _verifier(rsa_key, tmp_path)
    tok = await v.verify_token(_mint(rsa_key, azp="client-9"))
    assert tok is not None
    assert tok.client_id == "client-9" and tok.subject == "u"
    assert tok.scopes == ["a", "b"] and tok.resource == RES
    assert tok.token == ""  # the credential is never retained
    assert await v.verify_token(_mint(rsa_key, sub=None)) is None  # no subject/client at all
    assert await v.verify_token(_mint(rsa_key, sub=123)) is None  # non-string subject


async def test_verifier_rejects_without_trusted_keys(
    monkeypatch: pytest.MonkeyPatch, rsa_key: Any, tmp_path: Path
) -> None:
    _patch_http(monkeypatch, {f"{ISS}/k": httpx.ConnectError("idp down")})
    v, _ = _verifier(rsa_key, tmp_path)
    assert await v.verify_token(_mint(rsa_key)) is None  # JWKS outage: deny, never allow
    assert await v.verify_token("not.a-jwt") is None
    assert await v.verify_token("opaque-token-without-dots") is None
    header_bad = jwt.encode({"iss": ISS}, "s" * 40, algorithm="HS256", headers={"kid": "k1"})
    assert await v.verify_token(header_bad) is None  # HS256 never accepted


async def test_unexpected_exception_means_deny(
    monkeypatch: pytest.MonkeyPatch, rsa_key: Any, tmp_path: Path
) -> None:
    v, _ = _verifier(rsa_key, tmp_path)

    def explode(_: str) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(v, "_verify_jwt", explode)
    assert await v.verify_token("a.b.c") is None


async def test_verifier_without_keystore_or_idp(tmp_path: Path) -> None:
    only_idp = HubTokenVerifier(
        AuthSettings(enabled=True, issuer=ISS, audience=RES, resource_url=RES), keystore=None
    )
    assert await only_idp.verify_token("mcph_abcd1234_secret") is None  # api keys disabled
    only_keys = HubTokenVerifier(
        AuthSettings(enabled=True, resource_url=RES, api_key_file=tmp_path / "k"),
        keystore=KeyStore(tmp_path / "k"),
    )
    assert await only_keys.verify_token("a.b.c") is None  # no IdP configured: JWTs unsupported
    assert only_keys._jwks is None


async def test_algorithm_must_be_in_config(
    monkeypatch: pytest.MonkeyPatch, rsa_key: Any, tmp_path: Path
) -> None:
    _patch_http(monkeypatch, {f"{ISS}/k": FakeResp(data={"keys": [_jwk(rsa_key, "k1")]})})
    v, _ = _verifier(rsa_key, tmp_path, algorithms=["ES256"])
    assert await v.verify_token(_mint(rsa_key)) is None  # RS256 not enabled


# ---- key store ------------------------------------------------------------------------------


def test_scope_validation() -> None:
    assert validate_scopes(["b:x", "a:y", "a:y"]) == ["a:y", "b:x"]
    for bad in ([], [""], ["Admin"], ["a b"], ["a:b:c"], ["*:*"], ["sample"]):
        with pytest.raises(ValidationFailed):
            validate_scopes(bad)


def test_keystore_corrupt_and_missing(tmp_path: Path) -> None:
    store = KeyStore(tmp_path / "none.json")
    assert store.list() == []
    assert store.verify("mcph_aaaaaaaa_xxxx") == (None, "unknown_key")
    bad = tmp_path / "bad.json"
    bad.write_text('{"keys": [{"id": 1}]}', encoding="utf-8")
    with pytest.raises(ConfigError):
        KeyStore(bad).list()
    assert KeyStore(bad).verify("mcph_aaaaaaaa_xxxx") == (None, "store_error")


def test_keystore_malformed_tokens(tmp_path: Path) -> None:
    store = KeyStore(tmp_path / "k.json")
    for t in ("", "mcph", "mcph_", "mcph__x", "mcph_id_", "other_id_secret", "mcph_id"):
        assert store.verify(t) == (None, "malformed")


def test_keystore_reload_picks_up_external_edit(tmp_path: Path) -> None:
    path = tmp_path / "k.json"
    a = KeyStore(path)
    token, rec = a.create("x", ["a:b"])
    b = KeyStore(path)
    assert b.verify(token)[0] is not None
    a.revoke(rec.id)
    assert b.verify(token) == (None, "revoked")


def test_keystore_atomic_write_failure_leaves_no_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = KeyStore(tmp_path / "k.json")
    store.create("ok", ["a:b"])

    def boom(*_: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        store.create("fails", ["a:b"])
    assert not list(tmp_path.glob(".keys-*"))
    assert len(json.loads((tmp_path / "k.json").read_text())["keys"]) == 1
