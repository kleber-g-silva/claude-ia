import base64
import json
import threading
import urllib.request
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from sac_mcp import auth as auth_mod
from sac_mcp import credentials as cred
from sac_mcp.auth import AuthError, AuthRequired, TokenManager, safe_claims_summary
from tests.conftest import TOKEN_URL


def fake_jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@respx.mock
def test_client_credentials_caches_and_renews(config, store, http):
    config.auth_flow = "client_credentials"
    clock = Clock()
    route = respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "tok1", "expires_in": 3600}),
            httpx.Response(200, json={"access_token": "tok2", "expires_in": 3600}),
        ]
    )
    tm = TokenManager(config, store, http, clock=clock)
    assert tm.get_access_token() == "tok1"
    assert tm.get_access_token() == "tok1"  # cache
    assert route.call_count == 1
    req = route.calls[0].request
    assert b"grant_type=client_credentials" in req.content
    assert req.headers["Authorization"].startswith("Basic ")  # segredo não vai no corpo
    assert b"s3cr3t" not in req.content
    clock.t += 3600 - 30  # dentro da margem de 60s -> renova
    assert tm.get_access_token() == "tok2"
    assert cred.REFRESH_TOKEN not in store.data  # 2-legged não persiste nada


def test_authorization_code_without_session_requires_login(config, store, http):
    with pytest.raises(AuthRequired, match="sac-mcp login"):
        TokenManager(config, store, http).get_access_token()


def test_missing_client_credentials(config, http):
    from sac_mcp.credentials import MemoryStore

    config.auth_flow = "client_credentials"
    with pytest.raises(AuthRequired, match="set-credentials"):
        TokenManager(config, MemoryStore(), http).get_access_token()


@respx.mock
def test_refresh_token_rotation(config, store, http):
    store.set(cred.REFRESH_TOKEN, "rt-old")
    route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "at", "expires_in": 600, "refresh_token": "rt-new"})
    )
    assert TokenManager(config, store, http).get_access_token() == "at"
    assert parse_qs(route.calls[0].request.content.decode())["grant_type"] == ["refresh_token"]
    assert store.get(cred.REFRESH_TOKEN) == "rt-new"


@respx.mock
def test_revoked_refresh_token_is_removed(config, store, http):
    store.set(cred.REFRESH_TOKEN, "rt-old")
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(401, json={"error": "invalid_grant"}))
    with pytest.raises(AuthRequired, match="invalid_grant"):
        TokenManager(config, store, http).get_access_token()
    assert store.get(cred.REFRESH_TOKEN) is None


@respx.mock
def test_probe_client_credentials(config, store, http):
    respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(400, json={"error": "unauthorized_client", "error_description": "grant not allowed"}),
            httpx.Response(200, json={"access_token": fake_jwt({"grant_type": "client_credentials",
                                                                 "scope": ["uaa.resource"]})}),
        ]
    )
    tm = TokenManager(config, store, http)
    refused = tm.probe_client_credentials()
    assert refused["client_credentials"] == "recusado" and "unauthorized_client" in refused["detalhe"]
    accepted = tm.probe_client_credentials()
    assert accepted["client_credentials"] == "aceito"
    assert accepted["grant_type"] == "client_credentials" and accepted["has_user_identity"] is False
    assert tm.current_token() is None  # sonda não guarda token


def test_claims_summary_has_no_pii_or_token():
    tok = fake_jwt({"grant_type": "authorization_code", "user_name": "joao@empresa", "scope": "a b", "exp": 9})
    s = safe_claims_summary(tok)
    assert s == {"jwt": True, "grant_type": "authorization_code", "has_user_identity": True,
                 "scopes": ["a", "b"], "expires_at_epoch": 9}
    assert "joao" not in json.dumps(s)


@respx.mock
def test_interactive_login_pkce_end_to_end(config, store, http, monkeypatch):
    config.redirect_uri = "http://localhost:18765/callback"
    token_route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "at", "expires_in": 600, "refresh_token": "rt"})
    )
    respx.route(host="127.0.0.1").pass_through()
    seen = {}

    def fake_browser(url):
        q = parse_qs(urlparse(url).query)
        seen.update(q)
        cb = f"http://127.0.0.1:18765/callback?code=AUTHCODE&state={q['state'][0]}"
        threading.Timer(0.2, lambda: urllib.request.urlopen(cb, timeout=5).read()).start()
        return True

    monkeypatch.setattr(auth_mod.webbrowser, "open", fake_browser)
    TokenManager(config, store, http).interactive_login(timeout=10)
    assert seen["code_challenge_method"] == ["S256"] and seen["response_type"] == ["code"]
    body = parse_qs(token_route.calls[0].request.content.decode())
    assert body["grant_type"] == ["authorization_code"] and body["code"] == ["AUTHCODE"]
    assert len(body["code_verifier"][0]) >= 43
    assert store.get(cred.REFRESH_TOKEN) == "rt"


def test_interactive_login_rejects_bad_state(config, store, http, monkeypatch):
    config.redirect_uri = "http://localhost:18766/callback"

    def fake_browser(url):
        cb = "http://127.0.0.1:18766/callback?code=X&state=forged"
        threading.Timer(0.2, lambda: urllib.request.urlopen(cb, timeout=5).read()).start()
        return True

    monkeypatch.setattr(auth_mod.webbrowser, "open", fake_browser)
    with pytest.raises(AuthError, match="state"):
        TokenManager(config, store, http).interactive_login(timeout=10)
