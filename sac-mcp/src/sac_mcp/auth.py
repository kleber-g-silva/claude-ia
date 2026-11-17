"""OAuth 2.0 contra o XSUAA do tenant SAC.

Fluxos:
- authorization_code (padrão): 3-legged + PKCE. O token carrega a identidade do
  usuário, então o SAC aplica Data Access Control. Login interativo via
  `sac-mcp login`; o refresh token fica no Credential Manager e o servidor
  renova o access token automaticamente.
- client_credentials (opt-in): 2-legged, conexão técnica. NÃO aplica DAC por
  usuário. Sem refresh token: um novo token é solicitado ao expirar.

O access token nunca é persistido; fica apenas em memória.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import logging
import secrets
import threading
import time
import webbrowser
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from sac_mcp import credentials as cred
from sac_mcp.config import Config
from sac_mcp.credentials import SecretStore

log = logging.getLogger(__name__)

EXPIRY_SKEW_SECONDS = 60


class AuthError(RuntimeError):
    pass


class AuthRequired(AuthError):
    """Não há sessão válida; o usuário precisa executar `sac-mcp login`."""


@dataclass
class Token:
    access_token: str
    expires_at: float

    def valid(self, now: float) -> bool:
        return now < self.expires_at - EXPIRY_SKEW_SECONDS


def decode_jwt_claims(token: str) -> dict[str, Any]:
    """Decodifica o payload do JWT SEM validar assinatura. Uso apenas diagnóstico local."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:  # token opaco ou formato inesperado
        return {}


def safe_claims_summary(token: str) -> dict[str, Any]:
    """Resumo sem dados pessoais nem o token em si."""
    c = decode_jwt_claims(token)
    scopes = c.get("scope", [])
    if isinstance(scopes, str):
        scopes = scopes.split()
    return {
        "jwt": bool(c),
        "grant_type": c.get("grant_type"),
        "has_user_identity": bool(c.get("user_name") or c.get("user_id")),
        "scopes": sorted(scopes),
        "expires_at_epoch": c.get("exp"),
    }


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _oauth_error(resp: httpx.Response) -> str:
    try:
        body = resp.json()
        return f"HTTP {resp.status_code} {body.get('error', '')}: {body.get('error_description', '')}".strip()
    except Exception:
        return f"HTTP {resp.status_code}"


class TokenManager:
    def __init__(
        self,
        config: Config,
        store: SecretStore,
        http: httpx.Client,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.store = store
        self.http = http
        self.clock = clock
        self._token: Token | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------ helpers
    def _client_auth(self) -> tuple[str, str]:
        cid, secret = self.store.get(cred.CLIENT_ID), self.store.get(cred.CLIENT_SECRET)
        if not cid or not secret:
            raise AuthRequired("Client ID/Secret não encontrados no cofre. Execute: sac-mcp set-credentials")
        return cid, secret

    def _post_token(self, data: dict[str, str]) -> dict[str, Any]:
        resp = self.http.post(
            self.config.token_url,
            data=data,
            auth=self._client_auth(),
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            raise AuthError(f"Falha no token endpoint ({data.get('grant_type')}): {_oauth_error(resp)}")
        return resp.json()

    def _accept(self, body: dict[str, Any]) -> Token:
        if "access_token" not in body:
            raise AuthError("Resposta do token endpoint sem access_token.")
        expires_in = float(body.get("expires_in", 0) or 0)
        self._token = Token(body["access_token"], self.clock() + expires_in)
        new_refresh = body.get("refresh_token")
        if new_refresh and self.config.auth_flow == "authorization_code":
            self.store.set(cred.REFRESH_TOKEN, new_refresh)  # rotação
        return self._token

    # ------------------------------------------------------------ public
    def invalidate(self) -> None:
        self._token = None

    def get_access_token(self) -> str:
        with self._lock:
            if self._token and self._token.valid(self.clock()):
                return self._token.access_token
            if self.config.auth_flow == "client_credentials":
                return self._accept(self._post_token({"grant_type": "client_credentials"})).access_token
            refresh = self.store.get(cred.REFRESH_TOKEN)
            if not refresh:
                raise AuthRequired("Sessão SAC inexistente. Execute no terminal: sac-mcp login")
            try:
                body = self._post_token({"grant_type": "refresh_token", "refresh_token": refresh})
            except AuthError as exc:
                self.store.delete(cred.REFRESH_TOKEN)
                raise AuthRequired(f"Sessão SAC expirada ou revogada ({exc}). Execute: sac-mcp login") from exc
            return self._accept(body).access_token

    def current_token(self) -> str | None:
        return self._token.access_token if self._token else None

    # ------------------------------------------------------------ login (3-legged)
    def build_authorize_url(self, state: str, challenge: str) -> str:
        cid, _ = self._client_auth()
        query = {
            "response_type": "code",
            "client_id": cid,
            "redirect_uri": self.config.redirect_uri,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{self.config.authorize_url}?{urlencode(query)}"

    def exchange_code(self, code: str, verifier: str) -> Token:
        return self._accept(
            self._post_token(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.config.redirect_uri,
                    "code_verifier": verifier,
                }
            )
        )

    def interactive_login(self, open_browser: bool = True, timeout: float = 300) -> Token:
        if self.config.auth_flow != "authorization_code":
            raise AuthError("login interativo só se aplica a auth_flow=authorization_code.")
        verifier, challenge = _pkce_pair()
        state = secrets.token_urlsafe(24)
        url = self.build_authorize_url(state, challenge)
        result = _wait_for_callback(self.config.redirect_uri, url, open_browser, timeout)
        if result.get("error"):
            raise AuthError(f"Autorização negada: {result['error']} {result.get('error_description', '')}")
        if not secrets.compare_digest(result.get("state", ""), state):
            raise AuthError("Parâmetro state inválido no callback (possível CSRF). Login abortado.")
        if not result.get("code"):
            raise AuthError("Callback sem authorization code.")
        token = self.exchange_code(result["code"], verifier)
        if not self.store.get(cred.REFRESH_TOKEN):
            log.warning("O token endpoint não devolveu refresh token; será necessário novo login ao expirar.")
        return token

    # ------------------------------------------------------------ grant check
    def probe_client_credentials(self) -> dict[str, Any]:
        """Testa se o client aceita client_credentials. Não persiste o token."""
        resp = self.http.post(
            self.config.token_url,
            data={"grant_type": "client_credentials"},
            auth=self._client_auth(),
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 200:
            return {"client_credentials": "aceito", **safe_claims_summary(resp.json().get("access_token", ""))}
        return {"client_credentials": "recusado", "detalhe": _oauth_error(resp)}


def _wait_for_callback(redirect_uri: str, authorize_url: str, open_browser: bool, timeout: float) -> dict[str, str]:
    parsed = urlparse(redirect_uri)
    expected_path = parsed.path or "/"
    result: dict[str, str] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            req = urlparse(self.path)
            if req.path != expected_path:
                self.send_response(404)
                self.end_headers()
                return
            for k, v in parse_qs(req.query).items():
                result[k] = v[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write("<h3>Login SAC concluído. Pode fechar esta janela.</h3>".encode())

        def log_message(self, *args: Any) -> None:  # não logar a URL (contém o code)
            pass

    server = http.server.HTTPServer(("127.0.0.1", parsed.port), Handler)
    server.timeout = 1
    print("Abrindo o navegador para login no SAP Analytics Cloud...", flush=True)
    # A URL contém o Client ID (inerente ao OAuth): só é exibida se o navegador não abrir.
    if not (open_browser and webbrowser.open(authorize_url)):
        print("Navegador não abriu. Acesse manualmente a URL abaixo:\n" + authorize_url, flush=True)
    deadline = time.time() + timeout
    try:
        while not result and time.time() < deadline:
            server.handle_request()
    finally:
        server.server_close()
    if not result:
        raise AuthError("Tempo esgotado aguardando o callback do login.")
    return result
