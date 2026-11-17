"""Configuração do servidor (sem segredos).

Ordem de precedência: valores padrão < config.json < variáveis de ambiente.
Segredos (Client ID, Client Secret, refresh token) NUNCA ficam aqui:
ficam no Windows Credential Manager (ver credentials.py).
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_TOKEN_URL = "https://usinalins-q.authentication.br10.hana.ondemand.com/oauth/token"
DEFAULT_AUTHORIZE_URL = "https://usinalins-q.authentication.br10.hana.ondemand.com/oauth/authorize"

AUTH_FLOWS = ("authorization_code", "client_credentials")
ALLOW_ALL = "*"


class ConfigError(ValueError):
    pass


def config_dir() -> Path:
    override = os.environ.get("SAC_MCP_CONFIG_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "sac-mcp"
    return Path.home() / ".config" / "sac-mcp"


def _https_url(name: str, value: str) -> str:
    value = value.strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ConfigError(f"{name} deve ser uma URL https válida (recebido: {value!r}).")
    return value


@dataclass
class Config:
    tenant_url: str = ""
    token_url: str = DEFAULT_TOKEN_URL
    authorize_url: str = DEFAULT_AUTHORIZE_URL
    auth_flow: str = "authorization_code"  # respeita o Data Access Control do usuário
    redirect_uri: str = "http://localhost:8765/callback"
    default_top: int = 1000
    max_top: int = 50000
    model_allowlist: list[str] = field(default_factory=list)  # vazia = nenhum modelo liberado
    export_dir: str = ""
    send_custom_auth_header: bool = True
    timeout_seconds: float = 120.0

    # ------------------------------------------------------------------ checks
    def validate(self, require_tenant: bool = True) -> "Config":
        if require_tenant:
            if not self.tenant_url:
                raise ConfigError(
                    "SAC_TENANT_URL não configurada. Informe a URL do tenant SAC "
                    "(ex.: https://<tenant>.<dc>.hcs.cloud.sap) no config.json ou na variável SAC_TENANT_URL."
                )
            self.tenant_url = _https_url("tenant_url", self.tenant_url)
        self.token_url = _https_url("token_url", self.token_url)
        self.authorize_url = _https_url("authorize_url", self.authorize_url)
        if self.auth_flow not in AUTH_FLOWS:
            raise ConfigError(f"auth_flow deve ser um de {AUTH_FLOWS}.")
        ru = urlparse(self.redirect_uri)
        if ru.scheme != "http" or ru.hostname not in ("localhost", "127.0.0.1") or not ru.port:
            raise ConfigError("redirect_uri deve ser http://localhost:<porta>/<caminho> (loopback).")
        if not (1 <= self.default_top <= self.max_top <= 50000):
            raise ConfigError("Exige 1 <= default_top <= max_top <= 50000.")
        self.model_allowlist = [m.strip() for m in self.model_allowlist if m and m.strip()]
        return self

    def is_model_allowed(self, provider_id: str) -> bool:
        if ALLOW_ALL in self.model_allowlist:
            return True
        return provider_id in self.model_allowlist

    def resolved_export_dir(self) -> Path:
        if self.export_dir:
            return Path(self.export_dir)
        if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
            return Path(os.environ["LOCALAPPDATA"]) / "sac-mcp" / "exports"
        return config_dir() / "exports"

    # ------------------------------------------------------------------ load
    @classmethod
    def load(cls, require_tenant: bool = True) -> "Config":
        cfg = cls()
        path = config_dir() / "config.json"
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            for key, value in data.items():
                if hasattr(cfg, key):
                    setattr(cfg, key, value)
        env = os.environ
        if env.get("SAC_TENANT_URL"):
            cfg.tenant_url = env["SAC_TENANT_URL"]
        if env.get("SAC_TOKEN_URL"):
            cfg.token_url = env["SAC_TOKEN_URL"]
        if env.get("SAC_AUTHORIZE_URL"):
            cfg.authorize_url = env["SAC_AUTHORIZE_URL"]
        if env.get("SAC_AUTH_FLOW"):
            cfg.auth_flow = env["SAC_AUTH_FLOW"]
        if env.get("SAC_REDIRECT_URI"):
            cfg.redirect_uri = env["SAC_REDIRECT_URI"]
        if "SAC_MODEL_ALLOWLIST" in env:
            cfg.model_allowlist = env["SAC_MODEL_ALLOWLIST"].split(",")
        if env.get("SAC_DEFAULT_TOP"):
            cfg.default_top = int(env["SAC_DEFAULT_TOP"])
        if env.get("SAC_MAX_TOP"):
            cfg.max_top = int(env["SAC_MAX_TOP"])
        if env.get("SAC_EXPORT_DIR"):
            cfg.export_dir = env["SAC_EXPORT_DIR"]
        return cfg.validate(require_tenant=require_tenant)
