"""Configuração (sem segredos): registro de conexões SAC.

Arquivo: %APPDATA%\\sac-mcp\\config.json
{
  "connections": {
    "<cliente>-<ambiente>": {
      "client": "...", "environment": "...",
      "tenant_url": "https://...", "token_url": "https://.../oauth/token",
      "authorize_url": "https://.../oauth/authorize", "auth_flow": "authorization_code",
      "redirect_uri": "http://localhost:8765/callback", "model_allowlist": [], ...
    }
  }
}
Segredos (Client ID/Secret, refresh token) ficam no Windows Credential Manager,
isolados por conexão (ver credentials.py).
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from urllib.parse import urlparse

AUTH_FLOWS = ("authorization_code", "client_credentials")
ALLOW_ALL = "*"
HARD_MAX_TOP = 50000

# Domínios SAP esperados. Domínios customizados só via CLI (allow_custom_domain).
TENANT_DOMAINS = (".sapanalytics.cloud", ".hcs.cloud.sap")
AUTH_DOMAINS = (".hana.ondemand.com",)

_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9_]{0,30})$")
_CONN_ID = re.compile(r"^[a-z0-9][a-z0-9_]{0,30}-[a-z0-9][a-z0-9_]{0,30}$")


class ConfigError(ValueError):
    pass


def config_dir() -> Path:
    override = os.environ.get("SAC_MCP_CONFIG_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "sac-mcp"
    return Path.home() / ".config" / "sac-mcp"


def config_path() -> Path:
    return config_dir() / "config.json"


def default_export_dir() -> Path:
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "sac-mcp" / "exports"
    return config_dir() / "exports"


def slug(value: str, what: str) -> str:
    s = re.sub(r"[^a-z0-9_]+", "_", (value or "").strip().lower()).strip("_")
    if not _SLUG.match(s):
        raise ConfigError(f"{what} inválido: {value!r} (use letras, números e _; até 31 caracteres).")
    return s


def make_connection_id(client: str, environment: str) -> str:
    return f"{slug(client, 'cliente')}-{slug(environment, 'ambiente')}"


def validate_connection_id(conn_id: str) -> str:
    if not isinstance(conn_id, str) or not _CONN_ID.match(conn_id):
        raise ConfigError(f"Identificador de conexão inválido: {conn_id!r} (formato <cliente>-<ambiente>).")
    return conn_id


def _https_url(name: str, value: str, domains: tuple[str, ...] | None, path_required: str | None = None) -> str:
    value = (value or "").strip().rstrip("/")
    p = urlparse(value)
    if p.scheme != "https" or not p.hostname:
        raise ConfigError(f"{name} deve ser uma URL https válida (recebido: {value!r}).")
    if p.username or p.password or p.port not in (None, 443):
        raise ConfigError(f"{name} não pode conter usuário, senha ou porta.")
    if domains is not None and not p.hostname.endswith(domains):
        raise ConfigError(
            f"{name}: host {p.hostname!r} fora dos domínios SAP esperados {domains}. "
            "Para domínio customizado, cadastre pela CLI com --allow-custom-domain."
        )
    if path_required is not None and p.path != path_required:
        raise ConfigError(f"{name} deve terminar em {path_required!r}.")
    if path_required is None and p.path not in ("", "/"):
        raise ConfigError(f"{name} deve conter apenas o host (sem caminho).")
    return value


@dataclass
class Config:
    """Configuração de UMA conexão SAC (um tenant)."""

    tenant_url: str = ""
    token_url: str = ""
    authorize_url: str = ""
    auth_flow: str = "authorization_code"  # respeita o Data Access Control do usuário
    redirect_uri: str = "http://localhost:8765/callback"
    default_top: int = 1000
    max_top: int = HARD_MAX_TOP
    model_allowlist: list[str] = field(default_factory=list)  # vazia = nenhum modelo liberado
    export_dir: str = ""
    send_custom_auth_header: bool = True
    timeout_seconds: float = 120.0
    client: str = ""
    environment: str = ""
    allow_custom_domain: bool = False

    @property
    def connection_id(self) -> str:
        return make_connection_id(self.client, self.environment) if self.client and self.environment else ""

    def validate(self, require_tenant: bool = True) -> "Config":
        tdom = None if self.allow_custom_domain else TENANT_DOMAINS
        adom = None if self.allow_custom_domain else AUTH_DOMAINS
        if require_tenant or self.tenant_url:
            if not self.tenant_url:
                raise ConfigError("tenant_url não configurada.")
            self.tenant_url = _https_url("tenant_url", self.tenant_url, tdom)
        if not self.token_url:
            raise ConfigError("token_url não configurada.")
        self.token_url = _https_url("token_url", self.token_url, adom, "/oauth/token")
        if not self.authorize_url:
            self.authorize_url = self.token_url[: -len("/oauth/token")] + "/oauth/authorize"
        self.authorize_url = _https_url("authorize_url", self.authorize_url, adom, "/oauth/authorize")
        if urlparse(self.token_url).hostname != urlparse(self.authorize_url).hostname:
            raise ConfigError("token_url e authorize_url devem estar no mesmo host de autenticação.")
        if self.auth_flow not in AUTH_FLOWS:
            raise ConfigError(f"auth_flow deve ser um de {AUTH_FLOWS}.")
        ru = urlparse(self.redirect_uri)
        if ru.scheme != "http" or ru.hostname not in ("localhost", "127.0.0.1") or not ru.port:
            raise ConfigError("redirect_uri deve ser http://localhost:<porta>/<caminho> (loopback).")
        if not (1 <= self.default_top <= self.max_top <= HARD_MAX_TOP):
            raise ConfigError(f"Exige 1 <= default_top <= max_top <= {HARD_MAX_TOP}.")
        self.model_allowlist = sorted({m.strip() for m in self.model_allowlist if m and m.strip()})
        if self.client or self.environment:
            make_connection_id(self.client, self.environment)
        return self

    def is_model_allowed(self, provider_id: str) -> bool:
        if ALLOW_ALL in self.model_allowlist:
            return True
        return provider_id in self.model_allowlist

    def resolved_export_dir(self) -> Path:
        base = Path(self.export_dir) if self.export_dir else default_export_dir()
        return base / self.connection_id if self.connection_id else base

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ConfigError(f"Campos desconhecidos na conexão: {sorted(unknown)}")
        return cls(**data)


class Registry:
    """Conexões persistidas em config.json (gravação atômica)."""

    def __init__(self, connections: dict[str, Config] | None = None, path: Path | None = None) -> None:
        self.connections: dict[str, Config] = connections or {}
        self.path = path or config_path()

    @classmethod
    def load(cls, path: Path | None = None) -> "Registry":
        path = path or config_path()
        if not path.exists():
            return cls({}, path)
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"config.json inválido: {exc}") from exc
        if "tenant_url" in data:
            raise ConfigError(
                "config.json no formato antigo (conexão única). Recadastre com: sac-mcp add"
            )
        conns: dict[str, Config] = {}
        for cid, raw in (data.get("connections") or {}).items():
            cfg = Config.from_dict(raw).validate()
            if cfg.connection_id != validate_connection_id(cid):
                raise ConfigError(f"Conexão {cid!r}: id não corresponde a cliente/ambiente.")
            conns[cid] = cfg
        return cls(conns, path)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"connections": {cid: c.to_dict() for cid, c in sorted(self.connections.items())}}
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".config-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, self.path)

    def get(self, conn_id: str) -> Config:
        validate_connection_id(conn_id)
        if conn_id not in self.connections:
            raise ConfigError(
                f"Conexão {conn_id!r} não cadastrada. Disponíveis: {sorted(self.connections) or 'nenhuma'}."
            )
        return self.connections[conn_id]

    def add(self, cfg: Config) -> str:
        cfg.validate()
        if not cfg.connection_id:
            raise ConfigError("Informe cliente e ambiente.")
        if cfg.connection_id in self.connections:
            raise ConfigError(f"Conexão {cfg.connection_id!r} já existe. Remova-a antes de recadastrar.")
        for other_id, other in self.connections.items():
            if other.tenant_url == cfg.tenant_url:
                raise ConfigError(f"O tenant {cfg.tenant_url} já está cadastrado como {other_id!r}.")
        self.connections[cfg.connection_id] = cfg
        return cfg.connection_id

    def remove(self, conn_id: str) -> Config:
        cfg = self.get(conn_id)
        del self.connections[conn_id]
        return cfg
