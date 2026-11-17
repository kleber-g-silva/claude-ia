"""Servidor MCP (stdio) — SAP Analytics Cloud Data Export Service, somente leitura."""
from __future__ import annotations

import csv
import io
import logging
import re
from datetime import datetime
from typing import Any, Literal

import httpx
from keyring.errors import KeyringError
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from sac_mcp import __version__
from sac_mcp.auth import AuthError, TokenManager, safe_claims_summary
from sac_mcp.config import Config, ConfigError
from sac_mcp.credentials import KeyringStore, SecretStore
from sac_mcp.redaction import redact
from sac_mcp.sac_client import SacClient, SacError

log = logging.getLogger(__name__)

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True)

mcp = MCPServer(
    name="sac",
    version=__version__,
    instructions=(
        "Acesso SOMENTE LEITURA ao SAP Analytics Cloud via Data Export Service. "
        "Fluxo: sac_list_models -> sac_get_model_metadata -> sac_get_fact_data/sac_get_master_data. "
        "Use $select e $filter para reduzir volume; para extrações grandes prefira output='file'."
    ),
)


class _Runtime:
    """Inicialização preguiçosa: o servidor sobe mesmo sem config para listar ferramentas."""

    def __init__(self) -> None:
        self.config: Config | None = None
        self.tokens: TokenManager | None = None
        self.client: SacClient | None = None
        self.store: SecretStore | None = None

    def setup(self, config: Config, store: SecretStore, http: httpx.Client) -> None:
        self.config, self.store = config, store
        self.tokens = TokenManager(config, store, http)
        self.client = SacClient(config, self.tokens, http)

    def ensure(self) -> SacClient:
        if self.client is None:
            try:
                cfg = Config.load()
            except ConfigError as exc:
                raise ToolError(str(exc)) from exc
            self.setup(cfg, KeyringStore(), httpx.Client(timeout=cfg.timeout_seconds))
        assert self.client is not None
        return self.client


runtime = _Runtime()


def _call(fn, *args, **kwargs):
    client = runtime.ensure()
    try:
        return fn(client, *args, **kwargs)
    except (SacError, AuthError) as exc:
        raise ToolError(redact(str(exc))) from exc
    except httpx.HTTPError as exc:
        raise ToolError(f"Erro de rede ao acessar o SAC: {type(exc).__name__}") from exc
    except KeyringError as exc:
        raise ToolError(f"Cofre de credenciais indisponível: {type(exc).__name__}") from exc


def _clamp_top(top: int | None) -> int:
    cfg = runtime.config
    assert cfg is not None
    if top is None:
        return cfg.default_top
    if top < 1:
        raise ToolError("top deve ser >= 1.")
    if top > cfg.max_top:
        raise ToolError(f"top={top} excede o máximo permitido por chamada ({cfg.max_top}).")
    return top


def _to_csv(rows: list[dict[str, Any]]) -> tuple[str, list[str]]:
    cols: list[str] = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue(), cols


def _extract(provider_id: str, entity_set: str, namespace: str, select: list[str] | None,
             filter: str | None, orderby: str | None, top: int | None,
             output: Literal["inline", "file"]) -> dict[str, Any]:
    client = runtime.ensure()
    limit = _clamp_top(top)
    rows = _call(lambda c: list(c.iter_rows(namespace, provider_id, entity_set, top=limit,
                                              select=select, filter_=filter, orderby=orderby)))
    text, cols = _to_csv(rows)
    result: dict[str, Any] = {
        "provider_id": provider_id,
        "entity_set": entity_set,
        "rows": len(rows),
        "limit": limit,
        "truncated": len(rows) >= limit,
        "columns": cols,
    }
    if output == "file":
        assert client.config is not None
        out_dir = client.config.resolved_export_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{provider_id}_{entity_set}")
        path = out_dir / f"{safe}_{datetime.now():%Y%m%d_%H%M%S}.csv"
        path.write_text(text, encoding="utf-8-sig")
        result["file"] = str(path)
    else:
        result["csv"] = text
    return result


# ---------------------------------------------------------------- tools
@mcp.tool(annotations=READ_ONLY)
def sac_auth_status() -> dict[str, Any]:
    """Status da autenticação: fluxo OAuth, grant e scopes do token atual (o token não é exibido)."""
    client = runtime.ensure()
    assert runtime.tokens is not None and runtime.config is not None
    try:
        token = runtime.tokens.get_access_token()
    except KeyringError as exc:
        return {"authenticated": False, "auth_flow": runtime.config.auth_flow,
                "detail": f"Cofre de credenciais indisponível: {type(exc).__name__}"}
    except AuthError as exc:
        return {"authenticated": False, "auth_flow": runtime.config.auth_flow, "detail": redact(str(exc))}
    return {
        "authenticated": True,
        "auth_flow": runtime.config.auth_flow,
        "respects_user_data_access_control": runtime.config.auth_flow == "authorization_code",
        "tenant": client.config.tenant_url,
        "model_allowlist": runtime.config.model_allowlist,
        **safe_claims_summary(token),
    }


@mcp.tool(annotations=READ_ONLY)
def sac_list_namespaces() -> list[dict[str, Any]]:
    """Lista os namespaces do Data Export Service (ex.: 'sac')."""
    return _call(lambda c: c.list_namespaces())


@mcp.tool(annotations=READ_ONLY)
def sac_list_models(namespace: str = "sac", name_contains: str | None = None) -> dict[str, Any]:
    """Lista os modelos (providers) visíveis ao usuário/cliente, indicando se estão na allowlist."""
    providers = _call(lambda c: c.list_providers(namespace))
    if name_contains:
        needle = name_contains.lower()
        providers = [p for p in providers if needle in str(p.get("ProviderName", "")).lower()
                     or needle in str(p.get("ProviderID", "")).lower()]
    cfg = runtime.config
    assert cfg is not None
    for p in providers:
        pid = p.get("ProviderID")
        p["allowed_by_allowlist"] = bool(pid) and cfg.is_model_allowed(str(pid))
    return {"count": len(providers), "models": providers}


@mcp.tool(annotations=READ_ONLY)
def sac_get_model_metadata(provider_id: str, namespace: str = "sac") -> dict[str, Any]:
    """Entity sets (FactData, master data) e colunas de um modelo, a partir do $metadata OData."""
    meta = _call(lambda c: c.metadata(namespace, provider_id))
    meta["available_entity_sets"] = _call(lambda c: c.entity_sets(namespace, provider_id))
    return meta


@mcp.tool(annotations=READ_ONLY)
def sac_get_fact_data(provider_id: str, namespace: str = "sac", select: list[str] | None = None,
                      filter: str | None = None, orderby: str | None = None, top: int | None = None,
                      output: Literal["inline", "file"] = "inline") -> dict[str, Any]:
    """Extrai fact data (GET .../FactData). Padrão 1.000 linhas, máximo 50.000 por chamada.
    `filter` usa sintaxe OData $filter. output='file' grava CSV local e não devolve os dados ao chat."""
    return _extract(provider_id, "FactData", namespace, select, filter, orderby, top, output)


@mcp.tool(annotations=READ_ONLY)
def sac_get_master_data(provider_id: str, entity_set: str, namespace: str = "sac",
                        select: list[str] | None = None, filter: str | None = None,
                        orderby: str | None = None, top: int | None = None,
                        output: Literal["inline", "file"] = "inline") -> dict[str, Any]:
    """Lê um entity set de master data do modelo. `entity_set` deve existir em sac_get_model_metadata."""
    if entity_set == "FactData":
        raise ToolError("Use sac_get_fact_data para FactData.")
    return _extract(provider_id, entity_set, namespace, select, filter, orderby, top, output)


def run() -> None:
    mcp.run(transport="stdio")
