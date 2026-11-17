"""Servidor MCP (stdio) — SAP Analytics Cloud Data Export Service, somente leitura, multi-tenant.

Proteção contra acesso ao ambiente errado ("duas chaves"):
  1. toda consulta/exportação exige o parâmetro `connection` explícito;
  2. a conexão precisa ter sido selecionada nesta sessão com sac_select_connection.
Se os dois não coincidirem, a chamada é recusada antes de qualquer acesso ao SAC.
A seleção vale só para o processo atual (não é persistida).
"""
from __future__ import annotations

import csv
import io
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Literal

import httpx
from keyring.errors import KeyringError
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from sac_mcp import __version__
from sac_mcp.auth import AuthError, TokenManager, safe_claims_summary
from sac_mcp.config import ALLOW_ALL, Config, ConfigError, Registry
from sac_mcp.credentials import KeyringStore, SecretStore
from sac_mcp.redaction import redact
from sac_mcp.sac_client import SacClient, SacError

log = logging.getLogger(__name__)

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True)
LOCAL_STATE = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
LOCAL_DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False,
                                    open_world_hint=False)

mcp = MCPServer(
    name="sac",
    version=__version__,
    instructions=(
        "Acesso SOMENTE LEITURA a um ou mais tenants SAP Analytics Cloud (Data Export Service). "
        "Cada conexão é identificada por '<cliente>-<ambiente>'. Antes de consultar: sac_list_connections -> "
        "sac_select_connection(connection). TODA consulta exige o parâmetro `connection`, que deve ser igual "
        "à conexão selecionada. Nunca troque de conexão sem o pedido explícito do usuário. "
        "Fluxo: sac_list_models -> sac_get_model_metadata -> sac_get_fact_data/sac_get_master_data. "
        "Credenciais NUNCA passam por este chat: são gravadas pelo usuário no terminal "
        "(sac-mcp set-credentials --connection <id>)."
    ),
)


@dataclass
class _Session:
    config: Config
    tokens: TokenManager
    client: SacClient


class _Runtime:
    def __init__(self) -> None:
        self.registry_loader: Callable[[], Registry] = Registry.load
        self.store_factory: Callable[[str], SecretStore] = KeyringStore.for_connection
        self._http: httpx.Client | None = None
        self.selected: str | None = None
        self.sessions: dict[str, _Session] = {}

    def configure(self, registry_loader: Callable[[], Registry], store_factory: Callable[[str], SecretStore],
                  http: httpx.Client) -> None:
        self.__init__()
        self.registry_loader, self.store_factory, self._http = registry_loader, store_factory, http

    @property
    def http(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(timeout=120.0)
        return self._http

    def registry(self) -> Registry:
        try:
            return self.registry_loader()  # relido a cada chamada: reflete alterações feitas pela CLI
        except ConfigError as exc:
            raise ToolError(str(exc)) from exc

    def config_for(self, connection: str) -> Config:
        try:
            return self.registry().get(connection)
        except ConfigError as exc:
            raise ToolError(str(exc)) from exc

    def session(self, connection: str, require_selected: bool = True) -> _Session:
        cfg = self.config_for(connection)
        if require_selected and self.selected != connection:
            raise ToolError(
                f"Conexão {connection!r} não está selecionada (selecionada: {self.selected or 'nenhuma'}). "
                f"Confirme com o usuário e chame sac_select_connection('{connection}')."
            )
        cached = self.sessions.get(connection)
        if cached and cached.config == cfg:
            return cached
        tokens = TokenManager(cfg, self.store_factory(connection), self.http)
        sess = _Session(cfg, tokens, SacClient(cfg, tokens, self.http))
        self.sessions[connection] = sess
        return sess

    def drop(self, connection: str) -> None:
        self.sessions.pop(connection, None)
        if self.selected == connection:
            self.selected = None


runtime = _Runtime()


def _guard(fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except (SacError, AuthError, ConfigError) as exc:
        raise ToolError(redact(str(exc))) from exc
    except httpx.HTTPError as exc:
        raise ToolError(f"Erro de rede ao acessar o SAC: {type(exc).__name__}") from exc
    except KeyringError as exc:
        raise ToolError(f"Cofre de credenciais indisponível: {type(exc).__name__}") from exc


def _clamp_top(cfg: Config, top: int | None) -> int:
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


def _extract(connection: str, provider_id: str, entity_set: str, namespace: str, select: list[str] | None,
             filter: str | None, orderby: str | None, top: int | None,
             output: Literal["inline", "file"]) -> dict[str, Any]:
    sess = runtime.session(connection)
    limit = _clamp_top(sess.config, top)
    rows = _guard(lambda: list(sess.client.iter_rows(namespace, provider_id, entity_set, top=limit,
                                                     select=select, filter_=filter, orderby=orderby)))
    text, cols = _to_csv(rows)
    result: dict[str, Any] = {
        "connection": connection,
        "provider_id": provider_id,
        "entity_set": entity_set,
        "rows": len(rows),
        "limit": limit,
        "truncated": len(rows) >= limit,
        "columns": cols,
    }
    if output == "file":
        out_dir = sess.config.resolved_export_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{connection}_{provider_id}_{entity_set}")
        path = out_dir / f"{safe}_{datetime.now():%Y%m%d_%H%M%S}.csv"
        path.write_text(text, encoding="utf-8-sig")
        result["file"] = str(path)
    else:
        result["csv"] = text
    return result


def _connection_summary(cid: str, cfg: Config) -> dict[str, Any]:
    try:
        creds: bool | str = runtime.store_factory(cid).has_credentials()
    except KeyringError:
        creds = "cofre indisponível"
    return {
        "connection": cid,
        "client": cfg.client,
        "environment": cfg.environment,
        "tenant_url": cfg.tenant_url,
        "auth_flow": cfg.auth_flow,
        "respects_user_data_access_control": cfg.auth_flow == "authorization_code",
        "model_allowlist": cfg.model_allowlist,
        "credentials_stored": creds,
        "selected": runtime.selected == cid,
    }


# ---------------------------------------------------------------- gestão de conexões
@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True,
                                      open_world_hint=False))
def sac_list_connections() -> dict[str, Any]:
    """Lista as conexões SAC cadastradas (sem segredos) e qual está selecionada nesta sessão."""
    reg = runtime.registry()
    if runtime.selected and runtime.selected not in reg.connections:
        runtime.drop(runtime.selected)
    return {
        "selected": runtime.selected,
        "connections": [_connection_summary(cid, cfg) for cid, cfg in sorted(reg.connections.items())],
    }


@mcp.tool(annotations=LOCAL_STATE)
def sac_add_connection(client: str, environment: str, tenant_url: str, token_url: str,
                       authorize_url: str | None = None,
                       auth_flow: Literal["authorization_code", "client_credentials"] = "authorization_code",
                       redirect_uri: str = "http://localhost:8765/callback",
                       model_allowlist: list[str] | None = None) -> dict[str, Any]:
    """Cadastra uma conexão SAC (somente configuração; NÃO recebe credenciais).
    O id resultante é '<cliente>-<ambiente>'. Hosts precisam ser domínios SAP. A allowlist não aceita '*'
    por esta ferramenta. Depois, o usuário grava as credenciais no terminal com
    `sac-mcp set-credentials --connection <id>`."""
    allow = model_allowlist or []
    if ALLOW_ALL in allow:
        raise ToolError("'*' (todos os modelos) só pode ser definido pela CLI: sac-mcp allowlist --connection <id> --all")
    cfg = Config(client=client, environment=environment, tenant_url=tenant_url, token_url=token_url,
                 authorize_url=authorize_url or "", auth_flow=auth_flow, redirect_uri=redirect_uri,
                 model_allowlist=list(allow), allow_custom_domain=False)
    reg = runtime.registry()
    cid = _guard(lambda: reg.add(cfg))
    reg.save()
    return {
        **_connection_summary(cid, reg.connections[cid]),
        "next_steps": [
            f"No terminal (fora do chat): sac-mcp set-credentials --connection {cid}",
            f"sac-mcp check-grant --connection {cid}  (confirma o grant; chamada real)",
            *([f"sac-mcp login --connection {cid}"] if auth_flow == "authorization_code" else []),
            f"Depois: sac_select_connection('{cid}')",
        ],
    }


@mcp.tool(annotations=LOCAL_STATE)
def sac_select_connection(connection: str) -> dict[str, Any]:
    """Seleciona a conexão desta sessão. Consultas só são aceitas para a conexão selecionada
    e com o mesmo `connection` informado explicitamente."""
    cfg = runtime.config_for(connection)
    runtime.selected = connection
    summary = _connection_summary(connection, cfg)
    if summary["credentials_stored"] is not True:
        summary["warning"] = f"Sem credenciais. No terminal: sac-mcp set-credentials --connection {connection}"
    return summary


@mcp.tool(annotations=LOCAL_DESTRUCTIVE)
def sac_remove_connection(connection: str, confirm: str) -> dict[str, Any]:
    """Remove a conexão do cadastro local e apaga suas credenciais/refresh token do Credential Manager.
    Não altera nada no SAC. `confirm` deve repetir exatamente o id da conexão."""
    if confirm != connection:
        raise ToolError("Confirmação inválida: `confirm` deve ser idêntico a `connection`.")
    reg = runtime.registry()
    _guard(lambda: reg.remove(connection))
    reg.save()
    _guard(lambda: runtime.store_factory(connection).delete_all())
    runtime.drop(connection)
    return {"removed": connection, "credentials_deleted": True, "remaining": sorted(reg.connections)}


# ---------------------------------------------------------------- consultas (somente leitura)
@mcp.tool(annotations=READ_ONLY)
def sac_auth_status(connection: str) -> dict[str, Any]:
    """Status da autenticação da conexão: fluxo OAuth, grant e scopes do token (o token não é exibido)."""
    sess = runtime.session(connection, require_selected=False)
    base = _connection_summary(connection, sess.config)
    try:
        token = sess.tokens.get_access_token()
    except KeyringError as exc:
        return {**base, "authenticated": False, "detail": f"Cofre de credenciais indisponível: {type(exc).__name__}"}
    except AuthError as exc:
        return {**base, "authenticated": False, "detail": redact(str(exc))}
    return {**base, "authenticated": True, **safe_claims_summary(token)}


@mcp.tool(annotations=READ_ONLY)
def sac_list_namespaces(connection: str) -> list[dict[str, Any]]:
    """Lista os namespaces do Data Export Service (ex.: 'sac') da conexão selecionada."""
    sess = runtime.session(connection)
    return _guard(sess.client.list_namespaces)


@mcp.tool(annotations=READ_ONLY)
def sac_list_models(connection: str, namespace: str = "sac", name_contains: str | None = None) -> dict[str, Any]:
    """Lista os modelos (providers) visíveis ao usuário/cliente na conexão, indicando a allowlist."""
    sess = runtime.session(connection)
    providers = _guard(lambda: sess.client.list_providers(namespace))
    if name_contains:
        needle = name_contains.lower()
        providers = [p for p in providers if needle in str(p.get("ProviderName", "")).lower()
                     or needle in str(p.get("ProviderID", "")).lower()]
    for p in providers:
        pid = p.get("ProviderID")
        p["allowed_by_allowlist"] = bool(pid) and sess.config.is_model_allowed(str(pid))
    return {"connection": connection, "count": len(providers), "models": providers}


@mcp.tool(annotations=READ_ONLY)
def sac_get_model_metadata(connection: str, provider_id: str, namespace: str = "sac") -> dict[str, Any]:
    """Entity sets (FactData, master data) e colunas de um modelo, a partir do $metadata OData."""
    sess = runtime.session(connection)
    meta = _guard(lambda: sess.client.metadata(namespace, provider_id))
    meta["available_entity_sets"] = _guard(lambda: sess.client.entity_sets(namespace, provider_id))
    meta["connection"] = connection
    return meta


@mcp.tool(annotations=READ_ONLY)
def sac_get_fact_data(connection: str, provider_id: str, namespace: str = "sac", select: list[str] | None = None,
                      filter: str | None = None, orderby: str | None = None, top: int | None = None,
                      output: Literal["inline", "file"] = "inline") -> dict[str, Any]:
    """Extrai fact data (GET .../FactData). Padrão 1.000 linhas, máximo 50.000 por chamada.
    `filter` usa sintaxe OData $filter. output='file' grava CSV local e não devolve os dados ao chat."""
    return _extract(connection, provider_id, "FactData", namespace, select, filter, orderby, top, output)


@mcp.tool(annotations=READ_ONLY)
def sac_get_master_data(connection: str, provider_id: str, entity_set: str, namespace: str = "sac",
                        select: list[str] | None = None, filter: str | None = None,
                        orderby: str | None = None, top: int | None = None,
                        output: Literal["inline", "file"] = "inline") -> dict[str, Any]:
    """Lê um entity set de master data do modelo. `entity_set` deve existir em sac_get_model_metadata."""
    if entity_set == "FactData":
        raise ToolError("Use sac_get_fact_data para FactData.")
    return _extract(connection, provider_id, entity_set, namespace, select, filter, orderby, top, output)


def run() -> None:
    mcp.run(transport="stdio")
