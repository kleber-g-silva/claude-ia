"""CLI: sac-mcp [serve|set-credentials|check-grant|login|logout|test|show-config]."""
from __future__ import annotations

import argparse
import getpass
import json
import sys

import httpx
from keyring.errors import KeyringError

from sac_mcp import credentials as cred
from sac_mcp.auth import AuthError, TokenManager, safe_claims_summary
from sac_mcp.config import Config, ConfigError, config_dir
from sac_mcp.credentials import KeyringStore
from sac_mcp.redaction import redact, setup_logging


def _tm(cfg: Config, store: KeyringStore) -> TokenManager:
    return TokenManager(cfg, store, httpx.Client(timeout=cfg.timeout_seconds))


def cmd_set_credentials(_: argparse.Namespace) -> int:
    store = KeyringStore()
    print(f"Cofre: {store.backend_name()} (serviço '{cred.SERVICE}')")
    cid = getpass.getpass("OAuth Client ID (entrada oculta): ").strip()
    secret = getpass.getpass("OAuth Client Secret (entrada oculta): ").strip()
    if not cid or not secret:
        print("Valores vazios; nada foi gravado.", file=sys.stderr)
        return 1
    store.set(cred.CLIENT_ID, cid)
    store.set(cred.CLIENT_SECRET, secret)
    store.delete(cred.REFRESH_TOKEN)  # sessão antiga pertence a outro client
    del cid, secret
    print("Credenciais gravadas no cofre do sistema. Nenhum valor foi exibido ou registrado.")
    return 0


def cmd_check_grant(_: argparse.Namespace) -> int:
    cfg = Config.load(require_tenant=False)
    result = _tm(cfg, KeyringStore()).probe_client_credentials()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(
        "\nInterpretação:\n"
        "- 'recusado' com unauthorized_client/invalid_client -> o client não usa Client Credentials; "
        "use auth_flow=authorization_code e execute 'sac-mcp login'.\n"
        "- 'aceito' -> o client aceita 2-legged (SEM Data Access Control por usuário). Ele pode aceitar "
        "também Authorization Code; confirme em SAC > System > Administration > App Integration > SAC_EXPORT.\n"
        "- O grant configurado no SAC é a fonte oficial; este teste é complementar."
    )
    return 0


def cmd_login(args: argparse.Namespace) -> int:
    cfg = Config.load(require_tenant=False)
    tm = _tm(cfg, KeyringStore())
    token = tm.interactive_login(open_browser=not args.no_browser)
    print("Login concluído. Resumo do token:")
    print(json.dumps(safe_claims_summary(token.access_token), indent=2, ensure_ascii=False))
    return 0


def cmd_logout(_: argparse.Namespace) -> int:
    KeyringStore().delete(cred.REFRESH_TOKEN)
    print("Refresh token removido do cofre.")
    return 0


def cmd_forget(_: argparse.Namespace) -> int:
    store = KeyringStore()
    for k in (cred.CLIENT_ID, cred.CLIENT_SECRET, cred.REFRESH_TOKEN):
        store.delete(k)
    print("Client ID, Client Secret e refresh token removidos do cofre.")
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    """Teste real: token + Namespaces + Providers (+ metadata e 5 linhas se --model)."""
    from sac_mcp.sac_client import SacClient

    cfg = Config.load()
    if args.model and not cfg.is_model_allowed(args.model):
        cfg.model_allowlist.append(args.model)  # apenas nesta execução
    http = httpx.Client(timeout=cfg.timeout_seconds)
    tm = TokenManager(cfg, KeyringStore(), http)
    client = SacClient(cfg, tm, http)
    steps = [
        ("token", lambda: safe_claims_summary(tm.get_access_token())),
        ("namespaces", lambda: client.list_namespaces()),
        ("providers", lambda: {"count": len(p := client.list_providers(args.namespace)),
                               "first": [x.get("ProviderID") for x in p[:10]]}),
    ]
    if args.model:
        steps += [
            ("entity_sets", lambda: client.entity_sets(args.namespace, args.model)),
            ("metadata", lambda: {k: len(v) for k, v in client.metadata(args.namespace, args.model).items()}),
            ("factdata_top5", lambda: {"rows": len(r := list(client.iter_rows(args.namespace, args.model,
                                                                              "FactData", top=5))),
                                       "columns": list(r[0].keys()) if r else []}),
        ]
    ok = True
    for name, fn in steps:
        try:
            print(f"[OK]   {name}: {json.dumps(fn(), ensure_ascii=False, default=str)[:800]}")
        except Exception as exc:  # relatório: registra e segue
            ok = False
            print(f"[ERRO] {name}: {type(exc).__name__}: {redact(str(exc))}")
            if name == "token":
                break
    return 0 if ok else 2


def cmd_show_config(_: argparse.Namespace) -> int:
    cfg = Config.load(require_tenant=False)
    store = KeyringStore()
    print(f"config_dir: {config_dir()}")
    print(json.dumps(cfg.__dict__, indent=2, ensure_ascii=False))
    print(f"cofre: {store.backend_name()}")
    for k in (cred.CLIENT_ID, cred.CLIENT_SECRET, cred.REFRESH_TOKEN):
        print(f"  {k}: {'presente' if store.get(k) else 'ausente'}")
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="sac-mcp", description=__doc__)
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="Inicia o servidor MCP (stdio). Padrão.")
    sub.add_parser("set-credentials", help="Grava Client ID/Secret no cofre (entrada oculta).")
    sub.add_parser("check-grant", help="Testa se o client aceita client_credentials (chamada real).")
    p_login = sub.add_parser("login", help="Login 3-legged (Authorization Code + PKCE).")
    p_login.add_argument("--no-browser", action="store_true")
    sub.add_parser("logout", help="Remove o refresh token do cofre.")
    sub.add_parser("forget", help="Remove todas as credenciais do cofre.")
    p_test = sub.add_parser("test", help="Teste real: token, Namespaces, Providers[, modelo].")
    p_test.add_argument("--namespace", default="sac")
    p_test.add_argument("--model", help="ProviderID para testar metadata e FactData (5 linhas).")
    sub.add_parser("show-config", help="Mostra configuração (sem segredos).")
    args = parser.parse_args(argv)

    setup_logging()
    handlers = {
        "set-credentials": cmd_set_credentials, "check-grant": cmd_check_grant, "login": cmd_login,
        "logout": cmd_logout, "forget": cmd_forget, "test": cmd_test, "show-config": cmd_show_config,
    }
    if args.cmd in (None, "serve"):
        from sac_mcp.server import run

        run()
        return
    try:
        sys.exit(handlers[args.cmd](args))
    except (ConfigError, AuthError) as exc:
        print(f"Erro: {redact(str(exc))}", file=sys.stderr)
        sys.exit(1)
    except KeyringError as exc:
        print(f"Erro: cofre de credenciais indisponível ({type(exc).__name__}).", file=sys.stderr)
        sys.exit(1)
