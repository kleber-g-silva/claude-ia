"""CLI do sac-mcp (multi-tenant).

  sac-mcp serve                                   servidor MCP (stdio; padrão)
  sac-mcp list | show-config                      conexões cadastradas (sem segredos)
  sac-mcp add [--client --environment --tenant-url --token-url ...]
  sac-mcp remove -c <id>
  sac-mcp allowlist -c <id> [--add M ...] [--remove M ...] [--all | --none]
  sac-mcp set-credentials -c <id>                 entrada oculta -> Credential Manager
  sac-mcp check-grant -c <id>                     chamada real (token endpoint)
  sac-mcp login -c <id> | logout -c <id> | forget -c <id>
  sac-mcp test -c <id> [--model <ProviderID>]     chamada real (somente GET)
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys

import httpx
from keyring.errors import KeyringError

from sac_mcp import credentials as cred
from sac_mcp.auth import AuthError, TokenManager, safe_claims_summary
from sac_mcp.config import ALLOW_ALL, Config, ConfigError, Registry, config_path
from sac_mcp.credentials import KeyringStore
from sac_mcp.redaction import redact, setup_logging


def _conn(args: argparse.Namespace) -> tuple[Registry, Config, KeyringStore]:
    reg = Registry.load()
    cfg = reg.get(args.connection)
    return reg, cfg, KeyringStore.for_connection(args.connection)


def _tm(cfg: Config, store: KeyringStore) -> TokenManager:
    return TokenManager(cfg, store, httpx.Client(timeout=cfg.timeout_seconds))


def _ask(prompt: str, value: str | None) -> str:
    return value if value else input(prompt).strip()


# ------------------------------------------------------------------ conexões
def cmd_list(_: argparse.Namespace) -> int:
    reg = Registry.load()
    print(f"config: {config_path()}")
    if not reg.connections:
        print("Nenhuma conexão cadastrada. Use: sac-mcp add")
        return 0
    for cid, cfg in sorted(reg.connections.items()):
        store = KeyringStore.for_connection(cid)
        try:
            creds = "sim" if store.has_credentials() else "NÃO"
            session = "sim" if store.get(cred.REFRESH_TOKEN) else "não"
        except KeyringError:
            creds = session = "cofre indisponível"
        print(f"- {cid}  [{cfg.environment.upper()}]  {cfg.tenant_url}")
        print(f"    auth_flow={cfg.auth_flow}  credenciais={creds}  sessão(refresh)={session}")
        print(f"    allowlist={cfg.model_allowlist or '[] (nenhum modelo liberado)'}")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    reg = Registry.load()
    cfg = Config(
        client=_ask("Cliente (ex.: usinalins): ", args.client),
        environment=_ask("Ambiente (ex.: dev, qas, prd): ", args.environment),
        tenant_url=_ask("URL do tenant SAC (https://<host>): ", args.tenant_url),
        token_url=_ask("Token URL (https://<host>/oauth/token): ", args.token_url),
        authorize_url=args.authorize_url or "",
        auth_flow=args.auth_flow,
        redirect_uri=args.redirect_uri,
        model_allowlist=list(args.model or []),
        allow_custom_domain=args.allow_custom_domain,
    )
    cid = reg.add(cfg)
    reg.save()
    print(f"Conexão cadastrada: {cid}  (authorize_url={cfg.authorize_url})")
    if args.with_credentials:
        return cmd_set_credentials(argparse.Namespace(connection=cid))
    print(f"Próximo passo: sac-mcp set-credentials --connection {cid}")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    reg, _, store = _conn(args)
    typed = args.yes or input(f"Digite o id '{args.connection}' para confirmar a remoção: ").strip()
    if typed != args.connection:
        print("Confirmação não confere; nada foi removido.", file=sys.stderr)
        return 1
    reg.remove(args.connection)
    reg.save()
    store.delete_all()
    print(f"Conexão {args.connection} removida (config + credenciais).")
    return 0


def cmd_allowlist(args: argparse.Namespace) -> int:
    reg, cfg, _ = _conn(args)
    models = set(cfg.model_allowlist)
    if args.all:
        models = {ALLOW_ALL}
    if args.none:
        models = set()
    models |= set(args.add or [])
    models -= set(args.remove or [])
    if ALLOW_ALL in models and len(models) > 1:
        models = {ALLOW_ALL}
    cfg.model_allowlist = sorted(models)
    cfg.validate()
    reg.save()
    print(f"{args.connection}: allowlist = {cfg.model_allowlist or '[] (nenhum modelo liberado)'}")
    return 0


# ------------------------------------------------------------------ credenciais / auth
def cmd_set_credentials(args: argparse.Namespace) -> int:
    _, cfg, store = _conn(args)
    print(f"Conexão: {args.connection} [{cfg.environment.upper()}] {cfg.tenant_url}")
    print(f"Cofre: {store.backend_name()} (serviço '{store.service}')")
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


def cmd_check_grant(args: argparse.Namespace) -> int:
    _, cfg, store = _conn(args)
    result = _tm(cfg, store).probe_client_credentials()
    print(json.dumps({"connection": args.connection, **result}, indent=2, ensure_ascii=False))
    print(
        "\nInterpretação:\n"
        "- 'recusado' com unauthorized_client/invalid_client -> o client não usa Client Credentials; "
        "mantenha auth_flow=authorization_code e execute 'sac-mcp login'.\n"
        "- 'aceito' -> o client aceita 2-legged (SEM Data Access Control por usuário). Ele pode aceitar "
        "também Authorization Code; confirme em SAC > System > Administration > App Integration.\n"
        "- O grant configurado no SAC é a fonte oficial; este teste é complementar."
    )
    return 0


def cmd_login(args: argparse.Namespace) -> int:
    _, cfg, store = _conn(args)
    print(f"Login em {args.connection} [{cfg.environment.upper()}] {cfg.tenant_url}")
    token = _tm(cfg, store).interactive_login(open_browser=not args.no_browser)
    print("Login concluído. Resumo do token:")
    print(json.dumps(safe_claims_summary(token.access_token), indent=2, ensure_ascii=False))
    return 0


def cmd_logout(args: argparse.Namespace) -> int:
    _, _, store = _conn(args)
    store.delete(cred.REFRESH_TOKEN)
    print(f"{args.connection}: refresh token removido do cofre.")
    return 0


def cmd_forget(args: argparse.Namespace) -> int:
    _, _, store = _conn(args)
    store.delete_all()
    print(f"{args.connection}: Client ID, Client Secret e refresh token removidos do cofre.")
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    """Teste real: token + Namespaces + Providers (+ metadata e 5 linhas se --model)."""
    from sac_mcp.sac_client import SacClient

    _, cfg, store = _conn(args)
    if args.model and not cfg.is_model_allowed(args.model):
        cfg.model_allowlist.append(args.model)  # apenas nesta execução; não é salvo
    http = httpx.Client(timeout=cfg.timeout_seconds)
    tm = TokenManager(cfg, store, http)
    client = SacClient(cfg, tm, http)
    print(f"Testando {args.connection} [{cfg.environment.upper()}] {cfg.tenant_url}")
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


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="sac-mcp", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd")

    def with_conn(name: str, help_: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_)
        p.add_argument("-c", "--connection", required=True, help="id '<cliente>-<ambiente>'")
        return p

    sub.add_parser("serve", help="Inicia o servidor MCP (stdio). Padrão.")
    sub.add_parser("list", help="Lista conexões (sem segredos).")
    sub.add_parser("show-config", help="Alias de list.")
    p_add = sub.add_parser("add", help="Cadastra uma conexão (pergunta o que faltar).")
    p_add.add_argument("--client")
    p_add.add_argument("--environment")
    p_add.add_argument("--tenant-url")
    p_add.add_argument("--token-url")
    p_add.add_argument("--authorize-url", help="Padrão: derivada da token URL (/oauth/authorize).")
    p_add.add_argument("--auth-flow", choices=["authorization_code", "client_credentials"],
                       default="authorization_code")
    p_add.add_argument("--redirect-uri", default="http://localhost:8765/callback")
    p_add.add_argument("--model", action="append", help="ProviderID liberado (repetível).")
    p_add.add_argument("--allow-custom-domain", action="store_true",
                       help="Aceita hosts fora de *.sapanalytics.cloud / *.hcs.cloud.sap / *.hana.ondemand.com.")
    p_add.add_argument("--with-credentials", action="store_true",
                       help="Em seguida, solicita Client ID/Secret (entrada oculta).")
    p_rm = with_conn("remove", "Remove a conexão e apaga suas credenciais.")
    p_rm.add_argument("--yes", metavar="ID", help="Confirmação não interativa (repita o id).")
    p_al = with_conn("allowlist", "Altera a allowlist de modelos da conexão.")
    p_al.add_argument("--add", nargs="+")
    p_al.add_argument("--remove", nargs="+")
    p_al.add_argument("--all", action="store_true", help="Libera todos os modelos ('*').")
    p_al.add_argument("--none", action="store_true", help="Esvazia a allowlist.")
    with_conn("set-credentials", "Grava Client ID/Secret no cofre (entrada oculta).")
    with_conn("check-grant", "Testa se o client aceita client_credentials (chamada real).")
    p_login = with_conn("login", "Login 3-legged (Authorization Code + PKCE).")
    p_login.add_argument("--no-browser", action="store_true")
    with_conn("logout", "Remove o refresh token da conexão.")
    with_conn("forget", "Remove todas as credenciais da conexão.")
    p_test = with_conn("test", "Teste real: token, Namespaces, Providers[, modelo].")
    p_test.add_argument("--namespace", default="sac")
    p_test.add_argument("--model", help="ProviderID para testar metadata e FactData (5 linhas).")
    args = parser.parse_args(argv)

    setup_logging()
    handlers = {
        "list": cmd_list, "show-config": cmd_list, "add": cmd_add, "remove": cmd_remove,
        "allowlist": cmd_allowlist, "set-credentials": cmd_set_credentials, "check-grant": cmd_check_grant,
        "login": cmd_login, "logout": cmd_logout, "forget": cmd_forget, "test": cmd_test,
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
