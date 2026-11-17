"""Isolamento entre tenants: credenciais, tokens, allowlist, seleção explícita e cadastro."""
import asyncio
import base64
import json

import httpx
import keyring
import keyring.backend
import pytest
import respx
from keyring.errors import PasswordDeleteError

from sac_mcp import cli, server
from sac_mcp import credentials as cred
from sac_mcp.config import Config, ConfigError, Registry, make_connection_id
from sac_mcp.credentials import KeyringStore

A, B = "acme-qas", "beta-prd"
TENANT_A, TENANT_B = "https://acme.eu10.hcs.cloud.sap", "https://beta.br10.hcs.cloud.sap"
AUTH_A, AUTH_B = "https://acme-q.authentication.eu10.hana.ondemand.com", "https://beta-p.authentication.br10.hana.ondemand.com"
# Valores fictícios (não são credenciais reais).
CREDS = {A: ("fake-id-A", "fake-secret-A"), B: ("fake-id-B", "fake-secret-B")}
SERVICE_DOC = {"value": [{"name": "FactData", "url": "FactData"}]}


class MemKeyring(keyring.backend.KeyringBackend):
    priority = 1

    def __init__(self):
        super().__init__()
        self.data = {}

    def get_password(self, service, username):
        return self.data.get((service, username))

    def set_password(self, service, username, password):
        self.data[(service, username)] = password

    def delete_password(self, service, username):
        if (service, username) not in self.data:
            raise PasswordDeleteError("not found")
        del self.data[(service, username)]


@pytest.fixture
def kr():
    previous = keyring.get_keyring()
    mem = MemKeyring()
    keyring.set_keyring(mem)
    yield mem
    keyring.set_keyring(previous)


def conn(client, env, tenant, auth, allow):
    return Config(client=client, environment=env, tenant_url=tenant, token_url=auth + "/oauth/token",
                  auth_flow="client_credentials", model_allowlist=allow)


@pytest.fixture
def env(kr, tmp_path):
    """Duas conexões persistidas em disco, credenciais no keyring (backend em memória)."""
    reg = Registry({}, tmp_path / "cfg" / "config.json")
    reg.add(conn("acme", "qas", TENANT_A, AUTH_A, ["MODEL1"]))
    reg.add(conn("beta", "prd", TENANT_B, AUTH_B, ["MODEL2"]))
    reg.save()
    for cid, (i, s) in CREDS.items():
        st = KeyringStore.for_connection(cid)
        st.set(cred.CLIENT_ID, i)
        st.set(cred.CLIENT_SECRET, s)
    http = httpx.Client()
    server.runtime.configure(lambda: Registry.load(reg.path), KeyringStore.for_connection, http)
    yield reg
    server.runtime.__init__()
    http.close()


@pytest.fixture
def sac():
    with respx.mock(assert_all_called=False) as r:
        r.post(AUTH_A + "/oauth/token").mock(return_value=httpx.Response(200, json={"access_token": "TOKEN-A",
                                                                                    "expires_in": 3600}))
        r.post(AUTH_B + "/oauth/token").mock(return_value=httpx.Response(200, json={"access_token": "TOKEN-B",
                                                                                    "expires_in": 3600}))
        for t in (TENANT_A, TENANT_B):
            r.get(t + "/api/v1/dataexport/administration/Namespaces").mock(
                return_value=httpx.Response(200, json={"value": [{"NamespaceID": "sac"}]}))
            for m in ("MODEL1", "MODEL2"):
                r.get(f"{t}/api/v1/dataexport/providers/sac/{m}").mock(return_value=httpx.Response(200, json=SERVICE_DOC))
                r.get(f"{t}/api/v1/dataexport/providers/sac/{m}/FactData").mock(
                    return_value=httpx.Response(200, json={"value": [{"tenant": t}]}))
        yield r


def call(name, args=None):
    res = asyncio.run(server.mcp.call_tool(name, args or {}))
    sc = res.structured_content
    return sc.get("result", sc) if isinstance(sc, dict) else json.loads(res.content[0].text)


def hosts_called(r):
    return [c.request.url.host for c in r.calls]


# ------------------------------------------------------------------ identificação
def test_connection_id_normalization():
    assert make_connection_id("Usina Lins", "QAS") == "usina_lins-qas"
    for bad in [("", "qas"), ("acme", ""), ("a" * 40, "qas")]:
        with pytest.raises(ConfigError):
            make_connection_id(*bad)


# ------------------------------------------------------------------ credenciais
def test_keyring_services_are_isolated(env, kr):
    assert cred.service_for(A) == "sac-mcp:acme-qas"
    services = {svc for (svc, _key) in kr.data}
    assert services == {"sac-mcp:acme-qas", "sac-mcp:beta-prd"}
    assert KeyringStore.for_connection(A).get(cred.CLIENT_SECRET) == "fake-secret-A"
    assert KeyringStore.for_connection(B).get(cred.CLIENT_SECRET) == "fake-secret-B"
    with pytest.raises(ConfigError):
        KeyringStore.for_connection("../../other")


def test_each_tenant_uses_its_own_credentials_and_token(env, sac):
    call("sac_select_connection", {"connection": A})
    call("sac_list_namespaces", {"connection": A})
    call("sac_select_connection", {"connection": B})
    call("sac_list_namespaces", {"connection": B})
    for c in sac.calls:
        req = c.request
        if req.method == "POST":
            user = base64.b64decode(req.headers["Authorization"].split()[1]).decode().split(":")[0]
            assert user == ("fake-id-A" if req.url.host in AUTH_A else "fake-id-B")
        else:
            expected = "Bearer TOKEN-A" if req.url.host in TENANT_A else "Bearer TOKEN-B"
            assert req.headers["Authorization"] == expected, "token de um tenant enviado a outro"


def test_refresh_token_rotation_is_isolated(env, kr):
    from sac_mcp.auth import TokenManager

    for cid in (A, B):
        KeyringStore.for_connection(cid).set(cred.REFRESH_TOKEN, f"rt-{cid}")
    cfg = env.get(A)
    cfg.auth_flow = "authorization_code"
    with respx.mock:
        respx.post(AUTH_A + "/oauth/token").mock(return_value=httpx.Response(
            200, json={"access_token": "x", "expires_in": 60, "refresh_token": "rt-new"}))
        with httpx.Client() as http:
            TokenManager(cfg, KeyringStore.for_connection(A), http).get_access_token()
    assert KeyringStore.for_connection(A).get(cred.REFRESH_TOKEN) == "rt-new"
    assert KeyringStore.for_connection(B).get(cred.REFRESH_TOKEN) == f"rt-{B}"


# ------------------------------------------------------------------ seleção explícita
def test_query_without_selection_is_refused_before_network(env, sac):
    with pytest.raises(Exception, match="não está selecionada"):
        call("sac_list_namespaces", {"connection": A})
    assert sac.calls.call_count == 0


def test_query_on_other_connection_than_selected_is_refused(env, sac):
    call("sac_select_connection", {"connection": A})
    with pytest.raises(Exception, match="não está selecionada"):
        call("sac_get_fact_data", {"connection": B, "provider_id": "MODEL2"})
    assert TENANT_B.split("//")[1] not in hosts_called(sac)
    assert AUTH_B.split("//")[1] not in hosts_called(sac)


def test_connection_parameter_is_mandatory(env, sac):
    call("sac_select_connection", {"connection": A})
    with pytest.raises(Exception):
        call("sac_get_fact_data", {"provider_id": "MODEL1"})
    assert sac.calls.call_count == 0


def test_unknown_connection(env):
    with pytest.raises(Exception, match="não cadastrada"):
        call("sac_select_connection", {"connection": "ghost-dev"})


def test_allowlist_is_per_connection(env, sac):
    call("sac_select_connection", {"connection": A})
    out = call("sac_get_fact_data", {"connection": A, "provider_id": "MODEL1"})
    assert out["connection"] == A and TENANT_A in out["csv"]
    with pytest.raises(Exception, match="allowlist"):
        call("sac_get_fact_data", {"connection": A, "provider_id": "MODEL2"})  # liberado só em B
    call("sac_select_connection", {"connection": B})
    with pytest.raises(Exception, match="allowlist"):
        call("sac_get_fact_data", {"connection": B, "provider_id": "MODEL1"})
    assert call("sac_get_fact_data", {"connection": B, "provider_id": "MODEL2"})["rows"] == 1


def test_exports_are_separated_by_connection(env, sac, tmp_path):
    for c in env.connections.values():
        c.export_dir = str(tmp_path / "exp")
    env.save()
    call("sac_select_connection", {"connection": A})
    fa = call("sac_get_fact_data", {"connection": A, "provider_id": "MODEL1", "output": "file"})["file"]
    call("sac_select_connection", {"connection": B})
    fb = call("sac_get_fact_data", {"connection": B, "provider_id": "MODEL2", "output": "file"})["file"]
    assert f"exp/{A}/" in fa.replace("\\", "/") and f"exp/{B}/" in fb.replace("\\", "/")


def test_cli_changes_are_picked_up_without_restart(env, sac):
    call("sac_select_connection", {"connection": A})
    with pytest.raises(Exception, match="allowlist"):
        call("sac_get_fact_data", {"connection": A, "provider_id": "MODEL2"})
    reg = Registry.load(env.path)
    reg.get(A).model_allowlist.append("MODEL2")
    reg.save()
    assert call("sac_get_fact_data", {"connection": A, "provider_id": "MODEL2"})["rows"] == 1


# ------------------------------------------------------------------ gestão via MCP
def test_list_connections_has_no_secrets(env):
    out = call("sac_list_connections")
    dump = json.dumps(out)
    assert [c["connection"] for c in out["connections"]] == [A, B]
    assert all(c["credentials_stored"] is True for c in out["connections"])
    for i, s in CREDS.values():
        assert i not in dump and s not in dump


def test_add_connection_tool(env, kr):
    schema = {t.name: t for t in asyncio.run(server.mcp.list_tools())}["sac_add_connection"].input_schema
    assert not {k for k in schema["properties"] if "secret" in k or k in ("client_id", "password")}
    out = call("sac_add_connection", {"client": "Gamma", "environment": "DEV",
                                      "tenant_url": "https://gamma.us10.hcs.cloud.sap",
                                      "token_url": "https://gamma.authentication.us10.hana.ondemand.com/oauth/token"})
    assert out["connection"] == "gamma-dev" and out["credentials_stored"] is False
    assert out["model_allowlist"] == [] and "set-credentials --connection gamma-dev" in out["next_steps"][0]
    saved = Registry.load(env.path).get("gamma-dev")
    assert saved.authorize_url == "https://gamma.authentication.us10.hana.ondemand.com/oauth/authorize"
    assert not any(svc == "sac-mcp:gamma-dev" for (svc, _k) in kr.data)  # nenhuma credencial criada


@pytest.mark.parametrize("override, match", [
    ({"model_allowlist": ["*"]}, "CLI"),
    ({"tenant_url": "https://evil.example.com"}, "domínios SAP"),
    ({"token_url": "https://evil.example.com/oauth/token"}, "domínios SAP"),
    ({"token_url": "https://x.hana.ondemand.com/steal"}, "/oauth/token"),
    ({"client": "acme", "environment": "qas"}, "já existe"),
    ({"tenant_url": TENANT_B}, "já está cadastrado"),
])
def test_add_connection_rejections(env, override, match):
    args = {"client": "delta", "environment": "dev", "tenant_url": "https://delta.us10.hcs.cloud.sap",
            "token_url": "https://delta.authentication.us10.hana.ondemand.com/oauth/token", **override}
    with pytest.raises(Exception, match=match):
        call("sac_add_connection", args)
    assert set(Registry.load(env.path).connections) == {A, B}


def test_remove_connection_isolated(env, kr):
    call("sac_select_connection", {"connection": A})
    with pytest.raises(Exception, match="Confirmação"):
        call("sac_remove_connection", {"connection": A, "confirm": B})
    out = call("sac_remove_connection", {"connection": A, "confirm": A})
    assert out["remaining"] == [B]
    assert server.runtime.selected is None
    assert not any(svc == "sac-mcp:acme-qas" for (svc, _k) in kr.data)
    assert KeyringStore.for_connection(B).get(cred.CLIENT_SECRET) == "fake-secret-B"
    assert set(Registry.load(env.path).connections) == {B}


# ------------------------------------------------------------------ CLI
def run_cli(argv):
    with pytest.raises(SystemExit) as e:
        cli.main(argv)
    return e.value.code


def test_cli_lifecycle(kr, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SAC_MCP_CONFIG_DIR", str(tmp_path / "c"))
    assert run_cli(["add", "--client", "acme", "--environment", "qas", "--tenant-url", TENANT_A,
                    "--token-url", AUTH_A + "/oauth/token"]) == 0
    assert run_cli(["add", "--client", "evil", "--environment", "x", "--tenant-url", "https://evil.example.com",
                    "--token-url", AUTH_A + "/oauth/token"]) == 1
    answers = iter(["fake-id-A", "fake-secret-A"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    assert run_cli(["set-credentials", "-c", A]) == 0
    assert run_cli(["allowlist", "-c", A, "--add", "M1", "M2"]) == 0
    assert run_cli(["allowlist", "-c", A, "--remove", "M1"]) == 0
    assert Registry.load().get(A).model_allowlist == ["M2"]
    assert run_cli(["list"]) == 0
    out = capsys.readouterr().out
    assert "fake-secret-A" not in out and "fake-id-A" not in out and "credenciais=sim" in out
    assert KeyringStore.for_connection(A).get(cred.CLIENT_ID) == "fake-id-A"
    assert run_cli(["remove", "-c", A, "--yes", "wrong"]) == 1
    assert run_cli(["remove", "-c", A, "--yes", A]) == 0
    assert kr.data == {} and Registry.load().connections == {}


def test_cli_requires_connection(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["test"])
    assert e.value.code == 2 and "--connection" in capsys.readouterr().err
