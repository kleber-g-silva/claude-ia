import asyncio
import csv
import io
import json
from pathlib import Path

import httpx
import pytest
import respx

from sac_mcp import server
from sac_mcp.auth import TokenManager
from sac_mcp.config import Config, ConfigError, Registry
from sac_mcp.redaction import redact
from sac_mcp.sac_client import PolicyViolation, SacClient, SacPermissionError, summarize_metadata
from tests.conftest import DES, TENANT, TOKEN_URL

CONN = "acme-qas"

METADATA_XML = """<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx">
 <edmx:DataServices><Schema Namespace="sap.x" xmlns="http://docs.oasis-open.org/odata/ns/edm">
  <EntityType Name="FactDataType"><Key><PropertyRef Name="ID"/></Key>
   <Property Name="Account" Type="Edm.String"/><Property Name="SignedData" Type="Edm.Decimal"/></EntityType>
  <EntityType Name="AccountMasterType"><Key><PropertyRef Name="ID"/></Key>
   <Property Name="ID" Type="Edm.String"/><Property Name="Description" Type="Edm.String"/></EntityType>
  <EntityContainer Name="C"><EntitySet Name="FactData" EntityType="sap.x.FactDataType"/>
   <EntitySet Name="AccountMaster" EntityType="sap.x.AccountMasterType"/></EntityContainer>
 </Schema></edmx:DataServices></edmx:Edmx>"""

SERVICE_DOC = {"value": [{"name": "FactData", "url": "FactData"}, {"name": "AccountMaster", "url": "AccountMaster"}]}


@pytest.fixture
def mocked():
    with respx.mock(assert_all_called=False) as r:
        r.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "AT", "expires_in": 3600}))
        yield r


@pytest.fixture
def client(config, store, http):
    config.auth_flow = "client_credentials"
    return SacClient(config, TokenManager(config, store, http), http)


def only_get_to_tenant(r):
    for call in r.calls:
        req = call.request
        if req.url.host == httpx.URL(TENANT).host:
            assert req.method == "GET", f"verbo não permitido: {req.method}"
            assert "prefer" not in {k.lower() for k in req.headers}


# ----------------------------------------------------------------- config
def test_allowlist_defaults_to_deny(tmp_path):
    cfg = Config(tenant_url=TENANT, token_url=TOKEN_URL).validate()
    assert cfg.model_allowlist == [] and not cfg.is_model_allowed("ANY")
    assert Config(tenant_url=TENANT, token_url=TOKEN_URL, model_allowlist=["*"]).validate().is_model_allowed("ANY")


@pytest.mark.parametrize("kwargs", [
    {"tenant_url": "http://insecure"}, {"auth_flow": "password"},
    {"redirect_uri": "http://evil.com:80/cb"}, {"default_top": 0}, {"max_top": 60000},
])
def test_invalid_config(kwargs):
    base = {"tenant_url": TENANT, "token_url": TOKEN_URL, **kwargs}
    with pytest.raises(ConfigError):
        Config(**base).validate()


def test_config_file_and_env(monkeypatch, tmp_path):
    # Adaptado ao multi-tenant: config.json com o registro de conexões (com BOM, como o PowerShell 5.1 grava).
    d = tmp_path / "cfg"
    d.mkdir()
    conn = {"client": "acme", "environment": "qas", "tenant_url": TENANT, "token_url": TOKEN_URL,
            "model_allowlist": ["A"]}
    (d / "config.json").write_text(json.dumps({"connections": {CONN: conn}}), encoding="utf-8-sig")
    cfg = Registry.load().get(CONN)
    assert cfg.model_allowlist == ["A"] and cfg.authorize_url.endswith("/oauth/authorize")
    (d / "config.json").write_text(json.dumps({"tenant_url": TENANT}))
    with pytest.raises(ConfigError, match="formato antigo"):
        Registry.load()


def test_redaction():
    s = redact('Authorization: Bearer abc.def-ghi client_secret=xyz {"refresh_token": "rrr"} eyJa.eyJb.c')
    assert "abc.def" not in s and "xyz" not in s and "rrr" not in s and "eyJa" not in s


# ----------------------------------------------------------------- client
def test_list_providers_url_and_headers(client, mocked):
    route = mocked.get(f"{DES}/administration/Namespaces(NamespaceID='sac')/Providers").mock(
        return_value=httpx.Response(200, json={"value": [{"ProviderID": "MODEL1", "ProviderName": "Opex"}]})
    )
    assert client.list_providers()[0]["ProviderID"] == "MODEL1"
    h = route.calls[0].request.headers
    assert h["Authorization"] == "Bearer AT" and h["x-sap-sac-custom-auth"] == "true"
    only_get_to_tenant(mocked)


def test_allowlist_blocks_before_any_call(client, mocked):
    with pytest.raises(PolicyViolation, match="allowlist"):
        client.metadata("sac", "NOT_ALLOWED")
    assert not [c for c in mocked.calls if c.request.url.host == httpx.URL(TENANT).host]


@pytest.mark.parametrize("bad", ["../x", "a/b", "x' or 1", ""])
def test_identifier_injection_blocked(client, bad):
    with pytest.raises(PolicyViolation):
        client.metadata("sac", bad)


def test_write_paths_and_delta_blocked(client, mocked):
    with pytest.raises(PolicyViolation, match="Prefer"):
        client.get(client.url("/providers/sac/MODEL1/FactData"), headers={"Prefer": "odata.track-changes"})
    with pytest.raises(PolicyViolation, match="delta"):
        client.get(client.url("/providers/sac/MODEL1/FactData"), params={"deltaid": "1"})
    with pytest.raises(PolicyViolation, match="Path"):
        client.get(TENANT + "/api/v1/dataimport/models")
    with pytest.raises(PolicyViolation, match="tenant"):
        client.get("https://other.host/api/v1/dataexport/administration/Namespaces")


def test_pagination_respects_top_and_validates_nextlink(client, mocked):
    mocked.get(f"{DES}/providers/sac/MODEL1").mock(return_value=httpx.Response(200, json=SERVICE_DOC))
    page2 = f"{DES}/providers/sac/MODEL1/FactData?$skiptoken=2"
    fact = mocked.get(f"{DES}/providers/sac/MODEL1/FactData")
    fact.side_effect = [
        httpx.Response(200, json={"value": [{"a": 1}, {"a": 2}], "@odata.nextLink": page2}),
        httpx.Response(200, json={"value": [{"a": 3}, {"a": 4}], "@odata.nextLink": page2 + "x"}),
    ]
    rows = list(client.iter_rows("sac", "MODEL1", "FactData", top=3, select=["a"], filter_="a gt 0"))
    assert rows == [{"a": 1}, {"a": 2}, {"a": 3}]
    first = fact.calls[0].request.url.params
    assert first["$top"] == "3" and first["$select"] == "a" and first["$filter"] == "a gt 0"
    assert fact.call_count == 2  # parou ao atingir o limite
    only_get_to_tenant(mocked)


def test_nextlink_to_foreign_host_is_rejected(client, mocked):
    mocked.get(f"{DES}/providers/sac/MODEL1").mock(return_value=httpx.Response(200, json=SERVICE_DOC))
    mocked.get(f"{DES}/providers/sac/MODEL1/FactData").mock(
        return_value=httpx.Response(200, json={"value": [{"a": 1}], "@odata.nextLink": "https://evil/steal"}))
    with pytest.raises(PolicyViolation):
        list(client.iter_rows("sac", "MODEL1", "FactData", top=10))


def test_unknown_entity_set(client, mocked):
    mocked.get(f"{DES}/providers/sac/MODEL1").mock(return_value=httpx.Response(200, json=SERVICE_DOC))
    with pytest.raises(Exception, match="não existe"):
        list(client.iter_rows("sac", "MODEL1", "Invented", top=1))


def test_401_retries_once_then_403_maps(client, mocked):
    ns = mocked.get(f"{DES}/administration/Namespaces")
    ns.side_effect = [httpx.Response(401), httpx.Response(200, json={"value": [{"NamespaceID": "sac"}]})]
    assert client.list_namespaces() == [{"NamespaceID": "sac"}]
    ns.side_effect = [httpx.Response(403)]
    with pytest.raises(SacPermissionError, match="403"):
        client.list_namespaces()


def test_metadata_summary():
    m = summarize_metadata(METADATA_XML)
    assert [s["name"] for s in m["entity_sets"]] == ["FactData", "AccountMaster"]
    assert m["entity_types"]["FactDataType"]["properties"][1] == {"name": "SignedData", "type": "Edm.Decimal"}


# ----------------------------------------------------------------- MCP server
@pytest.fixture
def mcp_runtime(config, store, http, tmp_path):
    # Adaptado ao multi-tenant: uma conexão registrada e selecionada.
    config.auth_flow = "client_credentials"
    config.client, config.environment = "acme", "qas"
    reg = Registry({CONN: config}, tmp_path / "cfg" / "config.json")
    server.runtime.configure(lambda: reg, lambda cid: store, http)
    server.runtime.selected = CONN
    yield server.mcp
    server.runtime.__init__()


def call(mcp, name, args=None):
    res = asyncio.run(mcp.call_tool(name, args or {}))
    return res


def payload(res):
    if getattr(res, "structured_content", None):
        sc = res.structured_content
        return sc.get("result", sc) if isinstance(sc, dict) else sc
    return json.loads(res.content[0].text)


def test_tools_are_read_only(mcp_runtime):
    tools = asyncio.run(mcp_runtime.list_tools())
    names = {t.name for t in tools}
    queries = {"sac_auth_status", "sac_list_namespaces", "sac_list_models", "sac_get_model_metadata",
               "sac_get_fact_data", "sac_get_master_data"}
    management = {"sac_list_connections", "sac_add_connection", "sac_select_connection", "sac_remove_connection"}
    assert names == queries | management
    by_name = {t.name: t for t in tools}
    assert all(by_name[n].annotations.read_only_hint and not by_name[n].annotations.destructive_hint for n in queries)
    # única ferramenta destrutiva é local (cadastro/cofre), nunca no SAC
    assert {n for n, t in by_name.items() if t.annotations.destructive_hint} == {"sac_remove_connection"}
    for n in queries:  # conexão explícita obrigatória
        assert "connection" in by_name[n].input_schema["required"]


def test_tool_fact_data_inline_and_limits(mcp_runtime, mocked):
    mocked.get(f"{DES}/providers/sac/MODEL1").mock(return_value=httpx.Response(200, json=SERVICE_DOC))
    mocked.get(f"{DES}/providers/sac/MODEL1/FactData").mock(
        return_value=httpx.Response(200, json={"value": [{"Account": "A1", "SignedData": 10}]}))
    out = payload(call(mcp_runtime, "sac_get_fact_data", {"connection": CONN, "provider_id": "MODEL1"}))
    assert out["rows"] == 1 and out["limit"] == 1000 and out["columns"] == ["Account", "SignedData"]
    assert list(csv.reader(io.StringIO(out["csv"])))[1] == ["A1", "10"]
    with pytest.raises(Exception, match="50000"):
        call(mcp_runtime, "sac_get_fact_data", {"connection": CONN, "provider_id": "MODEL1", "top": 50001})
    with pytest.raises(Exception, match="allowlist"):
        call(mcp_runtime, "sac_get_fact_data", {"connection": CONN, "provider_id": "OTHER"})


def test_tool_fact_data_to_file(mcp_runtime, mocked, config):
    mocked.get(f"{DES}/providers/sac/MODEL1").mock(return_value=httpx.Response(200, json=SERVICE_DOC))
    mocked.get(f"{DES}/providers/sac/MODEL1/FactData").mock(
        return_value=httpx.Response(200, json={"value": [{"Account": "A1"}]}))
    out = payload(call(mcp_runtime, "sac_get_fact_data", {"connection": CONN, "provider_id": "MODEL1", "output": "file"}))
    assert "csv" not in out and Path(out["file"]).parent == Path(config.export_dir) / CONN
    assert Path(out["file"]).read_text(encoding="utf-8-sig").startswith("Account")


def test_tool_metadata_and_models(mcp_runtime, mocked):
    mocked.get(f"{DES}/providers/sac/MODEL1/$metadata").mock(return_value=httpx.Response(200, text=METADATA_XML))
    mocked.get(f"{DES}/providers/sac/MODEL1").mock(return_value=httpx.Response(200, json=SERVICE_DOC))
    mocked.get(f"{DES}/administration/Namespaces(NamespaceID='sac')/Providers").mock(
        return_value=httpx.Response(200, json={"value": [{"ProviderID": "MODEL1", "ProviderName": "Opex"},
                                                         {"ProviderID": "M2", "ProviderName": "HR"}]}))
    meta = payload(call(mcp_runtime, "sac_get_model_metadata", {"connection": CONN, "provider_id": "MODEL1"}))
    assert meta["available_entity_sets"] == ["FactData", "AccountMaster"]
    models = payload(call(mcp_runtime, "sac_list_models", {"connection": CONN, "name_contains": "op"}))
    assert models["count"] == 1 and models["models"][0]["allowed_by_allowlist"] is True


def test_tool_errors_do_not_leak_secrets(mcp_runtime, mocked):
    mocked.get(f"{DES}/administration/Namespaces").mock(
        return_value=httpx.Response(500, text="boom client_secret=LEAK Bearer eyJx.eyJy.z"))
    with pytest.raises(Exception) as ei:
        call(mcp_runtime, "sac_list_namespaces", {"connection": CONN})
    assert "LEAK" not in str(ei.value) and "eyJx" not in str(ei.value)
