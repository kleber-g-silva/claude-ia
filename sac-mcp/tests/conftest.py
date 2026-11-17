import httpx
import pytest

from sac_mcp import credentials as cred
from sac_mcp.config import Config
from sac_mcp.credentials import MemoryStore

TENANT = "https://tenant.example.hcs.cloud.sap"
TOKEN_URL = "https://auth.example.hana.ondemand.com/oauth/token"
AUTH_URL = "https://auth.example.hana.ondemand.com/oauth/authorize"
DES = TENANT + "/api/v1/dataexport"


@pytest.fixture(autouse=True)
def isolated_config_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SAC_MCP_CONFIG_DIR", str(tmp_path / "cfg"))
    for var in ("SAC_TENANT_URL", "SAC_MODEL_ALLOWLIST", "SAC_AUTH_FLOW"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def config(tmp_path):
    return Config(
        tenant_url=TENANT,
        token_url=TOKEN_URL,
        authorize_url=AUTH_URL,
        model_allowlist=["MODEL1"],
        export_dir=str(tmp_path / "exports"),
    ).validate()


@pytest.fixture
def store():
    return MemoryStore({cred.CLIENT_ID: "cid-123", cred.CLIENT_SECRET: "s3cr3t-value"})


@pytest.fixture
def http():
    with httpx.Client() as c:
        yield c
