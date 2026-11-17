# sac-mcp — SAP Analytics Cloud (Data Export Service) para Claude Code

Servidor MCP local (stdio), **somente leitura**, construído com o SDK oficial `mcp` (Python, v2.x — `MCPServer`).

## Modelo de segurança

| Tema | Implementação |
|---|---|
| Somente leitura | Único verbo HTTP para o SAC: `GET`. Paths restritos a `/api/v1/dataexport/administration` e `/providers`. Header `Prefer` (cria assinatura de delta) e parâmetros `deltaid`/`externalid` bloqueados. `@odata.nextLink` validado (mesmo host/prefixo). |
| Permissões | Fluxo padrão **Authorization Code + PKCE** (3-legged): o SAC aplica o Data Access Control do usuário. `client_credentials` (2-legged, **sem DAC por usuário**) só por opt-in em `auth_flow`. 401/403 viram erro explícito, sem contorno. |
| Allowlist | `model_allowlist` em `config.json`. **Vazia = nenhum modelo liberado** para metadata/dados (listar modelos continua permitido). `"*"` libera todos. |
| Volume | 1.000 linhas por padrão, máximo 50.000 por chamada. `output="file"` grava CSV local e **não** devolve os dados ao chat. |
| Segredos | Client ID/Secret e refresh token no **Windows Credential Manager** (`keyring`, alvo `sac-mcp`). Entrada via `getpass` (oculta). Access token só em memória. Nada em arquivo, variável de ambiente ou repositório. |
| Logs | Apenas stderr, com mascaramento de tokens/segredos; `httpx` em WARNING. |
| Rede | Saída apenas para o host de autenticação (XSUAA) e o host do tenant SAC. |

## Endpoints utilizados (fonte: SAP Help / SAP Community)

```
GET /api/v1/dataexport/administration/Namespaces
GET /api/v1/dataexport/administration/Namespaces(NamespaceID='sac')/Providers
GET /api/v1/dataexport/providers/{NamespaceID}/{ProviderID}             (service document)
GET /api/v1/dataexport/providers/{NamespaceID}/{ProviderID}/$metadata
GET /api/v1/dataexport/providers/{NamespaceID}/{ProviderID}/FactData
GET /api/v1/dataexport/providers/{NamespaceID}/{ProviderID}/{EntitySet} (master data, descoberto no service document)
```

Pendências de validação no tenant real: suporte a `$top`/`$orderby` em FactData; necessidade do header `x-sap-sac-custom-auth` (enviado por padrão; desligável com `send_custom_auth_header: false`).

## Pré-requisitos no SAC (admin)

OAuth Client **SAC_EXPORT** em *System → Administration → App Integration*:
- acesso ao **Data Export Service** habilitado;
- para Authorization Code: Redirect URI **`http://localhost:8765/callback`** cadastrada (ou ajuste `-RedirectUri`).

## Instalação (Windows)

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -TenantUrl https://<tenant>.<dc>.hcs.cloud.sap
```

O instalador cria o venv em `%LOCALAPPDATA%\sac-mcp\venv`, grava `%APPDATA%\sac-mcp\config.json`, pede as credenciais (ocultas), registra o MCP (`claude mcp add --scope user sac ...\sac-mcp.exe serve`) e **pergunta antes** de qualquer chamada real ao SAC.

## Comandos

| Comando | Faz chamada ao SAC? |
|---|---|
| `sac-mcp show-config` | não |
| `sac-mcp set-credentials` | não |
| `sac-mcp check-grant` | sim (token endpoint) |
| `sac-mcp login` | sim (navegador + token endpoint) |
| `sac-mcp test [--model <ProviderID>]` | sim (somente GET) |
| `sac-mcp logout` / `forget` | não |

## Ferramentas MCP

`sac_auth_status`, `sac_list_namespaces`, `sac_list_models`, `sac_get_model_metadata`, `sac_get_fact_data`, `sac_get_master_data` — todas anotadas `readOnlyHint=true`.

## Testes

```bash
pip install -e ".[test]" && pytest
```
