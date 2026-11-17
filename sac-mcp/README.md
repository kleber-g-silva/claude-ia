# sac-mcp — SAP Analytics Cloud (Data Export Service) para Claude Code

Servidor MCP local (stdio), **somente leitura** e **multi-tenant**, construído com o SDK oficial `mcp` (Python, v2.x — `MCPServer`). Um único servidor gerencia várias conexões SAC, cada uma identificada por **`<cliente>-<ambiente>`** (ex.: `usinalins-qas`, `usinalins-prd`).

## Modelo de segurança

| Tema | Implementação |
|---|---|
| Somente leitura (SAC) | Único verbo HTTP para o SAC: `GET`. Paths restritos a `/api/v1/dataexport/administration` e `/providers`. Header `Prefer` (assinatura de delta) e parâmetros `deltaid`/`externalid` bloqueados. `@odata.nextLink` validado (mesmo host/prefixo). |
| Ambiente errado | **Duas chaves**: toda consulta exige `connection` explícito **e** a conexão precisa estar selecionada na sessão (`sac_select_connection`). Divergência = recusa antes de qualquer chamada de rede. A seleção não é persistida entre sessões. |
| Isolamento | Por conexão: URLs, grant, allowlist, credenciais, refresh token, access token (memória) e pasta de exportação. Cofre: serviço `sac-mcp:<conexão>` no Windows Credential Manager. |
| Permissões | Padrão **Authorization Code + PKCE** (3-legged): o SAC aplica o Data Access Control do usuário. `client_credentials` (2-legged, **sem DAC por usuário**) só por opt-in na conexão. |
| Allowlist | Por conexão. **Vazia = nenhum modelo liberado** para metadata/dados. `"*"` (todos) só pela CLI, nunca pelo chat. |
| Volume | 1.000 linhas por padrão, máximo 50.000 por chamada. `output="file"` grava CSV local (`exports\<conexão>\`) e não devolve os dados ao chat. |
| Segredos | Nunca trafegam pelo MCP/chat. Entrada oculta (`getpass`) no terminal. Nada em arquivo, variável de ambiente ou repositório. Logs em stderr com mascaramento. |
| Cadastro | Hosts restritos a `*.sapanalytics.cloud`, `*.hcs.cloud.sap` (tenant) e `*.hana.ondemand.com` (XSUAA, caminho `/oauth/token`). Domínio customizado só pela CLI (`--allow-custom-domain`). Id e tenant duplicados são recusados. |

## Ferramentas MCP

| Ferramenta | Tipo | Observação |
|---|---|---|
| `sac_list_connections` | leitura local | Sem segredos; indica se há credenciais e qual está selecionada |
| `sac_add_connection` | grava config local | Não recebe credenciais; recusa `*` e domínios não SAP |
| `sac_select_connection` | estado da sessão | Pré-requisito para consultas |
| `sac_remove_connection` | **destrutiva local** | Exige `confirm` = id; apaga config + credenciais da conexão; nada no SAC |
| `sac_auth_status(connection)` | leitura | Grant/scopes do token, sem expor o token |
| `sac_list_namespaces(connection)` | leitura SAC | |
| `sac_list_models(connection)` | leitura SAC | |
| `sac_get_model_metadata(connection, provider_id)` | leitura SAC | Exige allowlist |
| `sac_get_fact_data(connection, provider_id, ...)` | leitura SAC | Exige allowlist |
| `sac_get_master_data(connection, provider_id, entity_set, ...)` | leitura SAC | Entity set validado no service document |

## Endpoints utilizados (fonte: SAP Help / SAP Community)

```
GET /api/v1/dataexport/administration/Namespaces
GET /api/v1/dataexport/administration/Namespaces(NamespaceID='sac')/Providers
GET /api/v1/dataexport/providers/{NamespaceID}/{ProviderID}             (service document)
GET /api/v1/dataexport/providers/{NamespaceID}/{ProviderID}/$metadata
GET /api/v1/dataexport/providers/{NamespaceID}/{ProviderID}/FactData
GET /api/v1/dataexport/providers/{NamespaceID}/{ProviderID}/{EntitySet} (master data, descoberto no service document)
```

Pendências de validação em tenant real: `$top`/`$orderby` em FactData; necessidade do header `x-sap-sac-custom-auth`; formato das respostas de administração; suporte a PKCE no XSUAA.

## Pré-requisitos no SAC (admin), por tenant

OAuth Client em *System → Administration → App Integration*:
- acesso ao **Data Export Service** habilitado;
- para Authorization Code: Redirect URI **`http://localhost:8765/callback`** cadastrada.

## Instalação (Windows)

Ver [instruções no fim deste arquivo](#instalação-passo-a-passo).

## CLI

| Comando | Chamada ao SAC? |
|---|---|
| `sac-mcp list` | não |
| `sac-mcp add [--client --environment --tenant-url --token-url] [--with-credentials]` | não |
| `sac-mcp allowlist -c <id> --add M1 M2 \| --remove M1 \| --all \| --none` | não |
| `sac-mcp set-credentials -c <id>` | não |
| `sac-mcp remove -c <id>` | não |
| `sac-mcp check-grant -c <id>` | **sim** (token endpoint) |
| `sac-mcp login -c <id>` | **sim** (navegador + token endpoint) |
| `sac-mcp test -c <id> [--model <ProviderID>]` | **sim** (somente GET) |
| `sac-mcp logout -c <id>` / `forget -c <id>` | não |

## Testes

```bash
pip install -e ".[test]" && pytest
```

## Instalação passo a passo

1. Pré-requisitos: Python 3.10+ (com `py` launcher ou `python` no PATH) e Claude Code (`claude` no PATH).
2. Validação opcional de sintaxe do script, sem executar nada:
   ```powershell
   $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("$PWD\install.ps1",[ref]$null,[ref]$e); $e
   ```
   (sem saída = sem erros de sintaxe)
3. Instalação + registro único do servidor:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\install.ps1
   ```
   O script pergunta se deseja cadastrar conexões e, separadamente, se deseja fazer chamadas reais.
4. Cadastro direto de uma conexão (opcional):
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\install.ps1 -Client usinalins -Environment qas `
     -TenantUrl https://<tenant>.<dc>.hcs.cloud.sap `
     -TokenUrl https://usinalins-q.authentication.br10.hana.ondemand.com/oauth/token
   ```
5. Liberar modelos: `sac-mcp allowlist -c usinalins-qas --add <ProviderID>`.
6. No Claude Code: `/mcp` → `sac` conectado; peça para listar as conexões e selecionar a desejada.
