<#
.SYNOPSIS
  Instala o servidor MCP "sac" (SAP Analytics Cloud, somente leitura, multi-tenant) e o registra
  UMA vez no Claude Code (escopo user). As conexões (tenants) são cadastradas depois, quantas forem.

.DESCRIPTION
  1. Verifica Python >= 3.10 e o CLI "claude".
  2. Cria venv em %LOCALAPPDATA%\sac-mcp\venv e instala o pacote desta pasta.
  3. Registra um único servidor: claude mcp add --scope user sac <venv>\Scripts\sac-mcp.exe serve
  4. (Opcional) Cadastra conexões <cliente>-<ambiente>; credenciais com entrada oculta, gravadas no
     Windows Credential Manager isoladas por conexão (sac-mcp:<conexão>).
  5. (Opcional, pergunta antes) Chamadas REAIS ao SAC: check-grant, login, test.

  Nenhum segredo é passado por parâmetro, gravado em arquivo ou exibido.
  Configuração (sem segredos): %APPDATA%\sac-mcp\config.json

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install.ps1

.PARAMETER SkipCredentials
  Cadastra a conexão sem pedir Client ID/Secret (útil em execução não interativa). Depois, no seu
  terminal: sac-mcp set-credentials -c <conexão>

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -Client usinalins -Environment qas `
    -TenantUrl https://<tenant>.<dc>.hcs.cloud.sap `
    -TokenUrl https://usinalins-q.authentication.br10.hana.ondemand.com/oauth/token
#>
[CmdletBinding()]
param(
  [string]$Client,
  [string]$Environment,
  [string]$TenantUrl,
  [string]$TokenUrl,
  [string]$AuthorizeUrl,
  [ValidateSet("authorization_code", "client_credentials")]
  [string]$AuthFlow = "authorization_code",
  [string]$RedirectUri = "http://localhost:8765/callback",
  [switch]$AllowCustomDomain,
  [switch]$SkipRegister,
  [switch]$SkipCredentials,
  [switch]$NoPrompt
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host "ERRO: $msg" -ForegroundColor Red; exit 1 }
function Invoke-Quiet([scriptblock]$Block) {
  # PS 5.1 converte stderr redirecionado de comandos nativos em erro sob "Stop".
  $prev = $ErrorActionPreference; $ErrorActionPreference = "Continue"
  try { & $Block 2>$null } catch { $null } finally { $ErrorActionPreference = $prev }
}
function Confirm-Yes($question) {
  if ($NoPrompt) { return $false }
  $a = Read-Host "$question [s/N]"
  return ($a -match '^(s|sim|y|yes)$')
}
function Invoke-SacMcp {
  # Função simples (sem param()): $args repassa tudo literalmente, inclusive "-c", ao CLI.
  # Código de saída em $LASTEXITCODE; erro do CLI não interrompe o script.
  & $script:SacMcpExe @args
}

$SourceDir  = $PSScriptRoot
$InstallDir = Join-Path $env:LOCALAPPDATA "sac-mcp"
$VenvDir    = Join-Path $InstallDir "venv"
$ConfigDir  = Join-Path $env:APPDATA "sac-mcp"
$ConfigFile = Join-Path $ConfigDir "config.json"
$script:SacMcpExe = Join-Path $VenvDir "Scripts\sac-mcp.exe"

# ------------------------------------------------------------------ 1. pré-requisitos
Step "Verificando pré-requisitos"
$py = $null
foreach ($cand in @(@("py", "-3"), @("python"))) {
  $exe = $cand[0]
  if (Get-Command $exe -ErrorAction SilentlyContinue) {
    $candArgs = @($cand | Select-Object -Skip 1)
    $ok = Invoke-Quiet { & $exe @candArgs -c "import sys; print(int(sys.version_info >= (3, 10)))" }
    if ("$ok".Trim() -eq "1") { $py = $cand; break }
  }
}
if (-not $py) { Fail "Python 3.10+ não encontrado. Instale em https://www.python.org/downloads/ (marque 'Add to PATH')." }
$pyExe = $py[0]; $pyArgs = @($py | Select-Object -Skip 1)
Write-Host ("Python: " + (& $pyExe @pyArgs --version))

if (-not $SkipRegister -and -not (Get-Command claude -ErrorAction SilentlyContinue)) {
  Fail "CLI 'claude' não encontrado no PATH. Instale o Claude Code ou use -SkipRegister."
}
if (-not (Test-Path (Join-Path $SourceDir "pyproject.toml"))) { Fail "Execute o script a partir da pasta sac-mcp." }

# ------------------------------------------------------------------ 2. venv + pacote
Step "Instalando em $VenvDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$venvPy = Join-Path $VenvDir "Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
  & $pyExe @pyArgs -m venv $VenvDir
  if ($LASTEXITCODE -ne 0) { Fail "Falha ao criar o venv." }
}
& $venvPy -m pip install --quiet --upgrade pip
& $venvPy -m pip install --quiet $SourceDir
if ($LASTEXITCODE -ne 0) { Fail "Falha ao instalar dependências." }
& $venvPy -m pip install --quiet --force-reinstall --no-deps $SourceDir   # garante o código desta pasta
if ($LASTEXITCODE -ne 0) { Fail "Falha ao instalar o pacote sac-mcp." }
if (-not (Test-Path $script:SacMcpExe)) { Fail "Executável não encontrado: $script:SacMcpExe" }

# config.json do formato antigo (conexão única) não é compatível: preserva cópia e recomeça.
if (Test-Path $ConfigFile) {
  $raw = Get-Content $ConfigFile -Raw | ConvertFrom-Json
  if ($raw.PSObject.Properties.Name -contains "tenant_url") {
    $bak = "$ConfigFile.bak-" + (Get-Date -Format "yyyyMMddHHmmss")
    Move-Item $ConfigFile $bak
    Write-Host "config.json no formato antigo movido para $bak. Recadastre a conexão abaixo." -ForegroundColor Yellow
  }
}

# ------------------------------------------------------------------ 3. registro único no Claude Code
if (-not $SkipRegister) {
  Step "Registrando o servidor MCP 'sac' no Claude Code (escopo user)"
  Invoke-Quiet { & claude mcp remove sac --scope user } | Out-Null
  & claude mcp add --scope user sac $script:SacMcpExe serve
  if ($LASTEXITCODE -ne 0) { Fail "Falha no 'claude mcp add'." }
  & claude mcp get sac
}

# ------------------------------------------------------------------ 4. conexões
Step "Conexões cadastradas"
Invoke-SacMcp list

if ($Client -or $Environment -or $TenantUrl -or $TokenUrl) {
  if (-not ($Client -and $Environment -and $TenantUrl -and $TokenUrl)) {
    Fail "Para cadastrar por parâmetro informe -Client, -Environment, -TenantUrl e -TokenUrl."
  }
  Step "Cadastrando conexão $Client / $Environment"
  $addArgs = @("add", "--client", $Client, "--environment", $Environment, "--tenant-url", $TenantUrl,
               "--token-url", $TokenUrl, "--auth-flow", $AuthFlow, "--redirect-uri", $RedirectUri)
  if (-not $SkipCredentials) { $addArgs += "--with-credentials" }
  if ($AuthorizeUrl) { $addArgs += @("--authorize-url", $AuthorizeUrl) }
  if ($AllowCustomDomain) { $addArgs += "--allow-custom-domain" }
  Invoke-SacMcp @addArgs
  if ($LASTEXITCODE -ne 0) { Write-Host "Cadastro não concluído (ver mensagem acima)." -ForegroundColor Yellow }
}

while (Confirm-Yes "Cadastrar uma (nova) conexão agora?") {
  Write-Host "Informe cliente, ambiente, URL do tenant e Token URL. A Authorize URL é derivada da Token URL."
  if ($SkipCredentials) { Invoke-SacMcp add --auth-flow $AuthFlow --redirect-uri $RedirectUri }
  else { Invoke-SacMcp add --auth-flow $AuthFlow --redirect-uri $RedirectUri --with-credentials }
  if ($LASTEXITCODE -ne 0) { Write-Host "Cadastro não concluído (ver mensagem acima)." -ForegroundColor Yellow }
}

# ------------------------------------------------------------------ 5. chamadas reais (opcionais)
Write-Host "`nOs passos abaixo fazem chamadas REAIS ao SAC e só rodam com sua confirmação." -ForegroundColor Yellow
while (Confirm-Yes "Validar uma conexão agora (check-grant / login / teste de leitura)?") {
  Invoke-SacMcp list
  $conn = (Read-Host "Id da conexão (<cliente>-<ambiente>)").Trim()
  if (-not $conn) { continue }
  if (Confirm-Yes "[$conn] Verificar o Authorization Grant (check-grant)?") { Invoke-SacMcp check-grant -c $conn }
  if (Confirm-Yes "[$conn] Fazer login 3-legged agora (abre o navegador)?") { Invoke-SacMcp login -c $conn }
  if (Confirm-Yes "[$conn] Executar teste de leitura (token, Namespaces, Providers)?") {
    $model = (Read-Host "ProviderID para testar metadata + 5 linhas de FactData (Enter para pular)").Trim()
    if ($model) { Invoke-SacMcp test -c $conn --model $model } else { Invoke-SacMcp test -c $conn }
  }
}

Write-Host "`nConcluído." -ForegroundColor Green
Write-Host "  Configuração (sem segredos): $ConfigFile"
Write-Host "  CLI: $script:SacMcpExe  (list | add | remove | allowlist | set-credentials | check-grant | login | test)"
Write-Host "  No Claude Code: /mcp  -> servidor 'sac'; use sac_list_connections e sac_select_connection."
