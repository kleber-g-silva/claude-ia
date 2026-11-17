<#
.SYNOPSIS
  Instala o servidor MCP "sac" (SAP Analytics Cloud, somente leitura) e o registra no Claude Code (escopo user).

.DESCRIPTION
  1. Verifica Python >= 3.10 e o CLI "claude".
  2. Cria venv em %LOCALAPPDATA%\sac-mcp\venv e instala o pacote desta pasta.
  3. Grava %APPDATA%\sac-mcp\config.json (sem segredos; preserva a allowlist existente).
  4. Solicita Client ID/Secret com entrada oculta e grava no Windows Credential Manager.
  5. Registra o MCP: claude mcp add --scope user sac <venv>\Scripts\sac-mcp.exe serve
  6. Opcional (pergunta antes): check-grant, login e teste com chamadas REAIS ao SAC.

  Nenhum segredo é passado por parâmetro, gravado em arquivo ou exibido.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -TenantUrl https://<tenant>.<dc>.hcs.cloud.sap
#>
[CmdletBinding()]
param(
  [string]$TenantUrl,
  [ValidateSet("authorization_code", "client_credentials")]
  [string]$AuthFlow = "authorization_code",
  [string]$RedirectUri = "http://localhost:8765/callback",
  [string]$TokenUrl = "https://usinalins-q.authentication.br10.hana.ondemand.com/oauth/token",
  [string]$AuthorizeUrl = "https://usinalins-q.authentication.br10.hana.ondemand.com/oauth/authorize",
  [switch]$SkipCredentials,
  [switch]$SkipRegister
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
  $a = Read-Host "$question [s/N]"
  return ($a -match '^(s|sim|y|yes)$')
}

$SourceDir  = $PSScriptRoot
$InstallDir = Join-Path $env:LOCALAPPDATA "sac-mcp"
$VenvDir    = Join-Path $InstallDir "venv"
$ConfigDir  = Join-Path $env:APPDATA "sac-mcp"
$ConfigFile = Join-Path $ConfigDir "config.json"
$SacMcpExe  = Join-Path $VenvDir "Scripts\sac-mcp.exe"

# ------------------------------------------------------------------ 1. pré-requisitos
Step "Verificando pré-requisitos"
$py = $null
foreach ($cand in @(@("py", "-3"), @("python"))) {
  $exe = $cand[0]
  if (Get-Command $exe -ErrorAction SilentlyContinue) {
    $pyArgs = @($cand | Select-Object -Skip 1)
    $ok = Invoke-Quiet { & $exe @pyArgs -c "import sys; print(int(sys.version_info >= (3, 10)))" }
    if ($ok -eq "1") { $py = $cand; break }
  }
}
if (-not $py) { Fail "Python 3.10+ não encontrado. Instale em https://www.python.org/downloads/ (marque 'Add to PATH')." }
$pyExe = $py[0]; $pyArgs = @($py | Select-Object -Skip 1)
Write-Host ("Python: " + (& $pyExe @pyArgs --version))

if (-not $SkipRegister -and -not (Get-Command claude -ErrorAction SilentlyContinue)) {
  Fail "CLI 'claude' não encontrado no PATH. Instale o Claude Code ou use -SkipRegister."
}

if (-not $TenantUrl) {
  if (Test-Path $ConfigFile) {
    $existing = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    if ($existing.PSObject.Properties.Name -contains "tenant_url") { $TenantUrl = $existing.tenant_url }
  }
  if (-not $TenantUrl) { $TenantUrl = Read-Host "URL do tenant SAC (ex.: https://<tenant>.<dc>.hcs.cloud.sap)" }
}
$TenantUrl = $TenantUrl.Trim().TrimEnd("/")
if ($TenantUrl -notmatch '^https://[^/\s]+$') { Fail "URL do tenant inválida: use https://<host> sem caminho." }

# ------------------------------------------------------------------ 2. venv + pacote
Step "Criando ambiente virtual em $VenvDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
if (-not (Test-Path (Join-Path $VenvDir "Scripts\python.exe"))) {
  & $pyExe @pyArgs -m venv $VenvDir
  if ($LASTEXITCODE -ne 0) { Fail "Falha ao criar o venv." }
}
$venvPy = Join-Path $VenvDir "Scripts\python.exe"
& $venvPy -m pip install --upgrade --quiet pip
& $venvPy -m pip install --upgrade --quiet $SourceDir
if ($LASTEXITCODE -ne 0) { Fail "Falha ao instalar o pacote sac-mcp." }
if (-not (Test-Path $SacMcpExe)) { Fail "Executável não encontrado: $SacMcpExe" }

# ------------------------------------------------------------------ 3. config.json (sem segredos)
Step "Gravando configuração em $ConfigFile"
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
$cfg = [ordered]@{
  tenant_url      = $TenantUrl
  token_url       = $TokenUrl
  authorize_url   = $AuthorizeUrl
  auth_flow       = $AuthFlow
  redirect_uri    = $RedirectUri
  default_top     = 1000
  max_top         = 50000
  model_allowlist = @()
}
if (Test-Path $ConfigFile) {
  $old = Get-Content $ConfigFile -Raw | ConvertFrom-Json
  foreach ($k in @("model_allowlist", "default_top", "max_top", "export_dir")) {
    if ($old.PSObject.Properties.Name -contains $k) { $cfg[$k] = $old.$k }
  }
}
$cfg["model_allowlist"] = @($cfg["model_allowlist"])
$json = $cfg | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText($ConfigFile, $json, (New-Object Text.UTF8Encoding $false))
Write-Host "Allowlist atual: [$($cfg['model_allowlist'] -join ', ')] (vazia = nenhum modelo liberado; '*' = todos)"

# ------------------------------------------------------------------ 4. credenciais
if (-not $SkipCredentials) {
  Step "Credenciais do OAuth Client SAC_EXPORT (entrada oculta -> Windows Credential Manager)"
  & $SacMcpExe set-credentials
  if ($LASTEXITCODE -ne 0) { Fail "Credenciais não gravadas." }
}

# ------------------------------------------------------------------ 5. registro no Claude Code
if (-not $SkipRegister) {
  Step "Registrando o MCP 'sac' no Claude Code (escopo user)"
  Invoke-Quiet { & claude mcp remove sac --scope user } | Out-Null
  & claude mcp add --scope user sac $SacMcpExe serve
  if ($LASTEXITCODE -ne 0) { Fail "Falha no 'claude mcp add'." }
  & claude mcp get sac
}

# ------------------------------------------------------------------ 6. testes reais (opcionais)
Write-Host "`nInstalação local concluída. Os passos abaixo fazem chamadas REAIS ao SAC." -ForegroundColor Yellow
if (Confirm-Yes "Verificar o Authorization Grant do client agora (sac-mcp check-grant)?") {
  & $SacMcpExe check-grant
}
if ($AuthFlow -eq "authorization_code" -and (Confirm-Yes "Fazer login no SAC agora (abre o navegador)?")) {
  & $SacMcpExe login
}
if (Confirm-Yes "Executar teste de leitura (token, Namespaces, Providers)?") {
  $model = Read-Host "ProviderID para testar metadata + 5 linhas de FactData (Enter para pular)"
  if ($model) { & $SacMcpExe test --model $model } else { & $SacMcpExe test }
}

Write-Host "`nPróximos passos:" -ForegroundColor Green
Write-Host "  - Editar allowlist: $ConfigFile  (campo model_allowlist)"
Write-Host "  - Comandos: sac-mcp show-config | check-grant | login | logout | forget | test"
Write-Host "    ($SacMcpExe)"
Write-Host "  - No Claude Code: /mcp para ver o status do servidor 'sac'."
