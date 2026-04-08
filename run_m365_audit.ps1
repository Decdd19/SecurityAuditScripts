#!/usr/bin/env pwsh
# Launcher: authenticate and run M365 audit against the test tenant

$TenantId     = "4ad86fee-1fda-4be0-9a4e-f61877d9bca8"
$TenantDomain = "decdd19hotmail.onmicrosoft.com"
$OutputDir    = "$PSScriptRoot/reports"

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

Write-Host "`n=== Dunne Security — M365 Audit Launcher ===" -ForegroundColor Cyan
Write-Host "Tenant : $TenantDomain"
Write-Host "Output : $OutputDir`n"

# ── Connect to Microsoft Graph (device code — browser auth) ──
Write-Host "[1/2] Connecting to Microsoft Graph..." -ForegroundColor Yellow
Connect-MgGraph -TenantId $TenantId -UseDeviceAuthentication -NoWelcome -Scopes @(
    "Policy.Read.All",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
    "Directory.Read.All",
    "Organization.Read.All"
)
Write-Host "Graph connected.`n" -ForegroundColor Green

# ── Connect to Exchange Online (skipped automatically if no licence) ──
Write-Host "[2/2] Connecting to Exchange Online..." -ForegroundColor Yellow
try {
    Connect-ExchangeOnline -Organization $TenantDomain -ShowBanner:$false
    Write-Host "Exchange connected.`n" -ForegroundColor Green
} catch {
    Write-Host "Exchange Online skipped — $($_.Exception.Message)`n" -ForegroundColor DarkYellow
}

# ── Run auditors ──
$auditors = @(
    "$PSScriptRoot/M365/m365-auditor/m365_auditor.ps1"
)

foreach ($script in $auditors) {
    $name = (Split-Path $script -Parent | Split-Path -Leaf)
    Write-Host "`n--- Running $name ---" -ForegroundColor Cyan
    & $script -TenantDomain $TenantDomain -Output "$OutputDir/$($name -replace '-auditor','')" -Format all
}

Write-Host "`n=== Audit complete. Reports in $OutputDir ===" -ForegroundColor Green
