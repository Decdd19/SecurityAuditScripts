<#
.SYNOPSIS
    Windows / Azure security audit orchestrator — the PS1 equivalent of audit.py.

.DESCRIPTION
    Runs any combination of Azure, M365, and Windows on-premises PS1 auditors,
    saves all output to a timestamped client folder, and optionally invokes
    tools\exec_summary.py to generate an executive HTML report.

.PARAMETER Client
    Client name (required). Used as the output folder slug.

.PARAMETER OutputDir
    Base directory where the client folder is created (default: current directory).

.PARAMETER Azure
    Run all Azure auditors: keyvault, storage, nsg, activitylog, subscription,
    entra, defender, policy, azbackup.

.PARAMETER Windows
    Run all Windows on-premises auditors: laps.
    Must be run as administrator on the target machine.

.PARAMETER M365
    Run the M365 auditor.

.PARAMETER All
    Run all available auditors (Azure + M365 + Windows).

.PARAMETER AllSubscriptions
    Pass -AllSubscriptions to all Azure scripts that support it.

.PARAMETER SkipSummary
    Skip the exec_summary.py invocation even if Python is available.

.PARAMETER Open
    Open the HTML summary in the default browser when done.

.EXAMPLE
    .\Run-Audit.ps1 -Client "Acme Corp" -Azure -AllSubscriptions
    .\Run-Audit.ps1 -Client "Acme Corp" -All -Open
    .\Run-Audit.ps1 -Client "Acme Corp" -M365 -SkipSummary
    .\Run-Audit.ps1 -Client "Acme Corp" -Azure -OutputDir C:\Reports
#>
param(
    [Parameter(Mandatory = $false)]
    [string]$Client,

    [string]$OutputDir = '.',

    [switch]$Azure,

    [switch]$Windows,

    [switch]$M365,

    [switch]$All,

    [switch]$AllSubscriptions,

    [switch]$SkipSummary,

    [switch]$Open
)

# ── Banner ────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  🛡️  Security Audit Orchestrator — Run-Audit.ps1" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# ── Validate required params ──────────────────────────────────────────────────

if (-not $Client) {
    Write-Host "ERROR: -Client is required. Example: .\Run-Audit.ps1 -Client `"Acme Corp`" -Azure" -ForegroundColor Red
    exit 1
}

if (-not ($Azure -or $Windows -or $M365 -or $All)) {
    Write-Host "ERROR: Select at least one auditor group: -Azure, -Windows, -M365, or -All" -ForegroundColor Red
    exit 1
}

# ── Resolve paths ─────────────────────────────────────────────────────────────

$RepoRoot  = $PSScriptRoot
$DateStamp = Get-Date -Format 'yyyyMMdd'
$ClientSlug = ($Client -replace '\s+', '_').ToLower()
$ClientDir  = Join-Path (Resolve-Path $OutputDir) "${ClientSlug}_${DateStamp}"

New-Item -ItemType Directory -Path $ClientDir -Force | Out-Null

Write-Host "  Client : $Client" -ForegroundColor White
Write-Host "  Output : $ClientDir" -ForegroundColor White
Write-Host ""

# ── Pre-flight checks ─────────────────────────────────────────────────────────

if ($Windows -or $All) {
    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "WARNING: -Windows selected but not running as administrator. Some checks may fail." -ForegroundColor Yellow
    }
}

if ($Azure -or $All) {
    $azContext = $null
    try { $azContext = Get-AzContext -ErrorAction SilentlyContinue } catch {}
    if (-not $azContext) {
        Write-Host "WARNING: Az module context not detected. Run Connect-AzAccount before continuing." -ForegroundColor Yellow
    }
}

# ── Auditor definitions ───────────────────────────────────────────────────────
# Each entry: script path (relative to repo root), output prefix, supports AllSubscriptions

$AzureAuditors = @(
    @{ Name = 'keyvault';     Script = 'Azure\keyvault-auditor\keyvault_auditor.ps1';         Prefix = 'keyvault_report';     AllSubs = $true  }
    @{ Name = 'storage';      Script = 'Azure\storage-auditor\storage_auditor.ps1';           Prefix = 'storage_report';      AllSubs = $true  }
    @{ Name = 'nsg';          Script = 'Azure\nsg-auditor\nsg_auditor.ps1';                   Prefix = 'nsg_report';          AllSubs = $true  }
    @{ Name = 'activitylog';  Script = 'Azure\activitylog-auditor\activitylog_auditor.ps1';   Prefix = 'activitylog_report';  AllSubs = $true  }
    @{ Name = 'subscription'; Script = 'Azure\subscription-auditor\subscription_auditor.ps1'; Prefix = 'subscription_report'; AllSubs = $true  }
    @{ Name = 'entra';        Script = 'Azure\entra-auditor\entra_auditor.ps1';               Prefix = 'entra_report';        AllSubs = $true  }
    @{ Name = 'defender';     Script = 'Azure\defender-auditor\defender_auditor.ps1';         Prefix = 'defender_report';     AllSubs = $true  }
    @{ Name = 'policy';       Script = 'Azure\policy-auditor\azpolicy_auditor.ps1';           Prefix = 'policy_report';       AllSubs = $true  }
    @{ Name = 'azbackup';     Script = 'Azure\backup-auditor\azbackup_auditor.ps1';           Prefix = 'azbackup_report';     AllSubs = $true  }
)

$M365Auditors = @(
    @{ Name = 'm365';         Script = 'M365\m365-auditor\m365_auditor.ps1';                  Prefix = 'm365_report';         AllSubs = $false }
)

$WindowsAuditors = @(
    @{ Name = 'laps';         Script = 'OnPrem\Windows\laps-auditor\laps_auditor.ps1';        Prefix = 'laps_report';         AllSubs = $false }
    @{ Name = 'winpatch';     Script = 'OnPrem\Windows\winpatch-auditor\winpatch_auditor.ps1'; Prefix = 'winpatch_report';     AllSubs = $false }
)

# ── Build run list ────────────────────────────────────────────────────────────

$RunList = @()
if ($Azure  -or $All) { $RunList += $AzureAuditors  }
if ($M365   -or $All) { $RunList += $M365Auditors   }
if ($Windows -or $All) { $RunList += $WindowsAuditors }

Write-Host "  Auditors to run: $($RunList.Count)" -ForegroundColor Cyan
Write-Host ""

# ── Run auditors ──────────────────────────────────────────────────────────────

$Results = @()

foreach ($Auditor in $RunList) {
    $ScriptPath  = Join-Path $RepoRoot $Auditor.Script
    $OutputPrefix = Join-Path $ClientDir $Auditor.Prefix
    $LogFile     = Join-Path $ClientDir "$($Auditor.Name).log"

    Write-Host "  ▶  $($Auditor.Name)" -NoNewline -ForegroundColor Cyan

    if (-not (Test-Path $ScriptPath)) {
        Write-Host "  ⚠ SKIPPED (script not found: $ScriptPath)" -ForegroundColor Yellow
        $Results += @{ Name = $Auditor.Name; Status = 'SKIPPED'; Duration = 0 }
        continue
    }

    $StartTime = Get-Date

    # Build argument list
    $ScriptArgs = @('-NonInteractive', '-File', $ScriptPath,
                    '-Output', $OutputPrefix,
                    '-Format', 'json')

    if ($AllSubscriptions -and $Auditor.AllSubs) {
        $ScriptArgs += '-AllSubscriptions'
    }

    # Run the script, capturing stdout+stderr to log file
    try {
        $proc = Start-Process -FilePath 'pwsh' `
                              -ArgumentList $ScriptArgs `
                              -RedirectStandardOutput $LogFile `
                              -RedirectStandardError  "$LogFile.err" `
                              -Wait -PassThru -NoNewWindow

        $Duration = [int]((Get-Date) - $StartTime).TotalSeconds

        if ($proc.ExitCode -eq 0) {
            Write-Host "  ✓ DONE  (${Duration}s)" -ForegroundColor Green
            $Results += @{ Name = $Auditor.Name; Status = 'DONE'; Duration = $Duration }
        } else {
            Write-Host "  ✗ FAILED  (exit $($proc.ExitCode), ${Duration}s) — see $LogFile" -ForegroundColor Red
            $Results += @{ Name = $Auditor.Name; Status = 'FAILED'; Duration = $Duration }
        }
    } catch {
        $Duration = [int]((Get-Date) - $StartTime).TotalSeconds
        Write-Host "  ✗ FAILED  (exception: $($_.Exception.Message))" -ForegroundColor Red
        $Results += @{ Name = $Auditor.Name; Status = 'FAILED'; Duration = $Duration }
    }
}

# ── Summary table ─────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  Results" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

$colName     = 20
$colStatus   = 10
$colDuration = 10

$header = ("  {0,-$colName}  {1,-$colStatus}  {2,-$colDuration}" -f 'Script', 'Status', 'Duration')
Write-Host $header -ForegroundColor White
Write-Host ("  " + ("-" * ($colName + $colStatus + $colDuration + 4))) -ForegroundColor DarkGray

$AnyFailed = $false
foreach ($R in $Results) {
    $statusColour = switch ($R.Status) {
        'DONE'    { 'Green'  }
        'FAILED'  { 'Red'    }
        'SKIPPED' { 'Yellow' }
        default   { 'White'  }
    }
    $statusIcon = switch ($R.Status) {
        'DONE'    { '✓ DONE'    }
        'FAILED'  { '✗ FAILED'  }
        'SKIPPED' { '⚠ SKIPPED' }
        default   { $R.Status   }
    }
    $row = ("  {0,-$colName}  {1,-$colStatus}  {2}" -f $R.Name, $statusIcon, "$($R.Duration)s")
    Write-Host $row -ForegroundColor $statusColour
    if ($R.Status -eq 'FAILED') { $AnyFailed = $true }
}

Write-Host ""

# ── Executive summary ─────────────────────────────────────────────────────────

$SummaryHtml = $null

if (-not $SkipSummary) {
    $ExecSummaryScript = Join-Path $RepoRoot 'tools\exec_summary.py'

    # Detect Python
    $PythonCmd = $null
    foreach ($candidate in @('python3', 'python')) {
        try {
            $ver = & $candidate --version 2>&1
            if ($ver -match 'Python \d') { $PythonCmd = $candidate; break }
        } catch {}
    }

    if ($PythonCmd -and (Test-Path $ExecSummaryScript)) {
        Write-Host "  Generating executive summary..." -ForegroundColor Cyan
        $SummaryHtml = Join-Path $ClientDir 'exec_summary.html'
        & $PythonCmd $ExecSummaryScript `
            --input-dir  $ClientDir `
            --output     $SummaryHtml `
            --client-name $Client

        if ($LASTEXITCODE -eq 0 -and (Test-Path $SummaryHtml)) {
            Write-Host "  Summary : $SummaryHtml" -ForegroundColor Green
        } else {
            Write-Host "  WARNING: exec_summary.py did not complete successfully." -ForegroundColor Yellow
            $SummaryHtml = $null
        }
    } elseif (-not $PythonCmd) {
        Write-Host "  INFO: Python not found — skipping executive summary." -ForegroundColor Yellow
    } else {
        Write-Host "  INFO: tools\exec_summary.py not found — skipping executive summary." -ForegroundColor Yellow
    }
}

# ── Open in browser ───────────────────────────────────────────────────────────

if ($Open -and $SummaryHtml -and (Test-Path $SummaryHtml)) {
    Start-Process $SummaryHtml
}

# ── Exit code ─────────────────────────────────────────────────────────────────

Write-Host ""
if ($AnyFailed) {
    Write-Host "  Audit complete with failures. Review logs in: $ClientDir" -ForegroundColor Red
    exit 1
} else {
    Write-Host "  Audit complete. Output: $ClientDir" -ForegroundColor Green
    exit 0
}
