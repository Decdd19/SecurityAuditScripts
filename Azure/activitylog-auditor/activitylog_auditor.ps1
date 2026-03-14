<#
.SYNOPSIS
    Audits Azure Activity Log configuration for security compliance.
.DESCRIPTION
    Read-only audit of Activity Log diagnostic settings and alerts across one
    or all accessible subscriptions. Flags missing diagnostic settings,
    unconfigured log destinations, missing required log categories, short
    retention periods, and absent Activity Log alerts.
.PARAMETER Output
    Output file prefix (default: activitylog_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER AllSubscriptions
    Scan all subscriptions accessible to the current Az context.
.EXAMPLE
    .\activitylog_auditor.ps1
    .\activitylog_auditor.ps1 -AllSubscriptions -Format html
#>
param(
    [string]$Output          = 'activitylog_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format          = 'all',
    [switch]$AllSubscriptions
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Required log categories
# ---------------------------------------------------------------------------
$RequiredCategories = @('Administrative', 'Security', 'Policy', 'Alert')

# ---------------------------------------------------------------------------
# Az stubs — overridden by real Az module at runtime; Pester Mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command Get-AzDiagnosticSetting -ErrorAction SilentlyContinue)) {
    function Get-AzDiagnosticSetting { param($ResourceId) @() }
    function Get-AzActivityLogAlert { @() }
}

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------
function Get-SeverityLabel {
    param([int]$Score)
    if ($Score -ge 8) { return 'CRITICAL' }
    if ($Score -ge 6) { return 'HIGH' }
    if ($Score -ge 3) { return 'MEDIUM' }
    return 'LOW'
}

function Get-SeverityColour {
    param([string]$Severity)
    switch ($Severity) {
        'CRITICAL' { return '#dc3545' }
        'HIGH'     { return '#fd7e14' }
        'MEDIUM'   { return '#ffc107' }
        'LOW'      { return '#28a745' }
        default    { return '#6c757d' }
    }
}

# ---------------------------------------------------------------------------
# Audit function
# ---------------------------------------------------------------------------
function Get-ActivityLogFindings {
    param(
        [Parameter(Mandatory)][PSCustomObject]$Subscription
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $base = @{
        Subscription   = $Subscription.Name
        SubscriptionId = $Subscription.Id
    }

    $resourceId  = "/subscriptions/$($Subscription.Id)"
    $diagSettings = @(Get-AzDiagnosticSetting -ResourceId $resourceId -ErrorAction SilentlyContinue)

    # Check 1: No diagnostic settings at all
    if ($diagSettings.Count -eq 0) {
        $findings.Add([PSCustomObject](@{
            FindingType    = 'NoDiagnosticSetting'
            DiagSettingName = $null
            Detail         = 'No diagnostic setting configured for the subscription Activity Log'
            Score          = 9
            Severity       = 'CRITICAL'
            Recommendation = 'Create a diagnostic setting to export Activity Log to a Log Analytics workspace, storage account, or Event Hub.'
        } + $base))
    } else {
        foreach ($diag in $diagSettings) {
            # Check 2: No destination configured
            $hasWorkspace    = -not [string]::IsNullOrEmpty($diag.WorkspaceId)
            $hasStorage      = -not [string]::IsNullOrEmpty($diag.StorageAccountId)
            $hasEventHub     = -not [string]::IsNullOrEmpty($diag.EventHubName)

            if (-not $hasWorkspace -and -not $hasStorage -and -not $hasEventHub) {
                $findings.Add([PSCustomObject](@{
                    FindingType    = 'NoLogDestination'
                    DiagSettingName = $diag.Name
                    Detail         = "Diagnostic setting '$($diag.Name)' has no destination configured (no workspace, storage account, or event hub)"
                    Score          = 9
                    Severity       = 'CRITICAL'
                    Recommendation = 'Configure at least one destination (Log Analytics workspace, storage account, or Event Hub) for the diagnostic setting.'
                } + $base))
                continue
            }

            # Check 3: Required categories missing or disabled
            $enabledCategories = @{}
            foreach ($log in $diag.Logs) {
                if ($log.Enabled) {
                    $enabledCategories[$log.Category] = $log
                }
            }

            foreach ($cat in $RequiredCategories) {
                if (-not $enabledCategories.ContainsKey($cat)) {
                    $findings.Add([PSCustomObject](@{
                        FindingType    = 'MissingLogCategory'
                        DiagSettingName = $diag.Name
                        Detail         = "Category '$cat' not captured"
                        Score          = 7
                        Severity       = 'HIGH'
                        Recommendation = "Enable the '$cat' category in diagnostic setting '$($diag.Name)' to ensure full Activity Log coverage."
                    } + $base))
                }
            }

            # Check 4: Short retention on storage account destination
            if ($hasStorage) {
                $minDays = $null
                foreach ($log in $diag.Logs) {
                    if ($null -ne $log.RetentionPolicy -and $log.RetentionPolicy.Enabled) {
                        $days = $log.RetentionPolicy.Days
                        if ($null -eq $minDays -or $days -lt $minDays) {
                            $minDays = $days
                        }
                    }
                }
                if ($null -ne $minDays -and $minDays -lt 90) {
                    $findings.Add([PSCustomObject](@{
                        FindingType    = 'ShortRetention'
                        DiagSettingName = $diag.Name
                        Detail         = "Retention is $minDays days (minimum 90)"
                        Score          = 5
                        Severity       = 'MEDIUM'
                        Recommendation = "Increase retention to at least 90 days on the storage account destination in diagnostic setting '$($diag.Name)'."
                    } + $base))
                }
            }

            # Check 5: Event Hub destination — retention unverifiable
            if ($hasEventHub) {
                $findings.Add([PSCustomObject](@{
                    FindingType    = 'RetentionUnverifiable'
                    DiagSettingName = $diag.Name
                    Detail         = "Event Hub destination — retention cannot be audited"
                    Score          = 1
                    Severity       = 'LOW'
                    Recommendation = "Verify that downstream Event Hub consumers or connected storage enforce the required retention period (minimum 90 days)."
                } + $base))
            }
        }
    }

    # Check 6: No Activity Log alerts
    $alerts = @(Get-AzActivityLogAlert)
    if ($alerts.Count -eq 0) {
        $findings.Add([PSCustomObject](@{
            FindingType    = 'NoActivityLogAlerts'
            DiagSettingName = $null
            Detail         = 'No Activity Log alerts configured for this subscription'
            Score          = 6
            Severity       = 'HIGH'
            Recommendation = 'Create Activity Log alerts for critical operations such as policy changes, role assignments, and security group modifications.'
        } + $base))
    }

    return [PSCustomObject]@{ Findings = $findings; SubscriptionCount = 1 }
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function ConvertTo-HtmlReport {
    param(
        [Parameter(Mandatory)][array]$Findings,
        [string]$TenantId  = '',
        [string]$ScannedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
    )
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    $rows = foreach ($f in $Findings) {
        $colour = Get-SeverityColour $f.Severity
        $detail = if ($f.Detail) { [System.Web.HttpUtility]::HtmlEncode($f.Detail) } else { '-' }
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Subscription))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
            <td>$detail</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</td>
        </tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Activity Log Audit Report</title>
<style>
  body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5}
  h1{color:#333}.summary{display:flex;gap:16px;margin-bottom:24px}
  .card{background:#fff;border-radius:6px;padding:16px 24px;box-shadow:0 1px 4px rgba(0,0,0,.1);min-width:120px;text-align:center}
  .card .num{font-size:2em;font-weight:bold}.card .lbl{color:#666;font-size:.85em}
  table{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.1)}
  th{background:#343a40;color:#fff;padding:10px;text-align:left}
  td{padding:8px 10px;border-bottom:1px solid #dee2e6}tr:hover{background:#f1f3f5}
  .meta{color:#666;font-size:.85em;margin-bottom:16px}
</style></head><body>
<h1>Activity Log Audit Report</h1>
<p class='meta'>Tenant: $TenantId &nbsp;|&nbsp; Generated: $ScannedAt</p>
<div class='summary'>
  <div class='card'><div class='num'>$($Findings.Count)</div><div class='lbl'>Total Findings</div></div>
  <div class='card'><div class='num' style='color:#dc3545'>$($counts.CRITICAL)</div><div class='lbl'>CRITICAL</div></div>
  <div class='card'><div class='num' style='color:#fd7e14'>$($counts.HIGH)</div><div class='lbl'>HIGH</div></div>
  <div class='card'><div class='num' style='color:#ffc107'>$($counts.MEDIUM)</div><div class='lbl'>MEDIUM</div></div>
  <div class='card'><div class='num' style='color:#28a745'>$($counts.LOW)</div><div class='lbl'>LOW</div></div>
</div>
<table><thead><tr>
  <th>Subscription</th><th>FindingType</th><th>Detail</th>
  <th>Severity</th><th>Recommendation</th>
</tr></thead><tbody>
$($rows -join "`n")
</tbody></table></body></html>
"@
}

function ConvertTo-CsvReport {
    param([Parameter(Mandatory)][array]$Findings)
    $Findings | Select-Object Subscription, SubscriptionId, DiagSettingName,
        FindingType, Detail, Score, Severity, Recommendation
}

function Write-TerminalSummary {
    param([array]$Findings, [int]$SubscriptionsScanned)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }
    $top3 = $Findings | Sort-Object Score -Descending | Select-Object -First 3

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║       ACTIVITY LOG AUDIT COMPLETE                ║' -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    Write-Host "║  Subscriptions scanned: $($SubscriptionsScanned.ToString().PadRight(25))║" -ForegroundColor Cyan
    Write-Host "║  Total findings: $($Findings.Count.ToString().PadRight(32))║" -ForegroundColor Cyan
    Write-Host "║  CRITICAL: $($counts.CRITICAL)  HIGH: $($counts.HIGH)  MEDIUM: $($counts.MEDIUM)  LOW: $($counts.LOW)$((' ' * 20))║" -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    if ($top3) {
        Write-Host '║  Top findings:                                   ║' -ForegroundColor Cyan
        foreach ($f in $top3) {
            $line = "  [$($f.Severity)] $($f.Subscription): $($f.FindingType)"
            Write-Host "║  $($line.PadRight(47))║" -ForegroundColor Cyan
        }
    }
    Write-Host '╚══════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
}

function Set-RestrictedPermissions {
    param([string]$Path)
    if ($IsLinux -or $IsMacOS) {
        & chmod 600 $Path
    } else {
        $acl = Get-Acl $Path
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            'FullControl', 'Allow')
        $acl.SetAccessRule($rule)
        Set-Acl -Path $Path -AclObject $acl
    }
}

# ---------------------------------------------------------------------------
# Main — skipped when dot-sourced (InvocationName is '.' when dot-sourced)
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    $RequiredModules = @('Az.Accounts', 'Az.Monitor')
    foreach ($mod in $RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Write-Error "Required module '$mod' is not installed. Run: Install-Module $mod -Scope CurrentUser"
            exit 1
        }
    }

    $azContext = Get-AzContext
    if (-not $azContext) {
        Write-Error 'No active Azure context. Run Connect-AzAccount first.'
        exit 1
    }
    $tenantId = $azContext.Tenant.Id

    if ($AllSubscriptions) {
        $subscriptions = Get-AzSubscription
    } else {
        $subscriptions = @(Get-AzSubscription -SubscriptionId $azContext.Subscription.Id)
    }

    $allFindings        = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalSubscriptions = 0
    foreach ($sub in $subscriptions) {
        Write-Host "Scanning subscription: $($sub.Name) ($($sub.Id))" -ForegroundColor Gray
        Set-AzContext -SubscriptionId $sub.Id | Out-Null
        $result = Get-ActivityLogFindings -Subscription $sub
        $allFindings.AddRange([PSCustomObject[]]$result.Findings)
        $totalSubscriptions += $result.SubscriptionCount
    }

    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $reportData = @{
        generated_at = $timestamp
        tenant_id    = $tenantId
        findings     = $allFindings
        summary      = @{
            total    = $allFindings.Count
            critical = ($allFindings | Where-Object Severity -eq 'CRITICAL').Count
            high     = ($allFindings | Where-Object Severity -eq 'HIGH').Count
            medium   = ($allFindings | Where-Object Severity -eq 'MEDIUM').Count
            low      = ($allFindings | Where-Object Severity -eq 'LOW').Count
        }
    }

    switch ($Format) {
        'json'   {
            $reportData | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
            Set-RestrictedPermissions "$Output.json"
            Write-Host "JSON report: $Output.json"
        }
        'csv'    {
            ConvertTo-CsvReport $allFindings | Export-Csv "$Output.csv" -NoTypeInformation -Encoding UTF8
            Set-RestrictedPermissions "$Output.csv"
            Write-Host "CSV report: $Output.csv"
        }
        'html'   {
            ConvertTo-HtmlReport -Findings $allFindings -TenantId $tenantId -ScannedAt $timestamp |
                Out-File "$Output.html" -Encoding UTF8
            Set-RestrictedPermissions "$Output.html"
            Write-Host "HTML report: $Output.html"
        }
        'all'    {
            $reportData | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
            Set-RestrictedPermissions "$Output.json"
            ConvertTo-CsvReport $allFindings | Export-Csv "$Output.csv" -NoTypeInformation -Encoding UTF8
            Set-RestrictedPermissions "$Output.csv"
            ConvertTo-HtmlReport -Findings $allFindings -TenantId $tenantId -ScannedAt $timestamp |
                Out-File "$Output.html" -Encoding UTF8
            Set-RestrictedPermissions "$Output.html"
            Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
        }
        'stdout' { $reportData | ConvertTo-Json -Depth 10 }
        default  { Write-Error "Unknown format '$Format'"; exit 1 }
    }

    Write-TerminalSummary -Findings $allFindings -SubscriptionsScanned $totalSubscriptions
}
