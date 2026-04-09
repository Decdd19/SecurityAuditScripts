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
if (-not (Get-Command -Name 'Get-AzDiagnosticSetting' -ErrorAction SilentlyContinue)) {
    function Get-AzDiagnosticSetting { param($ResourceId) @() }
    function Get-AzActivityLogAlert { @() }
    function Get-AzOperationalInsightsWorkspace { param($ResourceGroupName, $Name) $null }
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
            Recommendation = 'Create activity log diagnostic setting: Azure Portal → Monitor → Activity log → Export Activity Logs → Add diagnostic setting → select all categories → send to Log Analytics workspace → Save'
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
                    Recommendation = 'Configure a destination for the diagnostic setting: Azure Portal → Monitor → Activity log → Export Activity Logs → select the setting → Edit → add Log Analytics workspace, storage account, or Event Hub → Save'
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
                        Recommendation = "Enable the '$cat' category: Azure Portal → Monitor → Activity log → Export Activity Logs → select '$($diag.Name)' → Edit → enable '$cat' log category → Save"
                    } + $base))
                }
            }

            # Check 4: Short retention on storage account destination
            if ($hasStorage) {
                $minDays = $null
                foreach ($log in $diag.Logs) {
                    if ($null -ne $log.RetentionPolicy -and $log.RetentionPolicy.Enabled) {
                        $days = $log.RetentionPolicy.Days
                        if ($days -ne 0 -and ($null -eq $minDays -or $days -lt $minDays)) {
                            $minDays = $days
                        }
                    }
                }
                if ($null -ne $minDays -and $minDays -ne 0 -and $minDays -lt 90) {
                    $findings.Add([PSCustomObject](@{
                        FindingType    = 'ShortRetention'
                        DiagSettingName = $diag.Name
                        Detail         = "Retention is $minDays days (minimum 90)"
                        Score          = 5
                        Severity       = 'MEDIUM'
                        Recommendation = "Increase retention: Azure Portal → Monitor → Activity log → Export Activity Logs → $($diag.Name) → edit → set Retention to 365 days → Save"
                    } + $base))
                }
            }

            # Log Analytics workspace retention check (best-effort)
            if ($hasWorkspace) {
                $workspaceId = $diag.WorkspaceId
                try {
                    if (Get-Command Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue) {
                        # Parse workspace resource group and name from the resource ID
                        if ($workspaceId -match '/resourceGroups/([^/]+)/providers/Microsoft\.OperationalInsights/workspaces/([^/]+)') {
                            $wsRg   = $Matches[1]
                            $wsName = $Matches[2]
                            $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $wsRg -Name $wsName -ErrorAction SilentlyContinue
                            if ($workspace -and $workspace.retentionInDays -lt 90) {
                                $findings.Add([PSCustomObject](@{
                                    FindingType    = 'WorkspaceRetentionShort'
                                    DiagSettingName = $diag.Name
                                    Detail         = "Log Analytics workspace '$wsName' retention is $($workspace.retentionInDays) days (minimum 90)"
                                    Score          = 4
                                    Severity       = (Get-SeverityLabel 4)
                                    Recommendation = "Create Log Analytics workspace: Azure Portal → Log Analytics workspaces → Create → choose subscription/RG/region → Review + Create"
                                } + $base))
                            }
                        }
                    }
                } catch {
                    Write-Warning "Could not check Log Analytics workspace retention for '$workspaceId': $_"
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
                    Recommendation = "Verify Event Hub retention: Azure Portal → Event Hubs → [namespace] → [hub] → Properties → Message Retention → set to 7 days minimum; also ensure downstream consumers archive to long-term storage (minimum 90 days)"
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
            Recommendation = 'Create activity log alert: Azure Portal → Monitor → Alerts → Create → Alert rule → Signal type: Activity log → select critical operation (e.g. Delete Policy Assignment) → set Action Group → Create'
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
            <td><div class='rem-text'>&#8627; $([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</div></td>
        </tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Activity Log Audit Report</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f6fa;color:#333}
  .header{background:#1a1a2e;color:#fff;padding:30px 40px}
  .header h1{margin:0;font-size:1.8em}
  .header p{margin:5px 0 0;opacity:0.8}
  .content{padding:24px 32px}
  .summary{display:flex;gap:16px;margin-bottom:24px}
  .card{background:#fff;border-radius:8px;padding:16px 24px;box-shadow:0 2px 8px rgba(0,0,0,0.08);min-width:120px;text-align:center}
  .card .num{font-size:2em;font-weight:bold}.card .lbl{color:#666;font-size:.85em}
  table{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 2px 8px rgba(0,0,0,0.08)}
  th{background:#1a1a2e;color:#fff;padding:10px;text-align:left}
  td{padding:8px 10px;border-bottom:1px solid #dee2e6}tr:hover{background:#f1f3f5}
  .meta{color:#666;font-size:.85em;margin-bottom:16px}
  .rem-text { display: block; font-size: 0.78em; color: #555; padding-left: 12px; font-style: italic; margin-top: 4px; }
</style></head><body>
<div class='header'>
<h1>Activity Log Audit Report</h1>
<p>Tenant: $TenantId &nbsp;|&nbsp; Generated: $ScannedAt</p>
</div>
<div class='content'>
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
</tbody></table>
</div></body></html>
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
        $subscriptions = if ($azContext.Subscription) { @(Get-AzSubscription -SubscriptionId $azContext.Subscription.Id) } else { @(Get-AzSubscription) }
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
            critical = @($allFindings | Where-Object Severity -eq 'CRITICAL').Count
            high     = @($allFindings | Where-Object Severity -eq 'HIGH').Count
            medium   = @($allFindings | Where-Object Severity -eq 'MEDIUM').Count
            low      = @($allFindings | Where-Object Severity -eq 'LOW').Count
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
