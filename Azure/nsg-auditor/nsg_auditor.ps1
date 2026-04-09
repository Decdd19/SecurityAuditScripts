<#
.SYNOPSIS
    Audits Azure Network Security Groups for dangerous configurations.
.DESCRIPTION
    Read-only audit of NSGs across one or all accessible subscriptions.
    Flags rules open to the internet on dangerous ports, orphaned NSGs,
    and NSGs with no explicit deny rules for high-risk ports.
.PARAMETER Output
    Output file prefix (default: nsg_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER AllSubscriptions
    Scan all subscriptions accessible to the current Az context.
.EXAMPLE
    .\nsg_auditor.ps1
    .\nsg_auditor.ps1 -AllSubscriptions -Format html
#>
param(
    [string]$Output          = 'nsg_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format          = 'all',
    [switch]$AllSubscriptions
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Dangerous ports
# ---------------------------------------------------------------------------
$DangerousPorts = @{
    21    = @{ Service = 'FTP';           Score = 7 }
    22    = @{ Service = 'SSH';           Score = 9 }
    23    = @{ Service = 'Telnet';        Score = 9 }
    389   = @{ Service = 'LDAP';          Score = 7 }
    445   = @{ Service = 'SMB';           Score = 9 }
    636   = @{ Service = 'LDAPS';         Score = 6 }
    1433  = @{ Service = 'SQL Server';    Score = 9 }
    2049  = @{ Service = 'NFS';           Score = 8 }
    2375  = @{ Service = 'Docker';        Score = 10 }
    2379  = @{ Service = 'etcd';          Score = 9 }
    3306  = @{ Service = 'MySQL';         Score = 8 }
    3389  = @{ Service = 'RDP';           Score = 10 }
    5432  = @{ Service = 'PostgreSQL';    Score = 8 }
    5900  = @{ Service = 'VNC';           Score = 9 }
    5985  = @{ Service = 'WinRM HTTP';    Score = 9 }
    5986  = @{ Service = 'WinRM HTTPS';   Score = 8 }
    6379  = @{ Service = 'Redis';         Score = 9 }
    9200  = @{ Service = 'Elasticsearch'; Score = 9 }
    9300  = @{ Service = 'Elasticsearch'; Score = 9 }
    27017 = @{ Service = 'MongoDB';       Score = 9 }
}

$OpenSourcePrefixes = @('*', '0.0.0.0/0', '::/0', 'Internet')

# ---------------------------------------------------------------------------
# Az stub — overridden by real Az module at runtime; Pester Mocks this
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-AzNetworkSecurityGroup' -ErrorAction SilentlyContinue)) {
    function Get-AzNetworkSecurityGroup { @() }
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
function Get-NsgFindings {
    param(
        [Parameter(Mandatory)][PSCustomObject]$Subscription
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $nsgs = @(Get-AzNetworkSecurityGroup)

    foreach ($nsg in $nsgs) {
        $base = @{
            NsgName        = $nsg.Name
            ResourceGroup  = $nsg.ResourceGroupName
            Subscription   = $Subscription.Name
            SubscriptionId = $Subscription.Id
        }

        # Orphaned NSG
        if ($nsg.NetworkInterfaces.Count -eq 0 -and $nsg.Subnets.Count -eq 0) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'Orphaned'
                Port           = $null
                SourceRange    = $null
                RuleName       = $null
                Score          = 2
                Severity       = 'LOW'
                Recommendation = "Associate NSG with subnet or NIC: Azure Portal → Network security groups → $($nsg.Name) → Subnets (or Network interfaces) → Associate → select resource → OK"
            } + $base))
        }

        # Rules open to internet on dangerous ports
        foreach ($rule in $nsg.SecurityRules) {
            if ($rule.Direction -ne 'Inbound' -or $rule.Access -ne 'Allow') { continue }
            $sourceOpen = ($rule.SourceAddressPrefix -in $OpenSourcePrefixes) -or
                          (($null -ne $rule.PSObject.Properties['SourceAddressPrefixes']) -and
                           ($null -ne $rule.SourceAddressPrefixes) -and ($rule.SourceAddressPrefixes | Where-Object { $_ -in $OpenSourcePrefixes }))
            if (-not $sourceOpen) { continue }

            $ports = @()
            if ($rule.DestinationPortRange -and $rule.DestinationPortRange -ne '*') {
                $ports += $rule.DestinationPortRange
            }
            $ports += @($rule.DestinationPortRanges)

            foreach ($dangerousPort in $DangerousPorts.Keys) {
                $matched = $false

                if ($rule.DestinationPortRange -eq '*') { $matched = $true }

                if (-not $matched) {
                    foreach ($portEntry in $ports) {
                        try { if ([int]$portEntry -eq $dangerousPort) { $matched = $true; break } } catch { }
                        if ($portEntry -match '^(\d+)-(\d+)$') {
                            if ($dangerousPort -ge [int]$Matches[1] -and $dangerousPort -le [int]$Matches[2]) {
                                $matched = $true; break
                            }
                        }
                    }
                }

                if ($matched) {
                    $portInfo = $DangerousPorts[$dangerousPort]
                    $findings.Add([PSCustomObject](@{
                        FindingType    = 'DangerousPort'
                        Port           = $dangerousPort
                        SourceRange    = $rule.SourceAddressPrefix
                        RuleName       = $rule.Name
                        Score          = $portInfo.Score
                        Severity       = (Get-SeverityLabel $portInfo.Score)
                        Recommendation = "Restrict $($portInfo.Service) (port $dangerousPort) to known source IPs or use Azure Bastion: Azure Portal → Network security groups → $($nsg.Name) → Inbound security rules → select rule → Source → IP Addresses → enter allowed CIDRs → Save. Consider Azure Bastion for SSH/RDP instead."
                    } + $base))
                }
            }
        }

        # NSG with no explicit inbound deny rules (weak posture)
        $hasDenyRule = $nsg.SecurityRules | Where-Object {
            $_.Direction -eq 'Inbound' -and $_.Access -eq 'Deny'
        }
        if (-not $hasDenyRule) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'NoDenyRules'
                Port           = $null
                SourceRange    = $null
                RuleName       = $null
                Score          = 3
                Severity       = 'MEDIUM'
                Recommendation = "Add explicit deny rules: Azure Portal → Network security groups → $($nsg.Name) → Inbound security rules → Add → Priority 4096 → Source: Any → Destination: Any → Action: Deny → Save"
            } + $base))
        }
    }
    return [PSCustomObject]@{ Findings = $findings; NsgCount = $nsgs.Count }
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function ConvertTo-HtmlReport {
    param(
        [Parameter(Mandatory)][array]$Findings,
        [string]$TenantId = '',
        [string]$ScannedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
    )
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    $rows = foreach ($f in $Findings) {
        $colour = Get-SeverityColour $f.Severity
        $port = if ($null -ne $f.Port) { $f.Port } else { '-' }
        $rule = if ($f.RuleName) { [System.Web.HttpUtility]::HtmlEncode($f.RuleName) } else { '-' }
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.NsgName))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.ResourceGroup))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Subscription))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
            <td>$port</td>
            <td>$rule</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td><div class='rem-text'>&#8627; $([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</div></td>
        </tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>NSG Audit Report</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f6fa;color:#333}
  .header{background:#1a1a2e;color:#fff;padding:30px 40px}
  .header h1{margin:0;font-size:1.8em}
  .header p{margin:5px 0 0;opacity:0.8}
  .summary{display:flex;gap:20px;padding:20px 40px;flex-wrap:wrap}
  .card{background:#fff;border-radius:8px;padding:20px 30px;flex:1;min-width:140px;box-shadow:0 2px 8px rgba(0,0,0,0.08);text-align:center}
  .card .num{font-size:2.5em;font-weight:bold}.card .lbl{color:#666;font-size:.85em;margin-top:4px}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08)}
  th{background:#1a1a2e;color:#fff;padding:12px 15px;text-align:left;font-size:0.85em;text-transform:uppercase;letter-spacing:0.5px}
  td{padding:10px 15px;border-bottom:1px solid #ecf0f1;vertical-align:top}tr:last-child td{border-bottom:none}tr:hover td{background:#f8f9ff}
  code{background:#ecf0f1;padding:2px 5px;border-radius:3px;font-size:0.85em}
  .footer{text-align:center;padding:20px;color:#999;font-size:0.85em}
  .rem-text { display: block; font-size: 0.78em; color: #555; padding-left: 12px; font-style: italic; margin-top: 4px; }
</style></head><body>
<div class='header'>
<h1>NSG Audit Report</h1>
<p>Tenant: $TenantId &nbsp;|&nbsp; Generated: $ScannedAt</p>
</div>
<div class='summary'>
  <div class='card'><div class='num'>$($Findings.Count)</div><div class='lbl'>Total Findings</div></div>
  <div class='card'><div class='num' style='color:#dc3545'>$($counts.CRITICAL)</div><div class='lbl'>CRITICAL</div></div>
  <div class='card'><div class='num' style='color:#fd7e14'>$($counts.HIGH)</div><div class='lbl'>HIGH</div></div>
  <div class='card'><div class='num' style='color:#ffc107'>$($counts.MEDIUM)</div><div class='lbl'>MEDIUM</div></div>
  <div class='card'><div class='num' style='color:#28a745'>$($counts.LOW)</div><div class='lbl'>LOW</div></div>
</div>
<table><thead><tr>
  <th>NSG</th><th>Resource Group</th><th>Subscription</th><th>Finding</th>
  <th>Port</th><th>Rule</th><th>Severity</th><th>Recommendation</th>
</tr></thead><tbody>
$($rows -join "`n")
</tbody></table></body></html>
"@
}

function ConvertTo-CsvReport {
    param([Parameter(Mandatory)][array]$Findings)
    $Findings | Select-Object NsgName, ResourceGroup, Subscription, SubscriptionId,
        FindingType, Port, SourceRange, RuleName, Score, Severity, Recommendation
}

function Write-TerminalSummary {
    param([array]$Findings, [int]$NsgsScanned)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }
    $top3 = $Findings | Sort-Object Score -Descending | Select-Object -First 3

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║           NSG AUDIT COMPLETE                     ║' -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    Write-Host "║  NSGs scanned  : $($NsgsScanned.ToString().PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  Total findings: $($Findings.Count.ToString().PadRight(31))║" -ForegroundColor Cyan
    Write-Host "║  CRITICAL: $($counts.CRITICAL)  HIGH: $($counts.HIGH)  MEDIUM: $($counts.MEDIUM)  LOW: $($counts.LOW)$((' ' * 20))║" -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    if ($top3) {
        Write-Host '║  Top findings:                                   ║' -ForegroundColor Cyan
        foreach ($f in $top3) {
            $line = "  [$($f.Severity)] $($f.NsgName): $($f.FindingType)"
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
    $RequiredModules = @('Az.Accounts', 'Az.Network')
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

    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalNsgs   = 0
    foreach ($sub in $subscriptions) {
        Write-Host "Scanning subscription: $($sub.Name) ($($sub.Id))" -ForegroundColor Gray
        Set-AzContext -SubscriptionId $sub.Id | Out-Null
        $result = Get-NsgFindings -Subscription $sub
        $allFindings.AddRange([PSCustomObject[]]$result.Findings)
        $totalNsgs += $result.NsgCount
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
        default { Write-Error "Unknown format '$Format'"; exit 1 }
    }

    Write-TerminalSummary -Findings $allFindings -NsgsScanned $totalNsgs
}
