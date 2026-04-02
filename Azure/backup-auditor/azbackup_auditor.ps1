<#
.SYNOPSIS
    Audits Azure Backup Recovery Services vaults for dangerous configurations.
.DESCRIPTION
    Read-only audit of Recovery Services vaults across one or all accessible
    subscriptions. Flags missing vaults, disabled soft delete, disabled
    immutability, and recent backup job failures.
.PARAMETER Output
    Output file prefix (default: azbackup_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER AllSubscriptions
    Scan all subscriptions accessible to the current Az context.
.EXAMPLE
    .\azbackup_auditor.ps1
    .\azbackup_auditor.ps1 -AllSubscriptions -Format html
    .\azbackup_auditor.ps1 -Format json
#>
param(
    [string]$Output          = 'azbackup_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format          = 'all',
    [switch]$AllSubscriptions
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Az stubs -- overridden by real Az module at runtime; Pester mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-AzContext' -ErrorAction SilentlyContinue)) {
    function Get-AzContext { @{ Subscription = @{ Id = 'sub-001'; Name = 'TestSub' }; Tenant = @{ Id = 'tenant-001' } } }
}
if (-not (Get-Command -Name 'Get-AzSubscription' -ErrorAction SilentlyContinue)) {
    function Get-AzSubscription { param($SubscriptionId) @() }
}
if (-not (Get-Command -Name 'Set-AzContext' -ErrorAction SilentlyContinue)) {
    function Set-AzContext { param($SubscriptionId) }
}
if (-not (Get-Command -Name 'Get-AzRecoveryServicesVault' -ErrorAction SilentlyContinue)) {
    function Get-AzRecoveryServicesVault { @() }
}
if (-not (Get-Command -Name 'Set-AzRecoveryServicesVaultContext' -ErrorAction SilentlyContinue)) {
    function Set-AzRecoveryServicesVaultContext { param($Vault) }
}
if (-not (Get-Command -Name 'Get-AzRecoveryServicesBackupProperty' -ErrorAction SilentlyContinue)) {
    function Get-AzRecoveryServicesBackupProperty { param($Vault) @{ BackupStorageRedundancy = 'GeoRedundant'; SoftDeleteFeatureState = 'Enabled' } }
}
if (-not (Get-Command -Name 'Get-AzRecoveryServicesVaultProperty' -ErrorAction SilentlyContinue)) {
    function Get-AzRecoveryServicesVaultProperty { param($Vault) @{ ImmutabilityState = 'Disabled' } }
}
if (-not (Get-Command -Name 'Get-AzRecoveryServicesBackupJob' -ErrorAction SilentlyContinue)) {
    function Get-AzRecoveryServicesBackupJob { param($VaultId) @() }
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
function Get-BackupFindings {
    param(
        [Parameter(Mandatory)][PSCustomObject]$Subscription
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $vaults   = @(Get-AzRecoveryServicesVault)

    # Check 1: No vaults found at all
    if ($vaults.Count -eq 0) {
        $findings.Add([PSCustomObject]@{
            FindingType      = 'NoVaults'
            Resource         = 'Subscription'
            Severity         = (Get-SeverityLabel 7)
            Score            = [int]7
            Description      = 'No Azure Backup Recovery Services vaults found'
            Recommendation   = "Create a Recovery Services vault: Azure Portal -> Recovery Services vaults -> Create -> select subscription and resource group -> provide vault name -> Review + Create."
            SubscriptionId   = $Subscription.Id
            SubscriptionName = $Subscription.Name
        })
        return [PSCustomObject]@{ Findings = $findings; VaultCount = 0 }
    }

    foreach ($vault in $vaults) {
        # Set vault context for subsequent calls
        Set-AzRecoveryServicesVaultContext -Vault $vault

        # Check 2: Soft delete disabled
        try {
            $backupProps = Get-AzRecoveryServicesBackupProperty -Vault $vault
            if ($backupProps.SoftDeleteFeatureState -ne 'Enabled') {
                $findings.Add([PSCustomObject]@{
                    FindingType      = 'SoftDeleteDisabled'
                    Resource         = $vault.Name
                    Severity         = (Get-SeverityLabel 7)
                    Score            = [int]7
                    Description      = "Soft delete disabled on vault '$($vault.Name)' -- backups can be permanently deleted"
                    Recommendation   = "Enable soft delete: Azure Portal -> Recovery Services vaults -> $($vault.Name) -> Properties -> Soft Delete -> Enable soft delete for cloud workloads -> Save."
                    SubscriptionId   = $Subscription.Id
                    SubscriptionName = $Subscription.Name
                })
            }
        } catch {
            Write-Warning "Could not retrieve backup properties for vault '$($vault.Name)': $_"
        }

        # Check 3: Immutability disabled
        try {
            $vaultProps = Get-AzRecoveryServicesVaultProperty -Vault $vault
            if ($vaultProps.ImmutabilityState -eq 'Disabled') {
                $findings.Add([PSCustomObject]@{
                    FindingType      = 'ImmutabilityDisabled'
                    Resource         = $vault.Name
                    Severity         = (Get-SeverityLabel 4)
                    Score            = [int]4
                    Description      = "Vault immutability not enabled on '$($vault.Name)'"
                    Recommendation   = "Enable immutability: Azure Portal -> Recovery Services vaults -> $($vault.Name) -> Properties -> Immutability -> Enable -> Save. Consider locking immutability for irreversible protection."
                    SubscriptionId   = $Subscription.Id
                    SubscriptionName = $Subscription.Name
                })
            }
        } catch {
            Write-Warning "Could not retrieve vault properties for vault '$($vault.Name)': $_"
        }

        # Check 4: Recent backup failures (last 24 hours)
        try {
            $jobs = @(Get-AzRecoveryServicesBackupJob -VaultId $vault.ID)
            $cutoff = (Get-Date).AddHours(-24)
            $recentFailures = @($jobs | Where-Object { $_.Status -eq 'Failed' -and $_.StartTime -gt $cutoff })
            if ($recentFailures.Count -gt 0) {
                $findings.Add([PSCustomObject]@{
                    FindingType      = 'RecentBackupFailure'
                    Resource         = $vault.Name
                    Severity         = (Get-SeverityLabel 7)
                    Score            = [int]7
                    Description      = "Backup job failures in last 24h on vault '$($vault.Name)'"
                    Recommendation   = "Investigate failed backup jobs: Azure Portal -> Recovery Services vaults -> $($vault.Name) -> Backup Jobs -> filter by Failed status -> review error details and retry."
                    SubscriptionId   = $Subscription.Id
                    SubscriptionName = $Subscription.Name
                })
            }
        } catch {
            Write-Warning "Could not retrieve backup jobs for vault '$($vault.Name)': $_"
        }
    }

    return [PSCustomObject]@{ Findings = $findings; VaultCount = $vaults.Count }
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
        $colour  = Get-SeverityColour $f.Severity
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Resource))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.SubscriptionName))</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td>$($f.Score)/10</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Description))</td>
            <td><div class='rem-text'>&#8627; $([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</div></td>
        </tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Azure Backup Audit Report</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f6fa;color:#333}
  .header{background:#1a1a2e;color:#fff;padding:30px 40px}
  .header h1{margin:0;font-size:1.8em}.header p{margin:5px 0 0;opacity:0.8}
  .content{padding:24px 40px}
  .summary{display:flex;gap:20px;flex-wrap:wrap;margin-bottom:24px}
  .card{background:#fff;border-radius:8px;padding:20px 30px;box-shadow:0 2px 8px rgba(0,0,0,0.08);min-width:140px;text-align:center}
  .card .num{font-size:2.5em;font-weight:bold}.card .lbl{color:#666;font-size:.85em;margin-top:4px}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);margin-bottom:24px}
  th{background:#1a1a2e;color:#fff;padding:12px 15px;text-align:left;font-size:0.85em;text-transform:uppercase;letter-spacing:0.5px}
  td{padding:10px 15px;border-bottom:1px solid #ecf0f1;vertical-align:top}tr:last-child td{border-bottom:none}tr:hover td{background:#f8f9ff}
  .rem-text{display:block;font-size:.78em;color:#555;padding-left:12px;font-style:italic;margin-top:4px}
  .footer{text-align:center;padding:20px;color:#999;font-size:0.85em}
</style></head><body>
<div class='header'>
<h1>&#128274; Azure Backup Audit Report</h1>
<p>Scanned: $ScannedAt$(if ($TenantId) { " &bull; Tenant: $([System.Web.HttpUtility]::HtmlEncode($TenantId))" })</p>
</div>
<div class='content'>
<div class='summary'>
  <div class='card'><div class='num' style='color:#dc3545'>$($counts.CRITICAL)</div><div class='lbl'>CRITICAL</div></div>
  <div class='card'><div class='num' style='color:#fd7e14'>$($counts.HIGH)</div><div class='lbl'>HIGH</div></div>
  <div class='card'><div class='num' style='color:#ffc107'>$($counts.MEDIUM)</div><div class='lbl'>MEDIUM</div></div>
  <div class='card'><div class='num' style='color:#28a745'>$($counts.LOW)</div><div class='lbl'>LOW</div></div>
  <div class='card'><div class='num'>$($Findings.Count)</div><div class='lbl'>Total Findings</div></div>
</div>
$(if ($Findings.Count -eq 0) { "<p>&#10003; No Azure Backup findings.</p>" } else {
"<table>
  <thead><tr>
    <th>Resource</th><th>Finding</th><th>Subscription</th>
    <th>Severity</th><th>Score</th><th>Description</th><th>Recommendation</th>
  </tr></thead>
  <tbody>$($rows -join '')</tbody>
</table>"
})
</div>
<div class='footer'>Generated by Azure Backup Auditor</div>
</body></html>
"@
}

function ConvertTo-JsonReport {
    param([array]$Findings, [string]$TenantId = '', [int]$VaultCount = 0)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    return @{
        generated_at    = (Get-Date).ToUniversalTime().ToString('o')
        tenant_id       = $TenantId
        vaults_scanned  = $VaultCount
        summary         = @{
            total_findings = $Findings.Count
            critical       = $counts.CRITICAL
            high           = $counts.HIGH
            medium         = $counts.MEDIUM
            low            = $counts.LOW
        }
        findings        = @($Findings | ForEach-Object {
            @{
                finding_type      = $_.FindingType
                resource          = $_.Resource
                severity          = $_.Severity
                severity_score    = $_.Score
                description       = $_.Description
                recommendation    = $_.Recommendation
                subscription_id   = $_.SubscriptionId
                subscription_name = $_.SubscriptionName
            }
        })
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
function Invoke-Audit {
    param([switch]$AllSubscriptions)

    $ctx         = Get-AzContext
    $tenantId    = $ctx.Tenant.Id
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalVaults = 0

    if ($AllSubscriptions) {
        $subs = @(Get-AzSubscription)
        foreach ($sub in $subs) {
            Set-AzContext -SubscriptionId $sub.Id | Out-Null
            $result = Get-BackupFindings -Subscription $sub
            foreach ($f in $result.Findings) { $allFindings.Add($f) }
            $totalVaults += $result.VaultCount
        }
    } else {
        $sub    = [PSCustomObject]@{ Id = $ctx.Subscription.Id; Name = $ctx.Subscription.Name }
        $result = Get-BackupFindings -Subscription $sub
        foreach ($f in $result.Findings) { $allFindings.Add($f) }
        $totalVaults = $result.VaultCount
    }

    return @{
        TenantId    = $tenantId
        Findings    = $allFindings.ToArray()
        VaultCount  = $totalVaults
    }
}

# ---------------------------------------------------------------------------
# Entry point (skipped when dot-sourced by Pester)
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    $result     = Invoke-Audit -AllSubscriptions:$AllSubscriptions
    $findings   = $result.Findings
    $tenantId   = $result.TenantId
    $vaultCount = $result.VaultCount

    if ($Format -eq 'stdout') {
        ConvertTo-JsonReport -Findings $findings -TenantId $tenantId -VaultCount $vaultCount | ConvertTo-Json -Depth 10
        exit 0
    }

    if ($Format -in @('html','all')) {
        $html = ConvertTo-HtmlReport -Findings $findings -TenantId $tenantId
        $htmlPath = "$Output.html"
        $html | Out-File -FilePath $htmlPath -Encoding utf8
        Write-Host "HTML report: $htmlPath"
    }

    if ($Format -in @('json','all')) {
        $jsonReport = ConvertTo-JsonReport -Findings $findings -TenantId $tenantId -VaultCount $vaultCount
        $jsonPath = "$Output.json"
        $jsonReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
        Write-Host "JSON report: $jsonPath"
    }

    if ($Format -in @('csv','all')) {
        $csvPath = "$Output.csv"
        $findings | Select-Object Resource, FindingType, Severity, Score, Description, Recommendation, SubscriptionId, SubscriptionName |
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
        Write-Host "CSV report: $csvPath"
    }
}
