<#
.SYNOPSIS
    Audits Azure Key Vaults for dangerous configurations and expiring secrets.
.DESCRIPTION
    Read-only audit of Key Vaults across one or all accessible subscriptions.
    Flags access policy model (legacy vault access vs RBAC), missing purge
    protection, missing soft delete, secrets/certificates/keys expiring within
    30 days or already expired, and missing diagnostic logging.
.PARAMETER Output
    Output file prefix (default: keyvault_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER AllSubscriptions
    Scan all subscriptions accessible to the current Az context.
.PARAMETER ExpiryWarningDays
    Flag secrets/certs/keys expiring within this many days (default: 30).
.EXAMPLE
    .\keyvault_auditor.ps1
    .\keyvault_auditor.ps1 -AllSubscriptions -Format html
    .\keyvault_auditor.ps1 -ExpiryWarningDays 60
#>
param(
    [string]$Output          = 'keyvault_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format          = 'all',
    [switch]$AllSubscriptions,
    [int]$ExpiryWarningDays  = 30
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Az stubs — overridden by real Az module at runtime; Pester mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-AzKeyVault' -ErrorAction SilentlyContinue)) {
    function Get-AzKeyVault                { param($VaultName) @() }
    function Get-AzKeyVaultSecret          { param($VaultName) @() }
    function Get-AzKeyVaultCertificate     { param($VaultName) @() }
    function Get-AzKeyVaultKey             { param($VaultName) @() }
    function Get-AzDiagnosticSetting       { param($ResourceId) @() }
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
# Expiry helper
# ---------------------------------------------------------------------------
function Get-ExpiryFinding {
    param(
        [string]$ItemName,
        [string]$VaultName,
        [string]$ItemType,   # Secret | Certificate | Key
        [datetime]$ExpiryDate,
        [string]$ResourceGroup,
        [string]$Subscription,
        [string]$SubscriptionId,
        [int]$WarningDays
    )
    $now = [datetime]::UtcNow
    $daysLeft = ($ExpiryDate - $now).Days

    if ($daysLeft -lt 0) {
        return [PSCustomObject]@{
            FindingType    = "${ItemType}Expired"
            VaultName      = $VaultName
            ItemName       = $ItemName
            ResourceGroup  = $ResourceGroup
            Subscription   = $Subscription
            SubscriptionId = $SubscriptionId
            Score          = 9
            Severity       = 'CRITICAL'
            Recommendation = "${ItemType} '$ItemName' in vault '$VaultName' EXPIRED $([Math]::Abs($daysLeft)) day(s) ago. " +
                             "Rotate immediately: Azure Portal → Key vaults → $VaultName → $($ItemType)s → $ItemName → New version."
        }
    }

    if ($daysLeft -le $WarningDays) {
        $score = if ($daysLeft -le 7) { 8 } elseif ($daysLeft -le 14) { 6 } else { 4 }
        $sev   = Get-SeverityLabel $score
        return [PSCustomObject]@{
            FindingType    = "${ItemType}ExpiringSoon"
            VaultName      = $VaultName
            ItemName       = $ItemName
            ResourceGroup  = $ResourceGroup
            Subscription   = $Subscription
            SubscriptionId = $SubscriptionId
            Score          = $score
            Severity       = $sev
            Recommendation = "${ItemType} '$ItemName' in vault '$VaultName' expires in $daysLeft day(s) ($($ExpiryDate.ToString('yyyy-MM-dd'))). " +
                             "Rotate before expiry: Azure Portal → Key vaults → $VaultName → $($ItemType)s → $ItemName → New version."
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Audit function
# ---------------------------------------------------------------------------
function Get-KeyVaultFindings {
    param(
        [Parameter(Mandatory)][PSCustomObject]$Subscription,
        [int]$ExpiryWarningDays = 30
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $vaults   = @(Get-AzKeyVault)

    foreach ($vault in $vaults) {
        $base = @{
            VaultName      = $vault.VaultName
            ResourceGroup  = $vault.ResourceGroupName
            Subscription   = $Subscription.Name
            SubscriptionId = $Subscription.Id
        }

        # 1. Legacy access policy model (not RBAC)
        #    EnableRbacAuthorization = $false or not set means vault access policies
        if ($vault.EnableRbacAuthorization -ne $true) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'LegacyAccessPolicyModel'
                ItemName       = ''
                Score          = 6
                Severity       = 'HIGH'
                Recommendation = "Migrate to Azure RBAC authorization: Azure Portal → Key vaults → $($vault.VaultName) → Access configuration → Permission model → Azure role-based access control → Apply. " +
                                 "Assign Key Vault roles to identities and remove legacy access policies after migration."
            } + $base))
        }

        # 2. Purge protection disabled
        if ($vault.EnablePurgeProtection -ne $true) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'PurgeProtectionDisabled'
                ItemName       = ''
                Score          = 7
                Severity       = 'HIGH'
                Recommendation = "Enable purge protection: Azure Portal → Key vaults → $($vault.VaultName) → Properties → Purge protection → Enable → Save. " +
                                 "Prevents permanent deletion of vault and secrets during retention period. Note: cannot be disabled once enabled."
            } + $base))
        }

        # 3. Soft delete disabled (older vaults; new vaults have it on by default since 2020)
        if ($vault.EnableSoftDelete -eq $false) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'SoftDeleteDisabled'
                ItemName       = ''
                Score          = 8
                Severity       = 'CRITICAL'
                Recommendation = "Enable soft delete: Azure Portal → Key vaults → $($vault.VaultName) → Properties → Soft delete → Enable → Save. " +
                                 "Required to use purge protection. Soft-deleted objects are recoverable for the retention period (default 90 days)."
            } + $base))
        }

        # 4. No diagnostic logging
        $resourceId = $vault.ResourceId
        if ($resourceId) {
            try {
                $diagSettings = Get-AzDiagnosticSetting -ResourceId $resourceId -ErrorAction SilentlyContinue
                if (-not $diagSettings) {
                    $findings.Add([PSCustomObject](@{
                        FindingType    = 'NoDiagnosticLogging'
                        ItemName       = ''
                        Score          = 5
                        Severity       = (Get-SeverityLabel 5)
                        Recommendation = "Enable diagnostic logging: Azure Portal → Key vaults → $($vault.VaultName) → Diagnostic settings → Add diagnostic setting → select AuditEvent and AllMetrics → send to Log Analytics workspace → Save."
                    } + $base))
                }
            } catch {
                Write-Warning "Could not retrieve diagnostic settings for vault '$($vault.VaultName)': $_"
            }
        }

        # 5. Secrets expiry
        try {
            $secrets = @(Get-AzKeyVaultSecret -VaultName $vault.VaultName)
            foreach ($secret in $secrets) {
                if ($null -ne $secret.Expires) {
                    $finding = Get-ExpiryFinding -ItemName $secret.Name -VaultName $vault.VaultName `
                        -ItemType 'Secret' -ExpiryDate $secret.Expires `
                        -ResourceGroup $vault.ResourceGroupName `
                        -Subscription $Subscription.Name -SubscriptionId $Subscription.Id `
                        -WarningDays $ExpiryWarningDays
                    if ($null -ne $finding) { $findings.Add($finding) }
                }
            }
        } catch {
            Write-Warning "Could not list secrets for vault '$($vault.VaultName)': $_"
        }

        # 6. Certificates expiry
        try {
            $certs = @(Get-AzKeyVaultCertificate -VaultName $vault.VaultName)
            foreach ($cert in $certs) {
                if ($null -ne $cert.Expires) {
                    $finding = Get-ExpiryFinding -ItemName $cert.Name -VaultName $vault.VaultName `
                        -ItemType 'Certificate' -ExpiryDate $cert.Expires `
                        -ResourceGroup $vault.ResourceGroupName `
                        -Subscription $Subscription.Name -SubscriptionId $Subscription.Id `
                        -WarningDays $ExpiryWarningDays
                    if ($null -ne $finding) { $findings.Add($finding) }
                }
            }
        } catch {
            Write-Warning "Could not list certificates for vault '$($vault.VaultName)': $_"
        }

        # 7. Keys expiry
        try {
            $keys = @(Get-AzKeyVaultKey -VaultName $vault.VaultName)
            foreach ($key in $keys) {
                if ($null -ne $key.Expires) {
                    $finding = Get-ExpiryFinding -ItemName $key.Name -VaultName $vault.VaultName `
                        -ItemType 'Key' -ExpiryDate $key.Expires `
                        -ResourceGroup $vault.ResourceGroupName `
                        -Subscription $Subscription.Name -SubscriptionId $Subscription.Id `
                        -WarningDays $ExpiryWarningDays
                    if ($null -ne $finding) { $findings.Add($finding) }
                }
            }
        } catch {
            Write-Warning "Could not list keys for vault '$($vault.VaultName)': $_"
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
        $item    = if ($f.ItemName) { [System.Web.HttpUtility]::HtmlEncode($f.ItemName) } else { '—' }
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.VaultName))</td>
            <td>$item</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.ResourceGroup))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Subscription))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td>$($f.Score)/10</td>
            <td><div class='rem-text'>&#8627; $([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</div></td>
        </tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Key Vault Audit Report</title>
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
  .rem-text{display:block;font-size:.78em;color:#555;padding-left:12px;font-style:italic;margin-top:4px}
</style></head><body>
<div class='header'>
<h1>&#128273; Key Vault Audit Report</h1>
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
$(if ($Findings.Count -eq 0) { "<p>&#10003; No Key Vault findings.</p>" } else {
"<table>
  <thead><tr>
    <th>Vault</th><th>Item</th><th>Resource Group</th><th>Subscription</th>
    <th>Finding</th><th>Severity</th><th>Score</th><th>Recommendation</th>
  </tr></thead>
  <tbody>$($rows -join '')</tbody>
</table>"
})
</div>
</body></html>
"@
}

function ConvertTo-JsonReport {
    param([array]$Findings, [string]$TenantId = '', [int]$VaultCount = 0)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    return @{
        generated_at  = (Get-Date).ToUniversalTime().ToString('o')
        tenant_id     = $TenantId
        vaults_scanned = $VaultCount
        summary       = @{
            total_findings = $Findings.Count
            critical       = $counts.CRITICAL
            high           = $counts.HIGH
            medium         = $counts.MEDIUM
            low            = $counts.LOW
        }
        findings      = @($Findings | ForEach-Object {
            @{
                finding_type    = $_.FindingType
                vault_name      = $_.VaultName
                item_name       = $_.ItemName
                resource_group  = $_.ResourceGroup
                subscription    = $_.Subscription
                subscription_id = $_.SubscriptionId
                risk_level      = $_.Severity
                severity_score  = $_.Score
                recommendation  = $_.Recommendation
            }
        })
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
function Invoke-Audit {
    param([switch]$AllSubscriptions, [int]$ExpiryWarningDays = 30)

    $ctx       = Get-AzContext
    $tenantId  = $ctx.Tenant.Id
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalVaults = 0

    if ($AllSubscriptions) {
        $subs = @(Get-AzSubscription)
        foreach ($sub in $subs) {
            Set-AzContext -SubscriptionId $sub.Id | Out-Null
            $result = Get-KeyVaultFindings -Subscription $sub -ExpiryWarningDays $ExpiryWarningDays
            foreach ($f in $result.Findings) { $allFindings.Add($f) }
            $totalVaults += $result.VaultCount
        }
    } else {
        $sub    = [PSCustomObject]@{ Id = $ctx.Subscription.Id; Name = $ctx.Subscription.Name }
        $result = Get-KeyVaultFindings -Subscription $sub -ExpiryWarningDays $ExpiryWarningDays
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
    $result   = Invoke-Audit -AllSubscriptions:$AllSubscriptions -ExpiryWarningDays $ExpiryWarningDays
    $findings = $result.Findings
    $tenantId = $result.TenantId
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
        $findings | Select-Object VaultName, ItemName, ResourceGroup, Subscription, FindingType, Severity, Score, Recommendation |
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
        Write-Host "CSV report: $csvPath"
    }
}
