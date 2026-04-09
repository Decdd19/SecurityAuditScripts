<#
.SYNOPSIS
    Audits Azure Storage Accounts for dangerous configurations.
.DESCRIPTION
    Read-only audit of Storage Accounts across one or all accessible subscriptions.
    Flags public blob access, shared key access, missing customer-managed keys,
    missing infrastructure encryption, and disabled soft delete.
.PARAMETER Output
    Output file prefix (default: storage_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER AllSubscriptions
    Scan all subscriptions accessible to the current Az context.
.EXAMPLE
    .\storage_auditor.ps1
    .\storage_auditor.ps1 -AllSubscriptions -Format html
#>
param(
    [string]$Output          = 'storage_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format          = 'all',
    [switch]$AllSubscriptions
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Az stubs — overridden by real Az module at runtime; Pester mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-AzStorageAccount' -ErrorAction SilentlyContinue)) {
    function Get-AzStorageAccount { @() }
    function New-AzStorageContext { [PSCustomObject]@{} }
    function Get-AzStorageBlobServiceProperty { [PSCustomObject]@{ DeleteRetentionPolicy = [PSCustomObject]@{ Enabled = $true; Days = 7 } } }
    function Get-AzDiagnosticSetting { param($ResourceId) @() }
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
function Get-StorageFindings {
    param(
        [Parameter(Mandatory)][PSCustomObject]$Subscription
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $accounts = @(Get-AzStorageAccount)

    foreach ($account in $accounts) {
        $base = @{
            AccountName    = $account.StorageAccountName
            ResourceGroup  = $account.ResourceGroupName
            Subscription   = $Subscription.Name
            SubscriptionId = $Subscription.Id
            Id             = $account.Id
        }

        # 1. Public blob access
        if ($account.AllowBlobPublicAccess -ne $false) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'PublicBlobAccess'
                Score          = 9
                Severity       = 'CRITICAL'
                Recommendation = "Disable public blob access: Azure Portal → Storage accounts → $($account.StorageAccountName) → Configuration → Allow Blob public access → Disabled → Save"
            } + $base))
        }

        # 2. Shared key access
        if ($account.AllowSharedKeyAccess -ne $false) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'SharedKeyAccess'
                Score          = 7
                Severity       = 'HIGH'
                Recommendation = "Disable shared key access (enforce Azure AD auth): Azure Portal → Storage accounts → $($account.StorageAccountName) → Configuration → Allow storage account key access → Disabled → Save"
            } + $base))
        }

        # 3. No customer-managed key (using Microsoft.Storage key source)
        if ($account.Encryption.KeySource -eq 'Microsoft.Storage') {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'NoCustomerManagedKey'
                Score          = 4
                Severity       = 'MEDIUM'
                Recommendation = "Enable CMK encryption: Azure Portal → Storage accounts → $($account.StorageAccountName) → Encryption → Encryption type → Customer-managed keys → select Key Vault and key → Save"
            } + $base))
        }

        # 4. No infrastructure encryption
        if ($account.Encryption.RequireInfrastructureEncryption -ne $true) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'NoInfrastructureEncryption'
                Score          = 2
                Severity       = 'LOW'
                Recommendation = "Enable infrastructure encryption (double encryption): Azure Portal → Storage accounts → $($account.StorageAccountName) → Encryption → Enable infrastructure encryption → Save (requires recreation for existing accounts)"
            } + $base))
        }

        # 5. Blob soft delete
        $blobProps = $null
        try {
            $storageCtx = New-AzStorageContext -StorageAccountName $account.StorageAccountName -UseConnectedAccount
            $blobProps = Get-AzStorageBlobServiceProperty -Context $storageCtx
        } catch {
            Write-Warning "Could not retrieve blob service properties for '$($account.StorageAccountName)': $_"
        }

        if ($null -ne $blobProps -and $blobProps.DeleteRetentionPolicy.Enabled -ne $true) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'SoftDeleteDisabled'
                Score          = 4
                Severity       = (Get-SeverityLabel 4)
                Recommendation = "Enable blob soft delete: Azure Portal → Storage accounts → $($account.StorageAccountName) → Data protection → Enable soft delete for blobs → set retention (minimum 7 days) → Save"
            } + $base))
        }

        # 6. Versioning disabled
        if ($null -ne $blobProps -and $blobProps.PSObject.Properties['IsVersioningEnabled'] -and
            $blobProps.IsVersioningEnabled -ne $true) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'VersioningDisabled'
                Score          = 3
                Severity       = (Get-SeverityLabel 3)
                Recommendation = "Enable blob versioning: Azure Portal → Storage accounts → $($account.StorageAccountName) → Data protection → Enable versioning for blobs → Save"
            } + $base))
        }

        # 7. No SAS expiry policy
        $sasPolicy = $account.PSObject.Properties['SasPolicy']
        if ($null -eq $sasPolicy -or $null -eq $account.SasPolicy -or
            $null -eq $account.SasPolicy.ExpirationAction) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'NoSasExpiryPolicy'
                Score          = 2
                Severity       = (Get-SeverityLabel 2)
                Recommendation = "Configure SAS expiry policy: Azure Portal → Storage accounts → $($account.StorageAccountName) → Configuration → SAS expiration period → set maximum allowed duration → Save"
            } + $base))
        }

        # 8. No diagnostic logging
        $resourceId = $account.Id
        if ($resourceId) {
            try {
                $diagSettings = Get-AzDiagnosticSetting -ResourceId $resourceId -ErrorAction SilentlyContinue
                if (-not $diagSettings) {
                    $findings.Add([PSCustomObject](@{
                        FindingType    = 'NoDiagnosticLogging'
                        Score          = 3
                        Severity       = (Get-SeverityLabel 3)
                        Recommendation = "Enable diagnostic logging: Azure Portal → Storage accounts → $($account.StorageAccountName) → Diagnostic settings → Add diagnostic setting → select StorageRead/Write/Delete → send to Log Analytics workspace → Save"
                    } + $base))
                }
            } catch {
                Write-Warning "Could not retrieve diagnostic settings for '$($account.StorageAccountName)': $_"
            }
        }
    }

    return [PSCustomObject]@{ Findings = $findings; AccountCount = $accounts.Count }
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
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.AccountName))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.ResourceGroup))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Subscription))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td><div class='rem-text'>&#8627; $([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</div></td>
        </tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Storage Account Audit Report</title>
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
<h1>Storage Account Audit Report</h1>
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
  <th>Account</th><th>Resource Group</th><th>Subscription</th><th>Finding</th>
  <th>Severity</th><th>Recommendation</th>
</tr></thead><tbody>
$($rows -join "`n")
</tbody></table></body></html>
"@
}

function ConvertTo-CsvReport {
    param([Parameter(Mandatory)][array]$Findings)
    $Findings | Select-Object AccountName, ResourceGroup, Subscription, SubscriptionId,
        FindingType, Score, Severity, Recommendation
}

function Write-TerminalSummary {
    param([array]$Findings, [int]$AccountsScanned)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }
    $top3 = $Findings | Sort-Object Score -Descending | Select-Object -First 3

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║        STORAGE ACCOUNT AUDIT COMPLETE            ║' -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    Write-Host "║  Accounts scanned: $($AccountsScanned.ToString().PadRight(29))║" -ForegroundColor Cyan
    Write-Host "║  Total findings  : $($Findings.Count.ToString().PadRight(29))║" -ForegroundColor Cyan
    Write-Host "║  CRITICAL: $($counts.CRITICAL)  HIGH: $($counts.HIGH)  MEDIUM: $($counts.MEDIUM)  LOW: $($counts.LOW)$((' ' * 20))║" -ForegroundColor Cyan
    Write-Host '╠══════════════════════════════════════════════════╣' -ForegroundColor Cyan
    if ($top3) {
        Write-Host '║  Top findings:                                   ║' -ForegroundColor Cyan
        foreach ($f in $top3) {
            $line = "  [$($f.Severity)] $($f.AccountName): $($f.FindingType)"
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
    $RequiredModules = @('Az.Accounts', 'Az.Storage')
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

    $allFindings     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalAccounts   = 0
    foreach ($sub in $subscriptions) {
        Write-Host "Scanning subscription: $($sub.Name) ($($sub.Id))" -ForegroundColor Gray
        Set-AzContext -SubscriptionId $sub.Id | Out-Null
        $result = Get-StorageFindings -Subscription $sub
        $allFindings.AddRange([PSCustomObject[]]$result.Findings)
        $totalAccounts += $result.AccountCount
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

    Write-TerminalSummary -Findings $allFindings -AccountsScanned $totalAccounts
}
