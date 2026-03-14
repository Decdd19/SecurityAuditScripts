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
                Recommendation = "Disable public blob access on storage account '$($account.StorageAccountName)' to prevent anonymous data exposure."
            } + $base))
        }

        # 2. Shared key access
        if ($account.AllowSharedKeyAccess -ne $false) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'SharedKeyAccess'
                Score          = 7
                Severity       = 'HIGH'
                Recommendation = "Disable shared key access on '$($account.StorageAccountName)' and use Azure AD authentication instead."
            } + $base))
        }

        # 3. No customer-managed key (using Microsoft.Storage key source)
        if ($account.Encryption.KeySource -eq 'Microsoft.Storage') {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'NoCustomerManagedKey'
                Score          = 4
                Severity       = 'MEDIUM'
                Recommendation = "Configure customer-managed keys (CMK) via Azure Key Vault for storage account '$($account.StorageAccountName)'."
            } + $base))
        }

        # 4. No infrastructure encryption
        if ($account.Encryption.RequireInfrastructureEncryption -ne $true) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'NoInfrastructureEncryption'
                Score          = 2
                Severity       = 'LOW'
                Recommendation = "Enable infrastructure encryption on '$($account.StorageAccountName)' for double encryption at rest."
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
                Recommendation = "Enable blob soft delete on '$($account.StorageAccountName)' to allow recovery from accidental deletions."
            } + $base))
        }

        # 6. Versioning disabled
        if ($null -ne $blobProps -and $blobProps.PSObject.Properties['IsVersioningEnabled'] -and
            $blobProps.IsVersioningEnabled -ne $true) {
            $findings.Add([PSCustomObject](@{
                FindingType    = 'VersioningDisabled'
                Score          = 3
                Severity       = (Get-SeverityLabel 3)
                Recommendation = "Enable blob versioning on '$($account.StorageAccountName)' to protect against accidental overwrites."
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
                Recommendation = "Configure a SAS expiry policy on '$($account.StorageAccountName)' to enforce maximum SAS token lifetime."
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
                        Recommendation = "Storage account '$($account.StorageAccountName)' has no diagnostic settings. Enable logging to capture read/write/delete operations."
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
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</td>
        </tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Storage Account Audit Report</title>
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
<h1>Storage Account Audit Report</h1>
<p class='meta'>Tenant: $TenantId &nbsp;|&nbsp; Generated: $ScannedAt</p>
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
        $subscriptions = @(Get-AzSubscription -SubscriptionId $azContext.Subscription.Id)
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

    Write-TerminalSummary -Findings $allFindings -AccountsScanned $totalAccounts
}
