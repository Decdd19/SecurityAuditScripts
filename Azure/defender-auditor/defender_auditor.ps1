<#
.SYNOPSIS
    Audits Microsoft Defender for Cloud configuration.
.DESCRIPTION
    Read-only audit of Defender for Cloud (Security Center) across one or all
    accessible subscriptions. Checks: Defender plan enablement per resource type,
    security contacts, auto-provisioning of monitoring agents, and secure score.
.PARAMETER Output
    Output file prefix (default: defender_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER AllSubscriptions
    Scan all subscriptions accessible to the current Az context.
.EXAMPLE
    .\defender_auditor.ps1
    .\defender_auditor.ps1 -AllSubscriptions -Format html
#>
param(
    [string]$Output          = 'defender_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format          = 'all',
    [switch]$AllSubscriptions
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Az stubs — overridden by real Az module at runtime; Pester mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-AzSecurityPricing' -ErrorAction SilentlyContinue)) {
    function Get-AzSecurityPricing                 { @() }
    function Get-AzSecurityContact                 { @() }
    function Get-AzSecurityAutoProvisioningSetting { @() }
    function Get-AzSecuritySecureScore             { @() }
}
if (-not (Get-Command -Name 'Get-AzContext' -ErrorAction SilentlyContinue)) {
    function Get-AzContext    { @{ Subscription = @{ Id = 'sub-001'; Name = 'TestSub' }; Tenant = @{ Id = 'tenant-001' } } }
    function Get-AzSubscription { param($SubscriptionId) @{ Id = $SubscriptionId; Name = 'TestSub' } }
    function Set-AzContext    { }
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
function Get-DefenderFindings {
    param([Parameter(Mandatory)][PSCustomObject]$Subscription)

    $findings        = [System.Collections.Generic.List[PSCustomObject]]::new()
    $subscriptionId  = $Subscription.Id
    $subscriptionName = $Subscription.Name

    # --- Defender Plans ---
    $IMPORTANT_PLANS = @('VirtualMachines','SqlServers','StorageAccounts','AppServices','KeyVaults','Containers','Arm')
    $pricings = @(Get-AzSecurityPricing)

    foreach ($plan in $IMPORTANT_PLANS) {
        $pricing = $pricings | Where-Object { $_.Name -eq $plan }
        $enabled = ($null -ne $pricing) -and ($pricing.PricingTier -eq 'Standard')
        if (-not $enabled) {
            $findings.Add([PSCustomObject]@{
                FindingType      = 'DefenderPlanDisabled'
                Resource         = $plan
                Severity         = 'HIGH'
                Score            = 7
                Description      = "Defender for $plan is not enabled (Free tier)"
                Recommendation   = "Enable in Azure Portal → Microsoft Defender for Cloud → Environment settings → Defender plans → enable $plan"
                SubscriptionId   = $subscriptionId
                SubscriptionName = $subscriptionName
            })
        }
    }

    # --- Security Contact ---
    $contacts = @(Get-AzSecurityContact)
    if (-not $contacts -or ($contacts | Measure-Object).Count -eq 0) {
        $findings.Add([PSCustomObject]@{
            FindingType      = 'NoSecurityContact'
            Resource         = 'Security Contacts'
            Severity         = 'MEDIUM'
            Score            = 5
            Description      = 'No security contact email configured'
            Recommendation   = 'Configure in Azure Portal → Defender for Cloud → Environment settings → Email notifications'
            SubscriptionId   = $subscriptionId
            SubscriptionName = $subscriptionName
        })
    }

    # --- Auto-provisioning ---
    $autoProvision = @(Get-AzSecurityAutoProvisioningSetting)
    $mmaAgent = $autoProvision | Where-Object { $_.Name -eq 'mma-agent' }
    if ($mmaAgent -and $mmaAgent.AutoProvision -eq 'Off') {
        $findings.Add([PSCustomObject]@{
            FindingType      = 'AutoProvisioningOff'
            Resource         = 'MMA Agent'
            Severity         = 'MEDIUM'
            Score            = 4
            Description      = 'Auto-provisioning of Log Analytics agent is disabled'
            Recommendation   = 'Enable in Azure Portal → Defender for Cloud → Environment settings → Auto provisioning → Log Analytics agent → On'
            SubscriptionId   = $subscriptionId
            SubscriptionName = $subscriptionName
        })
    }

    # --- Secure Score ---
    $scores       = @(Get-AzSecuritySecureScore)
    $defaultScore = $scores | Where-Object { $_.Name -eq 'ascScore' } | Select-Object -First 1
    $scoreValue   = if ($defaultScore) { [math]::Round($defaultScore.SecureScore, 1) } else { $null }
    $maxScore     = if ($defaultScore) { [math]::Round($defaultScore.MaxSecureScore, 1) } else { $null }

    if ($defaultScore -and $defaultScore.Percentage -lt 0.5) {
        $findings.Add([PSCustomObject]@{
            FindingType      = 'LowSecureScore'
            Resource         = 'Secure Score'
            Severity         = 'HIGH'
            Score            = 7
            Description      = "Secure Score is below 50% ($([math]::Round($defaultScore.Percentage * 100, 0))%)"
            Recommendation   = 'Review and remediate high-impact recommendations in Defender for Cloud → Recommendations'
            SubscriptionId   = $subscriptionId
            SubscriptionName = $subscriptionName
        })
    }

    return [PSCustomObject]@{
        SubscriptionId    = $subscriptionId
        SubscriptionName  = $subscriptionName
        Findings          = $findings
        SecureScore       = $scoreValue
        MaxSecureScore    = $maxScore
        TotalPlansChecked = $IMPORTANT_PLANS.Count
        PlansEnabled      = ($IMPORTANT_PLANS | Where-Object {
            $p = $_
            ($pricings | Where-Object { $_.Name -eq $p -and $_.PricingTier -eq 'Standard' }) -ne $null
        } | Measure-Object).Count
    }
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function ConvertTo-HtmlReport {
    param(
        [Parameter(Mandatory)][array]$Results,
        [string]$TenantId  = '',
        [string]$ScannedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
    )

    $allFindings = @($Results | ForEach-Object { $_.Findings } | Where-Object { $_ -ne $null })
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $allFindings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    $rows = foreach ($f in $allFindings) {
        $colour = Get-SeverityColour $f.Severity
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.SubscriptionName))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Resource))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td>$($f.Score)/10</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Description))</td>
            <td><div class='rem-text'>&#8627; $([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</div></td>
        </tr>"
    }

    $scoreRows = foreach ($r in $Results) {
        $scoreDisplay = if ($null -ne $r.SecureScore) { "$($r.SecureScore) / $($r.MaxSecureScore)" } else { 'N/A' }
        "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($r.SubscriptionName))</td><td>$([System.Web.HttpUtility]::HtmlEncode($r.SubscriptionId))</td><td>$($r.PlansEnabled)/$($r.TotalPlansChecked)</td><td>$scoreDisplay</td><td>$(($r.Findings | Measure-Object).Count)</td></tr>"
    }

    return @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Defender for Cloud Audit Report</title>
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
  <h1>&#128737; Microsoft Defender for Cloud Audit Report</h1>
  <p>Scanned: $ScannedAt$(if ($TenantId) { " &bull; Tenant: $([System.Web.HttpUtility]::HtmlEncode($TenantId))" })</p>
</div>
<div class='content'>
<div class='summary'>
  <div class='card'><div class='num' style='color:#dc3545'>$($counts.CRITICAL)</div><div class='lbl'>CRITICAL</div></div>
  <div class='card'><div class='num' style='color:#fd7e14'>$($counts.HIGH)</div><div class='lbl'>HIGH</div></div>
  <div class='card'><div class='num' style='color:#ffc107'>$($counts.MEDIUM)</div><div class='lbl'>MEDIUM</div></div>
  <div class='card'><div class='num' style='color:#28a745'>$($counts.LOW)</div><div class='lbl'>LOW</div></div>
  <div class='card'><div class='num'>$($allFindings.Count)</div><div class='lbl'>Total Findings</div></div>
</div>
<h2>Subscription Summary</h2>
<table>
  <thead><tr><th>Subscription</th><th>ID</th><th>Plans Enabled</th><th>Secure Score</th><th>Findings</th></tr></thead>
  <tbody>$($scoreRows -join '')</tbody>
</table>
$(if ($allFindings.Count -eq 0) { "<p>&#10003; No Defender for Cloud findings.</p>" } else {
"<h2>Findings</h2>
<table>
  <thead><tr>
    <th>Subscription</th><th>Resource</th><th>Finding</th><th>Severity</th><th>Score</th><th>Description</th><th>Recommendation</th>
  </tr></thead>
  <tbody>$($rows -join '')</tbody>
</table>"
})
</div>
</body></html>
"@
}

function ConvertTo-JsonReport {
    param(
        [Parameter(Mandatory)][array]$Results,
        [string]$TenantId = ''
    )

    $allFindings = @($Results | ForEach-Object { $_.Findings } | Where-Object { $_ -ne $null })
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $allFindings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    return @{
        GeneratedAt = (Get-Date).ToUniversalTime().ToString('o')
        TenantId    = $TenantId
        Summary     = @{
            TotalFindings     = $allFindings.Count
            Critical          = $counts.CRITICAL
            High              = $counts.HIGH
            Medium            = $counts.MEDIUM
            Low               = $counts.LOW
        }
        Subscriptions = @($Results | ForEach-Object {
            @{
                SubscriptionId    = $_.SubscriptionId
                SubscriptionName  = $_.SubscriptionName
                PlansEnabled      = $_.PlansEnabled
                TotalPlansChecked = $_.TotalPlansChecked
                SecureScore       = $_.SecureScore
                MaxSecureScore    = $_.MaxSecureScore
                FindingsCount     = ($_.Findings | Measure-Object).Count
            }
        })
        Findings    = @($allFindings | ForEach-Object {
            @{
                FindingType      = $_.FindingType
                Resource         = $_.Resource
                Severity         = $_.Severity
                Score            = $_.Score
                Description      = $_.Description
                Recommendation   = $_.Recommendation
                SubscriptionId   = $_.SubscriptionId
                SubscriptionName = $_.SubscriptionName
            }
        })
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
function Invoke-Audit {
    param([switch]$AllSubscriptions)

    $ctx     = Get-AzContext
    $tenantId = $ctx.Tenant.Id
    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($AllSubscriptions) {
        $subs = @(Get-AzSubscription)
        foreach ($sub in $subs) {
            Set-AzContext -SubscriptionId $sub.Id | Out-Null
            $result = Get-DefenderFindings -Subscription ([PSCustomObject]@{ Id = $sub.Id; Name = $sub.Name })
            $allResults.Add($result)
        }
    } else {
        $sub    = [PSCustomObject]@{ Id = $ctx.Subscription.Id; Name = $ctx.Subscription.Name }
        $result = Get-DefenderFindings -Subscription $sub
        $allResults.Add($result)
    }

    return @{
        TenantId = $tenantId
        Results  = $allResults.ToArray()
    }
}

# ---------------------------------------------------------------------------
# Entry point (skipped when dot-sourced by Pester)
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    $audit    = Invoke-Audit -AllSubscriptions:$AllSubscriptions
    $results  = $audit.Results
    $tenantId = $audit.TenantId
    $allFindings = @($results | ForEach-Object { $_.Findings } | Where-Object { $_ -ne $null })

    if ($Format -eq 'stdout') {
        ConvertTo-JsonReport -Results $results -TenantId $tenantId | ConvertTo-Json -Depth 10
        exit 0
    }

    if ($Format -in @('html','all')) {
        $html     = ConvertTo-HtmlReport -Results $results -TenantId $tenantId
        $htmlPath = "$Output.html"
        $html | Out-File -FilePath $htmlPath -Encoding utf8
        Write-Host "HTML report: $htmlPath"
    }

    if ($Format -in @('json','all')) {
        $jsonReport = ConvertTo-JsonReport -Results $results -TenantId $tenantId
        $jsonPath   = "$Output.json"
        $jsonReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
        Write-Host "JSON report: $jsonPath"
    }

    if ($Format -in @('csv','all')) {
        $csvPath = "$Output.csv"
        $allFindings | Select-Object SubscriptionName, SubscriptionId, Resource, FindingType, Severity, Score, Description, Recommendation |
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
        Write-Host "CSV report: $csvPath"
    }
}
