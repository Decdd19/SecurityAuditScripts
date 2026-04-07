# Azure/hybrid-auditor/tests/hybrid_auditor.Tests.ps1
BeforeAll {
    function Connect-MgGraph { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext   { $null }
    function Get-MgOrganization { @() }
    function Invoke-MgGraphRequest { param($Uri, $Method) @{ value = @() } }
    function Get-AzContext { @{ Tenant = @{ Id = 'tid-001' }; Account = @{ Id = 'admin@contoso.com' } } }

    . "$PSScriptRoot/../hybrid_auditor.ps1"

    # Helper: build a sync-enabled organisation stub
    function New-TestOrg {
        param(
            [bool]$SyncEnabled       = $true,
            [datetime]$LastSync      = ((Get-Date).AddHours(-1))
        )
        [PSCustomObject]@{
            Id                          = 'org-001'
            OnPremisesSyncEnabled       = $SyncEnabled
            OnPremisesLastSyncDateTime  = $LastSync
        }
    }

    # Helper: build a sync-config hashtable (returned by Invoke-MgGraphRequest)
    function New-TestSyncConfig {
        param(
            [bool]$PhsEnabled       = $true,
            [bool]$WritebackEnabled = $true,
            [bool]$SsoEnabled       = $true,
            [bool]$AccDelEnabled    = $true,
            [int]$AccDelThreshold   = 500
        )
        @{
            value = @(
                @{
                    features = @{
                        passwordHashSyncEnabled    = $PhsEnabled
                        passwordWritebackEnabled   = $WritebackEnabled
                        seamlessSsoEnabled         = $SsoEnabled
                    }
                    configuration = @{
                        accidentalDeletionPrevention = @{
                            enabled        = $AccDelEnabled
                            alertThreshold = $AccDelThreshold
                        }
                    }
                }
            )
        }
    }
}  # end BeforeAll

# ---------------------------------------------------------------------------
# Cloud-only tenant guard
# ---------------------------------------------------------------------------
Describe 'Cloud-only tenant guard' {
    It 'emits CloudOnlyTenant INFO finding when onPremisesSyncEnabled is false' {
        Mock Get-MgOrganization { @(New-TestOrg -SyncEnabled $false) }
        $findings = Get-HybridCloudOnlyGuard
        $f = $findings | Where-Object { $_.FindingType -eq 'CloudOnlyTenant' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'INFO'
    }

    It 'returns empty when onPremisesSyncEnabled is true' {
        Mock Get-MgOrganization { @(New-TestOrg -SyncEnabled $true) }
        $findings = Get-HybridCloudOnlyGuard
        $findings | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-HybridSyncStatusFindings  (HA-01)
# ---------------------------------------------------------------------------
Describe 'Get-HybridSyncStatusFindings' {
    It 'flags SyncStale CRITICAL when last sync is older than 3 hours' {
        Mock Get-MgOrganization { @(New-TestOrg -LastSync ((Get-Date).AddHours(-5))) }
        $findings = Get-HybridSyncStatusFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'SyncStale' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'CRITICAL'
        $f.Score    | Should -BeGreaterOrEqual 8
        $f.CisControl | Should -Match '^CIS'
    }

    It 'flags SyncStale CRITICAL when OnPremisesLastSyncDateTime is null' {
        $org = [PSCustomObject]@{
            Id                         = 'org-001'
            OnPremisesSyncEnabled      = $true
            OnPremisesLastSyncDateTime = $null
        }
        Mock Get-MgOrganization { @($org) }
        $findings = Get-HybridSyncStatusFindings
        ($findings | Where-Object { $_.FindingType -eq 'SyncStale' }) | Should -Not -BeNullOrEmpty
    }

    It 'does not flag SyncStale when last sync is recent (under 3 hours)' {
        Mock Get-MgOrganization { @(New-TestOrg -LastSync ((Get-Date).AddHours(-1))) }
        $findings = Get-HybridSyncStatusFindings
        ($findings | Where-Object { $_.FindingType -eq 'SyncStale' }) | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-HybridSyncFeatureFindings  (HA-02, HA-03, HA-05)
# ---------------------------------------------------------------------------
Describe 'Get-HybridSyncFeatureFindings — PasswordHashSync (HA-02)' {
    It 'flags PasswordHashSyncDisabled MEDIUM when PHS is disabled' {
        Mock Invoke-MgGraphRequest { New-TestSyncConfig -PhsEnabled $false }
        $findings = Get-HybridSyncFeatureFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'PasswordHashSyncDisabled' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'MEDIUM'
    }

    It 'does not flag PasswordHashSyncDisabled when PHS is enabled' {
        Mock Invoke-MgGraphRequest { New-TestSyncConfig -PhsEnabled $true }
        $findings = Get-HybridSyncFeatureFindings
        ($findings | Where-Object { $_.FindingType -eq 'PasswordHashSyncDisabled' }) | Should -BeNullOrEmpty
    }
}

Describe 'Get-HybridSyncFeatureFindings — PasswordWriteback (HA-03)' {
    It 'flags PasswordWritebackDisabled MEDIUM when writeback is disabled' {
        Mock Invoke-MgGraphRequest { New-TestSyncConfig -WritebackEnabled $false }
        $findings = Get-HybridSyncFeatureFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'PasswordWritebackDisabled' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'MEDIUM'
    }

    It 'does not flag PasswordWritebackDisabled when writeback is enabled' {
        Mock Invoke-MgGraphRequest { New-TestSyncConfig -WritebackEnabled $true }
        $findings = Get-HybridSyncFeatureFindings
        ($findings | Where-Object { $_.FindingType -eq 'PasswordWritebackDisabled' }) | Should -BeNullOrEmpty
    }
}

Describe 'Get-HybridSyncFeatureFindings — SeamlessSso (HA-05)' {
    It 'flags SeamlessSsoNotEnabled LOW when seamless SSO is disabled' {
        Mock Invoke-MgGraphRequest { New-TestSyncConfig -SsoEnabled $false }
        $findings = Get-HybridSyncFeatureFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'SeamlessSsoNotEnabled' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'LOW'
    }

    It 'does not flag SeamlessSsoNotEnabled when seamless SSO is enabled' {
        Mock Invoke-MgGraphRequest { New-TestSyncConfig -SsoEnabled $true }
        $findings = Get-HybridSyncFeatureFindings
        ($findings | Where-Object { $_.FindingType -eq 'SeamlessSsoNotEnabled' }) | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-HybridSyncConfigFindings  (HA-04)
# ---------------------------------------------------------------------------
Describe 'Get-HybridSyncConfigFindings — AccidentalDeletionPrevention (HA-04)' {
    It 'flags AccidentalDeletionPreventionDisabled HIGH when protection is disabled' {
        Mock Invoke-MgGraphRequest { New-TestSyncConfig -AccDelEnabled $false }
        $findings = Get-HybridSyncConfigFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'AccidentalDeletionPreventionDisabled' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
        $f.Score    | Should -BeGreaterOrEqual 6
    }

    It 'does not flag AccidentalDeletionPreventionDisabled when protection is enabled' {
        Mock Invoke-MgGraphRequest { New-TestSyncConfig -AccDelEnabled $true }
        $findings = Get-HybridSyncConfigFindings
        ($findings | Where-Object { $_.FindingType -eq 'AccidentalDeletionPreventionDisabled' }) | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# ConvertTo-HybridJsonReport
# ---------------------------------------------------------------------------
Describe 'ConvertTo-HybridJsonReport' {
    It 'produces object with generated_at, tenant_id, summary, findings fields' {
        $f = [PSCustomObject]@{ FindingType = 'SyncStale'; Resource = 'tenant'; Severity = 'CRITICAL'; Score = 9; CisControl = 'CIS 5'; Recommendation = 'Fix sync.' }
        $report = ConvertTo-HybridJsonReport -Findings @($f) -TenantId 'tid-001'
        $report.generated_at              | Should -Not -BeNullOrEmpty
        $report.tenant_id                 | Should -Be 'tid-001'
        $report.summary                   | Should -Not -BeNullOrEmpty
        $report.summary.total_findings    | Should -Be 1
        $report.summary.critical          | Should -Be 1
        $report.findings.Count            | Should -Be 1
        $report.findings[0].finding_type  | Should -Be 'SyncStale'
    }

    It 'counts INFO severity findings in total_findings but not in risk buckets' {
        $findings = @(
            [PSCustomObject]@{ FindingType = 'CloudOnlyTenant'; Severity = 'INFO'; Score = 0; Resource = 'tenant'; CisControl = 'N/A'; Recommendation = '' }
        )
        $report = ConvertTo-HybridJsonReport -Findings $findings -TenantId ''
        $report.summary.total_findings | Should -Be 1
        $report.summary.critical       | Should -Be 0
        $report.summary.high           | Should -Be 0
    }
}
