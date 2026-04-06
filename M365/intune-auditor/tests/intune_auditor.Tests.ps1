# M365/intune-auditor/tests/intune_auditor.Tests.ps1
BeforeAll {
    function Connect-MgGraph { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext   { $null }
    function Get-MgDeviceManagementDeviceCompliancePolicy { @() }
    function Get-MgDeviceManagementManagedDevice          { param([switch]$All) @() }
    function Get-MgIdentityConditionalAccessPolicy        { @() }
    function Get-MgDeviceManagementDeviceEnrollmentConfiguration { @() }
    function Get-AzContext { @{ Tenant = @{ Id = 'tid-001' }; Account = @{ Id = 'admin@contoso.com' } } }

    . "$PSScriptRoot/../intune_auditor.ps1"
}

# ---------------------------------------------------------------------------
# Get-IntuneCompliancePolicyFindings
# ---------------------------------------------------------------------------

Describe 'Get-IntuneCompliancePolicyFindings' {
    It 'flags IN-01 for a platform with no compliance policy' {
        Mock Get-MgDeviceManagementDeviceCompliancePolicy { @() }
        $findings = Get-IntuneCompliancePolicyFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'MissingCompliancePolicy' }
        $f | Should -Not -BeNullOrEmpty
        $f.Count | Should -BeGreaterOrEqual 1
        $f[0].Severity | Should -Be 'HIGH'
        $f[0].CisControl | Should -Match '^CIS'
    }

    It 'does not flag IN-01 when all four platforms have a compliance policy' {
        Mock Get-MgDeviceManagementDeviceCompliancePolicy {
            @(
                [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; GracePeriodInMinutes = 0 }
                [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.iosCompliancePolicy';       GracePeriodInMinutes = 0 }
                [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.androidCompliancePolicy';   GracePeriodInMinutes = 0 }
                [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.macOSCompliancePolicy';     GracePeriodInMinutes = 0 }
            )
        }
        $findings = Get-IntuneCompliancePolicyFindings
        ($findings | Where-Object { $_.FindingType -eq 'MissingCompliancePolicy' }) | Should -BeNullOrEmpty
    }

    It 'flags IN-02 when grace period exceeds 1440 minutes (24h)' {
        Mock Get-MgDeviceManagementDeviceCompliancePolicy {
            @(
                [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; GracePeriodInMinutes = 2880 }
                [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.iosCompliancePolicy';       GracePeriodInMinutes = 0 }
                [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.androidCompliancePolicy';   GracePeriodInMinutes = 0 }
                [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.macOSCompliancePolicy';     GracePeriodInMinutes = 0 }
            )
        }
        $findings = Get-IntuneCompliancePolicyFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'ComplianceGracePeriodTooLong' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
    }
}

# ---------------------------------------------------------------------------
# Get-IntuneDeviceAccessFindings
# ---------------------------------------------------------------------------

Describe 'Get-IntuneDeviceAccessFindings' {
    It 'flags IN-03 when no CA policy requires device compliance' {
        Mock Get-MgIdentityConditionalAccessPolicy { @() }
        $findings = Get-IntuneDeviceAccessFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'NoCaDeviceComplianceEnforcement' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'CRITICAL'
    }

    It 'does not flag IN-03 when an enabled CA policy requires compliantDevice' {
        Mock Get-MgIdentityConditionalAccessPolicy {
            @([PSCustomObject]@{
                State         = 'enabled'
                GrantControls = [PSCustomObject]@{ BuiltInControls = @('compliantDevice') }
            })
        }
        $findings = Get-IntuneDeviceAccessFindings
        ($findings | Where-Object { $_.FindingType -eq 'NoCaDeviceComplianceEnforcement' }) | Should -BeNullOrEmpty
    }

    It 'flags IN-04 when non-compliant managed devices exist' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(
                [PSCustomObject]@{ DeviceName = 'LAPTOP-01'; ComplianceState = 'noncompliant'; UserPrincipalName = 'alice@contoso.com' }
                [PSCustomObject]@{ DeviceName = 'PHONE-01';  ComplianceState = 'compliant';    UserPrincipalName = 'bob@contoso.com'   }
            )
        }
        $findings = Get-IntuneDeviceAccessFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'UnmanagedDevicesAccessingM365' }
        $f | Should -Not -BeNullOrEmpty
        $f.Resource | Should -Match 'LAPTOP-01'
    }

    It 'does not flag IN-04 when all devices are compliant' {
        Mock Get-MgDeviceManagementManagedDevice {
            @([PSCustomObject]@{ DeviceName = 'LAPTOP-01'; ComplianceState = 'compliant'; UserPrincipalName = 'alice@contoso.com' })
        }
        $findings = Get-IntuneDeviceAccessFindings
        ($findings | Where-Object { $_.FindingType -eq 'UnmanagedDevicesAccessingM365' }) | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-IntuneEnrollmentFindings
# ---------------------------------------------------------------------------

Describe 'Get-IntuneEnrollmentFindings' {
    It 'flags IN-05 when no Windows auto-enrollment configuration exists' {
        Mock Get-MgDeviceManagementDeviceEnrollmentConfiguration {
            @([PSCustomObject]@{ '@odata.type' = '#microsoft.graph.deviceEnrollmentLimitConfiguration' })
        }
        $findings = Get-IntuneEnrollmentFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'WindowsAutoEnrollmentNotConfigured' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'MEDIUM'
    }

    It 'does not flag IN-05 when Windows auto-enrollment config exists' {
        Mock Get-MgDeviceManagementDeviceEnrollmentConfiguration {
            @([PSCustomObject]@{ '@odata.type' = '#microsoft.graph.windowsAutoEnrollmentConfiguration' })
        }
        $findings = Get-IntuneEnrollmentFindings
        ($findings | Where-Object { $_.FindingType -eq 'WindowsAutoEnrollmentNotConfigured' }) | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# License gate
# ---------------------------------------------------------------------------
Describe 'License gate' {
    It 'emits IntuneNotLicensed INFO finding and exits cleanly when Graph returns 403' {
        # Override the stub so it throws a 403-style error
        Mock Get-MgDeviceManagementDeviceCompliancePolicy {
            throw [System.Exception]::new('403 Forbidden: Intune license not found')
        }
        # Capture output — script writes to $Output files; check JSON contains the finding
        $tmpPrefix = Join-Path $TestDrive 'intune_nolicense'
        & "$PSScriptRoot/../intune_auditor.ps1" -Output $tmpPrefix -Format json -TenantDomain 'contoso.com'
        $json = Get-Content "$tmpPrefix.json" -Raw | ConvertFrom-Json
        $json.findings[0].FindingType | Should -Be 'IntuneNotLicensed'
        $json.findings[0].Severity   | Should -Be 'INFO'
    }
}
