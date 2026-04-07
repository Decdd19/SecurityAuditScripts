# M365/mde-auditor/tests/mde_auditor.Tests.ps1
BeforeAll {
    function Connect-MgGraph { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext   { $null }
    function Get-MgDeviceManagementManagedDevice { param([switch]$All) @() }
    function Get-MgDeviceManagementManagedDeviceWindowsProtectionState { param($ManagedDeviceId) $null }
    function Get-AzContext { @{ Tenant = @{ Id = 'tid-001' }; Account = @{ Id = 'admin@contoso.com' } } }

    . "$PSScriptRoot/../mde_auditor.ps1"

    # Helper: build a Windows device stub for testing
    function New-TestDevice {
    param(
        [string]$Id             = 'dev-001',
        [string]$DeviceName     = 'LAPTOP-01',
        [string]$OS             = 'Windows',
        [bool]$IsEncrypted      = $true,
        [string]$OnboardingStatus = 'onboarded',
        [bool]$RtpEnabled       = $true,
        [bool]$TamperEnabled    = $true,
        [datetime]$LastScan     = ((Get-Date).AddDays(-1))
    )
    [PSCustomObject]@{
        Id              = $Id
        DeviceName      = $DeviceName
        OperatingSystem = $OS
        IsEncrypted     = $IsEncrypted
        OnboardingStatus = $OnboardingStatus
        UserPrincipalName = 'user@contoso.com'
        _RtpEnabled     = $RtpEnabled
        _TamperEnabled  = $TamperEnabled
        _LastScan       = $LastScan
    }
    }  # end New-TestDevice
}  # end BeforeAll

# ---------------------------------------------------------------------------
# Get-MdeOnboardingFindings  (MDE-01)
# ---------------------------------------------------------------------------
Describe 'Get-MdeOnboardingFindings' {
    It 'flags DeviceNotOnboardedToMde CRITICAL when Windows device not onboarded' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(New-TestDevice -OnboardingStatus 'notOnboarded')
        }
        $findings = Get-MdeOnboardingFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'DeviceNotOnboardedToMde' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity   | Should -Be 'CRITICAL'
        $f.Score      | Should -BeGreaterOrEqual 8
        $f.CisControl | Should -Match '^CIS'
    }

    It 'does not flag MDE-01 when all Windows devices are onboarded' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(New-TestDevice -OnboardingStatus 'onboarded')
        }
        $findings = Get-MdeOnboardingFindings
        ($findings | Where-Object { $_.FindingType -eq 'DeviceNotOnboardedToMde' }) | Should -BeNullOrEmpty
    }

    It 'skips non-Windows devices for MDE-01' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(New-TestDevice -OS 'iOS' -OnboardingStatus 'notOnboarded')
        }
        $findings = Get-MdeOnboardingFindings
        ($findings | Where-Object { $_.FindingType -eq 'DeviceNotOnboardedToMde' }) | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-MdeEncryptionFindings  (MDE-03)
# ---------------------------------------------------------------------------
Describe 'Get-MdeEncryptionFindings' {
    It 'flags DeviceNotEncrypted HIGH when Windows device has isEncrypted=false' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(New-TestDevice -IsEncrypted $false)
        }
        $findings = Get-MdeEncryptionFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'DeviceNotEncrypted' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
        $f.Resource | Should -Match 'LAPTOP-01'
    }

    It 'does not flag MDE-03 when all Windows devices are encrypted' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(New-TestDevice -IsEncrypted $true)
        }
        $findings = Get-MdeEncryptionFindings
        ($findings | Where-Object { $_.FindingType -eq 'DeviceNotEncrypted' }) | Should -BeNullOrEmpty
    }

    It 'skips non-Windows devices for MDE-03' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(New-TestDevice -OS 'Android' -IsEncrypted $false)
        }
        $findings = Get-MdeEncryptionFindings
        ($findings | Where-Object { $_.FindingType -eq 'DeviceNotEncrypted' }) | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-MdeProtectionStateFindings  (MDE-02, MDE-04, MDE-05)
# ---------------------------------------------------------------------------
Describe 'Get-MdeProtectionStateFindings — MDE-02 RealTimeProtection' {
    It 'flags RtpDisabled HIGH when realTimeProtectionEnabled is false' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(New-TestDevice -RtpEnabled $false)
        }
        Mock Get-MgDeviceManagementManagedDeviceWindowsProtectionState {
            param($ManagedDeviceId)
            $dev = (Get-MgDeviceManagementManagedDevice)[0]
            [PSCustomObject]@{
                RealTimeProtectionEnabled        = $dev._RtpEnabled
                TamperProtectionEnabled          = $dev._TamperEnabled
                AntiVirusScanLastReportedDateTime = $dev._LastScan
            }
        }
        $findings = Get-MdeProtectionStateFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'RtpDisabled' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
    }

    It 'does not flag RtpDisabled when realTimeProtectionEnabled is true' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(New-TestDevice -RtpEnabled $true)
        }
        Mock Get-MgDeviceManagementManagedDeviceWindowsProtectionState {
            param($ManagedDeviceId)
            $dev = (Get-MgDeviceManagementManagedDevice)[0]
            [PSCustomObject]@{
                RealTimeProtectionEnabled        = $dev._RtpEnabled
                TamperProtectionEnabled          = $dev._TamperEnabled
                AntiVirusScanLastReportedDateTime = $dev._LastScan
            }
        }
        $findings = Get-MdeProtectionStateFindings
        ($findings | Where-Object { $_.FindingType -eq 'RtpDisabled' }) | Should -BeNullOrEmpty
    }
}

Describe 'Get-MdeProtectionStateFindings — MDE-04 TamperProtection' {
    It 'flags TamperProtectionDisabled HIGH when tamperProtectionEnabled is false' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(New-TestDevice -TamperEnabled $false)
        }
        Mock Get-MgDeviceManagementManagedDeviceWindowsProtectionState {
            param($ManagedDeviceId)
            $dev = (Get-MgDeviceManagementManagedDevice)[0]
            [PSCustomObject]@{
                RealTimeProtectionEnabled        = $dev._RtpEnabled
                TamperProtectionEnabled          = $dev._TamperEnabled
                AntiVirusScanLastReportedDateTime = $dev._LastScan
            }
        }
        $findings = Get-MdeProtectionStateFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'TamperProtectionDisabled' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
    }

    It 'does not flag TamperProtectionDisabled when tamperProtectionEnabled is true' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(New-TestDevice -TamperEnabled $true)
        }
        Mock Get-MgDeviceManagementManagedDeviceWindowsProtectionState {
            param($ManagedDeviceId)
            $dev = (Get-MgDeviceManagementManagedDevice)[0]
            [PSCustomObject]@{
                RealTimeProtectionEnabled        = $dev._RtpEnabled
                TamperProtectionEnabled          = $dev._TamperEnabled
                AntiVirusScanLastReportedDateTime = $dev._LastScan
            }
        }
        $findings = Get-MdeProtectionStateFindings
        ($findings | Where-Object { $_.FindingType -eq 'TamperProtectionDisabled' }) | Should -BeNullOrEmpty
    }
}

Describe 'Get-MdeProtectionStateFindings — MDE-05 ScanAge' {
    It 'flags StaleAntiVirusScan MEDIUM when last scan is older than 7 days' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(New-TestDevice -LastScan ((Get-Date).AddDays(-10)))
        }
        Mock Get-MgDeviceManagementManagedDeviceWindowsProtectionState {
            param($ManagedDeviceId)
            $dev = (Get-MgDeviceManagementManagedDevice)[0]
            [PSCustomObject]@{
                RealTimeProtectionEnabled        = $dev._RtpEnabled
                TamperProtectionEnabled          = $dev._TamperEnabled
                AntiVirusScanLastReportedDateTime = $dev._LastScan
            }
        }
        $findings = Get-MdeProtectionStateFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'StaleAntiVirusScan' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'MEDIUM'
        $f.Resource | Should -Match 'LAPTOP-01'
    }

    It 'does not flag StaleAntiVirusScan when last scan is within 7 days' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(New-TestDevice -LastScan ((Get-Date).AddDays(-1)))
        }
        Mock Get-MgDeviceManagementManagedDeviceWindowsProtectionState {
            param($ManagedDeviceId)
            $dev = (Get-MgDeviceManagementManagedDevice)[0]
            [PSCustomObject]@{
                RealTimeProtectionEnabled        = $dev._RtpEnabled
                TamperProtectionEnabled          = $dev._TamperEnabled
                AntiVirusScanLastReportedDateTime = $dev._LastScan
            }
        }
        $findings = Get-MdeProtectionStateFindings
        ($findings | Where-Object { $_.FindingType -eq 'StaleAntiVirusScan' }) | Should -BeNullOrEmpty
    }

    It 'flags StaleAntiVirusScan MEDIUM when AntiVirusScanLastReportedDateTime is null (never scanned)' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(New-TestDevice)
        }
        Mock Get-MgDeviceManagementManagedDeviceWindowsProtectionState {
            param($ManagedDeviceId)
            [PSCustomObject]@{
                RealTimeProtectionEnabled        = $true
                TamperProtectionEnabled          = $true
                AntiVirusScanLastReportedDateTime = $null
            }
        }
        $findings = Get-MdeProtectionStateFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'StaleAntiVirusScan' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'MEDIUM'
    }
}

Describe 'Get-MdeProtectionStateFindings — no Windows devices' {
    It 'returns no findings when there are no Windows managed devices' {
        Mock Get-MgDeviceManagementManagedDevice {
            @(New-TestDevice -OS 'iOS')
        }
        Mock Get-MgDeviceManagementManagedDeviceWindowsProtectionState { $null }
        $findings = Get-MdeProtectionStateFindings
        $findings | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# JSON output structure
# ---------------------------------------------------------------------------
Describe 'ConvertTo-MdeJsonReport' {
    It 'produces JSON with generated_at, tenant_id, summary, findings fields' {
        $f = [PSCustomObject]@{ FindingType = 'DeviceNotEncrypted'; Resource = 'PC-01'; Severity = 'HIGH'; Score = 7; CisControl = 'CIS 10'; Recommendation = 'Enable BitLocker.' }
        $report = ConvertTo-MdeJsonReport -Findings @($f) -TenantId 'tid-001'
        $report.generated_at | Should -Not -BeNullOrEmpty
        $report.tenant_id    | Should -Be 'tid-001'
        $report.summary      | Should -Not -BeNullOrEmpty
        $report.summary.total_findings | Should -Be 1
        $report.summary.high  | Should -Be 1
        $report.findings.Count | Should -Be 1
        $report.findings[0].finding_type | Should -Be 'DeviceNotEncrypted'
    }

    It 'counts severity buckets correctly in summary' {
        $findings = @(
            [PSCustomObject]@{ FindingType = 'A'; Severity = 'CRITICAL'; Score = 9; Resource = ''; CisControl = 'CIS 10'; Recommendation = '' }
            [PSCustomObject]@{ FindingType = 'B'; Severity = 'CRITICAL'; Score = 9; Resource = ''; CisControl = 'CIS 10'; Recommendation = '' }
            [PSCustomObject]@{ FindingType = 'C'; Severity = 'HIGH';     Score = 7; Resource = ''; CisControl = 'CIS 10'; Recommendation = '' }
            [PSCustomObject]@{ FindingType = 'D'; Severity = 'MEDIUM';   Score = 5; Resource = ''; CisControl = 'CIS 10'; Recommendation = '' }
        )
        $report = ConvertTo-MdeJsonReport -Findings $findings -TenantId ''
        $report.summary.critical | Should -Be 2
        $report.summary.high     | Should -Be 1
        $report.summary.medium   | Should -Be 1
        $report.summary.low      | Should -Be 0
    }
}
