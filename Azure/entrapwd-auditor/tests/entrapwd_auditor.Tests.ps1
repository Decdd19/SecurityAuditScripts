# Azure/entrapwd-auditor/tests/entrapwd_auditor.Tests.ps1
BeforeAll {
    # Stub all Graph cmdlets so the script loads without real modules installed.
    # Individual It blocks override with Mock as needed.
    function Get-MgDomain { @() }
    function Get-MgBetaDirectorySetting { @() }
    function Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy { $null }
    function Invoke-MgGraphRequest { param($Uri, $Method) @{} }
    function Connect-MgGraph { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext { $null }

    . "$PSScriptRoot/../entrapwd_auditor.ps1"
}

# ---------------------------------------------------------------------------
# Get-PasswordExpiryFindings
# ---------------------------------------------------------------------------
Describe 'Get-PasswordExpiryFindings' {
    It 'emits EP-01 MEDIUM finding when domain has expiry set' {
        Mock Get-MgDomain {
            @([PSCustomObject]@{ Id = 'contoso.com'; PasswordValidityPeriodInDays = 90 })
        }
        $findings = Get-PasswordExpiryFindings
        $findings | Should -HaveCount 1
        $findings[0].FindingType | Should -Be 'PasswordExpiryEnabled'
        $findings[0].Severity    | Should -Be 'MEDIUM'
        $findings[0].Domain      | Should -Be 'contoso.com'
        $findings[0].Score       | Should -Be 4
    }

    It 'emits no finding when PasswordValidityPeriodInDays is null' {
        Mock Get-MgDomain {
            @([PSCustomObject]@{ Id = 'contoso.com'; PasswordValidityPeriodInDays = $null })
        }
        $findings = Get-PasswordExpiryFindings
        $findings | Should -BeNullOrEmpty
    }

    It 'only flags expiry-enabled domains when multiple domains exist' {
        Mock Get-MgDomain {
            @(
                [PSCustomObject]@{ Id = 'a.com'; PasswordValidityPeriodInDays = 90   }
                [PSCustomObject]@{ Id = 'b.com'; PasswordValidityPeriodInDays = $null }
            )
        }
        $findings = Get-PasswordExpiryFindings
        $findings | Should -HaveCount 1
        $findings[0].Domain | Should -Be 'a.com'
    }
}

# ---------------------------------------------------------------------------
# Get-SsprFindings
# ---------------------------------------------------------------------------
Describe 'Get-SsprFindings' {
    It 'emits EP-02 HIGH finding when SSPR is disabled' {
        Mock Invoke-MgGraphRequest {
            @{ defaultUserRolePermissions = @{ allowedToUseSSPR = $false } }
        }
        $findings = Get-SsprFindings
        $findings | Should -HaveCount 1
        $findings[0].FindingType | Should -Be 'SsprDisabled'
        $findings[0].Severity    | Should -Be 'HIGH'
        $findings[0].Score       | Should -Be 6
    }

    It 'emits no finding when SSPR is enabled' {
        Mock Invoke-MgGraphRequest {
            @{ defaultUserRolePermissions = @{ allowedToUseSSPR = $true } }
        }
        $findings = Get-SsprFindings
        $findings | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-SmartLockoutFindings
# ---------------------------------------------------------------------------
Describe 'Get-SmartLockoutFindings' {
    It 'emits EP-03 MEDIUM finding when lockoutThreshold exceeds 10' {
        Mock Get-MgBetaDirectorySetting {
            @([PSCustomObject]@{
                DisplayName = 'Password Rule Settings'
                Values = @(
                    [PSCustomObject]@{ Name = 'lockoutThreshold';         Value = '15' }
                    [PSCustomObject]@{ Name = 'lockoutDurationInSeconds'; Value = '60' }
                )
            })
        }
        $findings = Get-SmartLockoutFindings
        $f = $findings | Where-Object { $_.Detail -match 'threshold' }
        $f              | Should -Not -BeNullOrEmpty
        $f.FindingType  | Should -Be 'SmartLockoutPermissive'
        $f.Severity     | Should -Be 'MEDIUM'
    }

    It 'emits EP-03 MEDIUM finding when lockoutDurationInSeconds is under 60' {
        Mock Get-MgBetaDirectorySetting {
            @([PSCustomObject]@{
                DisplayName = 'Password Rule Settings'
                Values = @(
                    [PSCustomObject]@{ Name = 'lockoutThreshold';         Value = '10' }
                    [PSCustomObject]@{ Name = 'lockoutDurationInSeconds'; Value = '30' }
                )
            })
        }
        $findings = Get-SmartLockoutFindings
        $f = $findings | Where-Object { $_.Detail -match 'duration' }
        $f             | Should -Not -BeNullOrEmpty
        $f.FindingType | Should -Be 'SmartLockoutPermissive'
    }

    It 'emits no finding when threshold and duration are within bounds' {
        Mock Get-MgBetaDirectorySetting {
            @([PSCustomObject]@{
                DisplayName = 'Password Rule Settings'
                Values = @(
                    [PSCustomObject]@{ Name = 'lockoutThreshold';         Value = '5'   }
                    [PSCustomObject]@{ Name = 'lockoutDurationInSeconds'; Value = '120' }
                )
            })
        }
        $findings = Get-SmartLockoutFindings
        $findings | Should -BeNullOrEmpty
    }

    It 'emits no finding when password rule settings are not configured' {
        Mock Get-MgBetaDirectorySetting { @() }
        $findings = Get-SmartLockoutFindings
        $findings | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-SecurityDefaultsFindings
# ---------------------------------------------------------------------------
Describe 'Get-SecurityDefaultsFindings' {
    It 'emits EP-04 HIGH finding when security defaults are disabled' {
        Mock Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy {
            [PSCustomObject]@{ IsEnabled = $false }
        }
        $findings = Get-SecurityDefaultsFindings
        $findings | Should -HaveCount 1
        $findings[0].FindingType | Should -Be 'SecurityDefaultsDisabled'
        $findings[0].Severity    | Should -Be 'HIGH'
        $findings[0].Score       | Should -Be 7
    }

    It 'emits no finding when security defaults are enabled' {
        Mock Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy {
            [PSCustomObject]@{ IsEnabled = $true }
        }
        $findings = Get-SecurityDefaultsFindings
        $findings | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-CustomBannedPasswordFindings
# ---------------------------------------------------------------------------
Describe 'Get-CustomBannedPasswordFindings' {
    It 'emits EP-05 LOW finding when banned password check is disabled' {
        Mock Get-MgBetaDirectorySetting {
            @([PSCustomObject]@{
                DisplayName = 'Password Rule Settings'
                Values = @(
                    [PSCustomObject]@{ Name = 'enableBannedPasswordCheck'; Value = 'false'   }
                    [PSCustomObject]@{ Name = 'banPasswordList';                     Value = 'contoso' }
                )
            })
        }
        $findings = Get-CustomBannedPasswordFindings
        $findings | Should -HaveCount 1
        $findings[0].FindingType | Should -Be 'CustomBannedPasswordsAbsent'
        $findings[0].Severity    | Should -Be 'LOW'
        $findings[0].Score       | Should -Be 2
    }

    It 'emits EP-05 LOW finding when banned password list is empty' {
        Mock Get-MgBetaDirectorySetting {
            @([PSCustomObject]@{
                DisplayName = 'Password Rule Settings'
                Values = @(
                    [PSCustomObject]@{ Name = 'enableBannedPasswordCheck'; Value = 'true' }
                    [PSCustomObject]@{ Name = 'banPasswordList';                     Value = ''     }
                )
            })
        }
        $findings = Get-CustomBannedPasswordFindings
        $findings | Should -HaveCount 1
        $findings[0].FindingType | Should -Be 'CustomBannedPasswordsAbsent'
    }

    It 'emits no finding when banned password check is enabled with a list' {
        Mock Get-MgBetaDirectorySetting {
            @([PSCustomObject]@{
                DisplayName = 'Password Rule Settings'
                Values = @(
                    [PSCustomObject]@{ Name = 'enableBannedPasswordCheck'; Value = 'true'          }
                    [PSCustomObject]@{ Name = 'banPasswordList';                     Value = 'contoso,acme'  }
                )
            })
        }
        $findings = Get-CustomBannedPasswordFindings
        $findings | Should -BeNullOrEmpty
    }
}
