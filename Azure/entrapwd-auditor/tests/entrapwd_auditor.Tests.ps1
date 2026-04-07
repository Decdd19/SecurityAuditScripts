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
