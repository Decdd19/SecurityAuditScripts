# OnPrem/Windows/localuser-auditor/tests/localuser_auditor.Tests.ps1
BeforeAll {
    function Get-LocalUser { param($Name) @() }
    function Get-LocalGroup { @() }
    function Get-LocalGroupMember { param($Group) @() }
    function Get-Service { param($Name) $null }
    function Get-ItemProperty { param($Path, $Name) $null }

    . "$PSScriptRoot/../localuser_auditor.ps1"
}

Describe 'Get-LocalUserFindings' {
    It 'flags guest account enabled' {
        Mock Get-LocalUser {
            param($Name)
            if ($Name -eq 'Guest') {
                [PSCustomObject]@{
                    Name             = 'Guest'
                    Enabled          = $true
                    PasswordRequired = $true
                    LastLogon        = $null
                }
            } else {
                @()
            }
        }

        $findings = Get-LocalUserFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'GuestAccountEnabled' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
    }

    It 'does not flag disabled guest account' {
        Mock Get-LocalUser {
            param($Name)
            if ($Name -eq 'Guest') {
                [PSCustomObject]@{
                    Name             = 'Guest'
                    Enabled          = $false
                    PasswordRequired = $true
                    LastLogon        = $null
                }
            } else {
                @()
            }
        }

        $findings = Get-LocalUserFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'GuestAccountEnabled' }
        $finding  | Should -BeNullOrEmpty
    }

    It 'flags local user with no password required' {
        Mock Get-LocalUser {
            param($Name)
            if ($Name -eq 'Guest') {
                # Return disabled Guest so it does not produce a GuestAccountEnabled finding
                [PSCustomObject]@{
                    Name             = 'Guest'
                    Enabled          = $false
                    PasswordRequired = $true
                    LastLogon        = $null
                    PasswordExpires  = $true
                }
            } elseif ($Name -eq 'Administrator') {
                [PSCustomObject]@{
                    Name             = 'Administrator'
                    Enabled          = $false
                    PasswordRequired = $true
                    LastLogon        = $null
                    PasswordExpires  = $true
                }
            } else {
                @(
                    [PSCustomObject]@{
                        Name             = 'TestUser'
                        Enabled          = $true
                        PasswordRequired = $false
                        LastLogon        = (Get-Date)
                        PasswordExpires  = $true
                    }
                )
            }
        }

        $findings = Get-LocalUserFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'LocalUserNoPassword' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.UserName | Should -Be 'TestUser'
    }

    It 'flags autologin registry key' {
        Mock Get-ItemProperty {
            param($Path, $Name)
            if ($Path -like '*Winlogon*' -and $Name -eq 'AutoAdminLogon') {
                [PSCustomObject]@{ AutoAdminLogon = '1' }
            } else {
                $null
            }
        }

        $findings = Get-LocalUserFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'AutologinEnabled' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Score | Should -Be 9
    }

    It 'flags WDigest credential caching enabled' {
        Mock Get-ItemProperty {
            param($Path, $Name)
            if ($Path -like '*WDigest*' -and $Name -eq 'UseLogonCredential') {
                [PSCustomObject]@{ UseLogonCredential = 1 }
            } else {
                $null
            }
        }

        $findings = Get-LocalUserFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'WDigestAuthEnabled' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
    }

    It 'flags RemoteRegistry service running' {
        Mock Get-Service {
            param($Name)
            if ($Name -eq 'RemoteRegistry') {
                [PSCustomObject]@{ Status = 'Running' }
            } else {
                $null
            }
        }

        $findings = Get-LocalUserFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'RemoteRegistryEnabled' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Score | Should -Be 6
        $finding.Severity | Should -Be 'HIGH'
    }

    It 'flags stale local user' {
        Mock Get-LocalUser {
            param($Name)
            if ($Name -eq 'Guest') {
                [PSCustomObject]@{
                    Name             = 'Guest'
                    Enabled          = $false
                    PasswordRequired = $true
                    LastLogon        = $null
                    PasswordExpires  = $true
                }
            } elseif ($Name -eq 'Administrator') {
                [PSCustomObject]@{
                    Name             = 'Administrator'
                    Enabled          = $false
                    PasswordRequired = $true
                    LastLogon        = $null
                    PasswordExpires  = $true
                }
            } else {
                @(
                    [PSCustomObject]@{
                        Name             = 'OldUser'
                        Enabled          = $true
                        PasswordRequired = $true
                        LastLogon        = (Get-Date).AddDays(-100)
                        PasswordExpires  = $true
                    }
                )
            }
        }

        $findings = Get-LocalUserFindings
        $finding  = $findings | Where-Object { $_.FindingType -eq 'StaleLocalUser' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.UserName | Should -Be 'OldUser'
    }
}
