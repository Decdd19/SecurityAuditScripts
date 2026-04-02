# OnPrem/Windows/laps-auditor/tests/laps_auditor.Tests.ps1
BeforeAll {
    # ---------------------------------------------------------------------------
    # AD module stubs -- all return empty by default; individual tests Mock as needed
    # ---------------------------------------------------------------------------
    function Get-ADObject { param($Filter, $SearchBase, $Properties) @() }
    function Get-ADComputer { param($Filter, $Properties) @() }
    function Get-ADDomain { @{ DNSRoot = 'test.local'; DistinguishedName = 'DC=test,DC=local' } }

    . "$PSScriptRoot/../laps_auditor.ps1"
}

Describe 'Get-LapsFindings' {

    It '1. flags HIGH when Legacy LAPS schema is missing' {
        Mock Get-ADObject { @() }
        Mock Get-ADComputer { @() }

        $result   = Get-LapsFindings
        $finding  = $result.findings | Where-Object { $_.FindingType -eq 'LapsNotInstalled' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
        $finding.Score | Should -Be 7
    }

    It '2. no schema finding when Legacy LAPS schema is present' {
        Mock Get-ADObject {
            param($Filter, $SearchBase, $Properties)
            $filterStr = "$Filter"
            if ($filterStr -like '*ms-Mcs-AdmPwd*') {
                return @([PSCustomObject]@{ Name = 'ms-Mcs-AdmPwd' })
            }
            return @()
        }
        Mock Get-ADComputer { @() }

        $result   = Get-LapsFindings
        $finding  = $result.findings | Where-Object { $_.FindingType -eq 'LapsNotInstalled' }
        $finding  | Should -BeNullOrEmpty
    }

    It '3. flags MEDIUM when Windows LAPS schema is missing' {
        Mock Get-ADObject { @() }
        Mock Get-ADComputer { @() }

        $result   = Get-LapsFindings
        $finding  = $result.findings | Where-Object { $_.FindingType -eq 'WindowsLapsNotPresent' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
        $finding.Score | Should -Be 5
    }

    It '4. no Windows LAPS finding when schema attribute is present' {
        Mock Get-ADObject {
            param($Filter, $SearchBase, $Properties)
            $filterStr = "$Filter"
            if ($filterStr -like '*msLAPS-Password*') {
                return @([PSCustomObject]@{ Name = 'msLAPS-Password' })
            }
            if ($filterStr -like '*ms-Mcs-AdmPwd*') {
                return @([PSCustomObject]@{ Name = 'ms-Mcs-AdmPwd' })
            }
            return @()
        }
        Mock Get-ADComputer { @() }

        $result   = Get-LapsFindings
        $finding  = $result.findings | Where-Object { $_.FindingType -eq 'WindowsLapsNotPresent' }
        $finding  | Should -BeNullOrEmpty
    }

    It '5. flags HIGH when 0% LAPS coverage (no computers managed)' {
        Mock Get-ADObject {
            param($Filter, $SearchBase, $Properties)
            return @([PSCustomObject]@{ Name = 'ms-Mcs-AdmPwd' })
        }
        Mock Get-ADComputer {
            return @(
                [PSCustomObject]@{
                    Name = 'PC01'
                    'ms-Mcs-AdmPwdExpirationTime'    = $null
                    'msLAPS-PasswordExpirationTime'   = $null
                },
                [PSCustomObject]@{
                    Name = 'PC02'
                    'ms-Mcs-AdmPwdExpirationTime'    = $null
                    'msLAPS-PasswordExpirationTime'   = $null
                }
            )
        }

        $result   = Get-LapsFindings
        $finding  = $result.findings | Where-Object { $_.FindingType -eq 'LowLapsCoverage' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
        $finding.Description | Should -BeLike '*0%*'
    }

    It '6. no coverage finding when 100% LAPS coverage' {
        Mock Get-ADObject {
            return @([PSCustomObject]@{ Name = 'ms-Mcs-AdmPwd' })
        }
        Mock Get-ADComputer {
            $future = (Get-Date).AddDays(30)
            return @(
                [PSCustomObject]@{
                    Name = 'PC01'
                    'ms-Mcs-AdmPwdExpirationTime'    = $future
                    'msLAPS-PasswordExpirationTime'   = $null
                },
                [PSCustomObject]@{
                    Name = 'PC02'
                    'ms-Mcs-AdmPwdExpirationTime'    = $future
                    'msLAPS-PasswordExpirationTime'   = $null
                }
            )
        }

        $result   = Get-LapsFindings
        $finding  = $result.findings | Where-Object { $_.FindingType -eq 'LowLapsCoverage' }
        $finding  | Should -BeNullOrEmpty
        $result.summary.coverage_pct | Should -Be 100
    }

    It '7. flags HIGH when 50% coverage (below 80% threshold)' {
        Mock Get-ADObject {
            return @([PSCustomObject]@{ Name = 'ms-Mcs-AdmPwd' })
        }
        Mock Get-ADComputer {
            $future = (Get-Date).AddDays(30)
            return @(
                [PSCustomObject]@{
                    Name = 'PC01'
                    'ms-Mcs-AdmPwdExpirationTime'    = $future
                    'msLAPS-PasswordExpirationTime'   = $null
                },
                [PSCustomObject]@{
                    Name = 'PC02'
                    'ms-Mcs-AdmPwdExpirationTime'    = $null
                    'msLAPS-PasswordExpirationTime'   = $null
                }
            )
        }

        $result   = Get-LapsFindings
        $finding  = $result.findings | Where-Object { $_.FindingType -eq 'LowLapsCoverage' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Description | Should -BeLike '*50*'
    }

    It '8. flags MEDIUM when expired LAPS password is present' {
        Mock Get-ADObject {
            return @([PSCustomObject]@{ Name = 'ms-Mcs-AdmPwd' })
        }
        Mock Get-ADComputer {
            $past   = (Get-Date).AddDays(-10)
            $future = (Get-Date).AddDays(30)
            return @(
                [PSCustomObject]@{
                    Name = 'PC01'
                    'ms-Mcs-AdmPwdExpirationTime'    = $past
                    'msLAPS-PasswordExpirationTime'   = $null
                },
                [PSCustomObject]@{
                    Name = 'PC02'
                    'ms-Mcs-AdmPwdExpirationTime'    = $future
                    'msLAPS-PasswordExpirationTime'   = $null
                }
            )
        }

        $result   = Get-LapsFindings
        $finding  = $result.findings | Where-Object { $_.FindingType -eq 'ExpiredLapsPasswords' }
        $finding  | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
        $finding.Description | Should -BeLike '*1 computer*'
    }

    It '9. no expiry finding when all passwords are current' {
        Mock Get-ADObject {
            return @([PSCustomObject]@{ Name = 'ms-Mcs-AdmPwd' })
        }
        Mock Get-ADComputer {
            $future = (Get-Date).AddDays(30)
            return @(
                [PSCustomObject]@{
                    Name = 'PC01'
                    'ms-Mcs-AdmPwdExpirationTime'    = $future
                    'msLAPS-PasswordExpirationTime'   = $null
                },
                [PSCustomObject]@{
                    Name = 'PC02'
                    'ms-Mcs-AdmPwdExpirationTime'    = $null
                    'msLAPS-PasswordExpirationTime'   = $future
                }
            )
        }

        $result   = Get-LapsFindings
        $finding  = $result.findings | Where-Object { $_.FindingType -eq 'ExpiredLapsPasswords' }
        $finding  | Should -BeNullOrEmpty
    }

    It '10. findings have FindingType, Severity, and Score fields' {
        Mock Get-ADObject { @() }
        Mock Get-ADComputer { @() }

        $result = Get-LapsFindings
        $result.findings.Count | Should -BeGreaterThan 0

        foreach ($f in $result.findings) {
            $f.PSObject.Properties.Name | Should -Contain 'FindingType'
            $f.PSObject.Properties.Name | Should -Contain 'Severity'
            $f.PSObject.Properties.Name | Should -Contain 'Score'
        }
    }

    It '11. summary contains correct coverage percentage' {
        Mock Get-ADObject {
            return @([PSCustomObject]@{ Name = 'ms-Mcs-AdmPwd' })
        }
        Mock Get-ADComputer {
            $future = (Get-Date).AddDays(30)
            return @(
                [PSCustomObject]@{
                    Name = 'PC01'
                    'ms-Mcs-AdmPwdExpirationTime'    = $future
                    'msLAPS-PasswordExpirationTime'   = $null
                },
                [PSCustomObject]@{
                    Name = 'PC02'
                    'ms-Mcs-AdmPwdExpirationTime'    = $null
                    'msLAPS-PasswordExpirationTime'   = $null
                },
                [PSCustomObject]@{
                    Name = 'PC03'
                    'ms-Mcs-AdmPwdExpirationTime'    = $future
                    'msLAPS-PasswordExpirationTime'   = $null
                },
                [PSCustomObject]@{
                    Name = 'PC04'
                    'ms-Mcs-AdmPwdExpirationTime'    = $null
                    'msLAPS-PasswordExpirationTime'   = $null
                }
            )
        }

        $result = Get-LapsFindings
        $result.summary.total_computers | Should -Be 4
        $result.summary.laps_managed | Should -Be 2
        $result.summary.coverage_pct | Should -Be 50
    }

    It '12. overall risk reflects highest severity finding' {
        Mock Get-ADObject { @() }
        Mock Get-ADComputer {
            return @(
                [PSCustomObject]@{
                    Name = 'PC01'
                    'ms-Mcs-AdmPwdExpirationTime'    = $null
                    'msLAPS-PasswordExpirationTime'   = $null
                }
            )
        }

        $result = Get-LapsFindings
        # With missing schemas and low coverage, HIGH findings exist
        $result.summary.overall_risk | Should -Be 'HIGH'
    }
}
