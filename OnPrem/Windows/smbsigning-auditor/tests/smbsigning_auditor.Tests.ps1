BeforeAll {
    # Define cmdlet stubs before dot-sourcing so the script's guard doesn't overwrite them
    function Get-SmbServerConfiguration {
        [PSCustomObject]@{
            RequireSecuritySignature = $false
            EnableSecuritySignature  = $false
        }
    }
    function Get-SmbClientConfiguration {
        [PSCustomObject]@{
            RequireSecuritySignature = $false
            EnableSecuritySignature  = $false
        }
    }

    . (Join-Path $PSScriptRoot '..' 'smbsigning_auditor.ps1')
}

Describe 'Get-Score' {
    It 'Returns 10 when all signing disabled' {
        $status = [PSCustomObject]@{
            ServerRequireSignature = $false
            ServerEnableSignature  = $false
            ClientRequireSignature = $false
            ClientEnableSignature  = $false
        }
        Get-Score -Status $status | Should -Be 10
    }

    It 'Returns 0 when all signing required and enabled' {
        $status = [PSCustomObject]@{
            ServerRequireSignature = $true
            ServerEnableSignature  = $true
            ClientRequireSignature = $true
            ClientEnableSignature  = $true
        }
        Get-Score -Status $status | Should -Be 0
    }

    It 'Server require missing adds 5 to score' {
        $status = [PSCustomObject]@{
            ServerRequireSignature = $false
            ServerEnableSignature  = $true
            ClientRequireSignature = $true
            ClientEnableSignature  = $true
        }
        Get-Score -Status $status | Should -Be 5
    }

    It 'Client require missing adds 2 to score' {
        $status = [PSCustomObject]@{
            ServerRequireSignature = $true
            ServerEnableSignature  = $true
            ClientRequireSignature = $false
            ClientEnableSignature  = $true
        }
        Get-Score -Status $status | Should -Be 2
    }

    It 'Score is capped at 10' {
        $status = [PSCustomObject]@{
            ServerRequireSignature = $false
            ServerEnableSignature  = $false
            ClientRequireSignature = $false
            ClientEnableSignature  = $false
        }
        Get-Score -Status $status | Should -BeLessOrEqual 10
    }
}

Describe 'Get-Flags' {
    It 'Returns NTLM relay flag when server require signing missing' {
        $status = [PSCustomObject]@{
            ServerRequireSignature = $false
            ServerEnableSignature  = $true
            ClientRequireSignature = $true
            ClientEnableSignature  = $true
        }
        $flags, $rems = Get-Flags -Status $status
        $flags | Should -Contain ($flags | Where-Object { $_ -match 'NTLM' } | Select-Object -First 1)
    }

    It 'Returns positive flag when all signing enforced' {
        $status = [PSCustomObject]@{
            ServerRequireSignature = $true
            ServerEnableSignature  = $true
            ClientRequireSignature = $true
            ClientEnableSignature  = $true
        }
        $flags, $rems = Get-Flags -Status $status
        ($flags | Where-Object { $_ -match '✅' }).Count | Should -BeGreaterThan 0
    }

    It 'Flags and remediations have equal length' {
        $status = [PSCustomObject]@{
            ServerRequireSignature = $false
            ServerEnableSignature  = $false
            ClientRequireSignature = $false
            ClientEnableSignature  = $false
        }
        $flags, $rems = Get-Flags -Status $status
        $flags.Count | Should -Be $rems.Count
    }

    It 'Client signing not enabled uses info prefix' {
        $status = [PSCustomObject]@{
            ServerRequireSignature = $true
            ServerEnableSignature  = $true
            ClientRequireSignature = $true
            ClientEnableSignature  = $false
        }
        $flags, $rems = Get-Flags -Status $status
        ($flags | Where-Object { $_ -match '^ℹ️' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Invoke-SmbSigningAudit' {
    BeforeEach {
        Mock Get-SmbServerConfiguration {
            [PSCustomObject]@{
                RequireSecuritySignature = $false
                EnableSecuritySignature  = $false
            }
        }
        Mock Get-SmbClientConfiguration {
            [PSCustomObject]@{
                RequireSecuritySignature = $false
                EnableSecuritySignature  = $false
            }
        }
    }

    It 'Returns report with generated_at field' {
        $report = Invoke-SmbSigningAudit
        $report.generated_at | Should -Not -BeNullOrEmpty
    }

    It 'Returns report with findings array' {
        $report = Invoke-SmbSigningAudit
        $report.findings.Count | Should -BeGreaterThan 0
    }

    It 'Finding has risk_level field' {
        $report = Invoke-SmbSigningAudit
        $report.findings[0].risk_level | Should -Not -BeNullOrEmpty
    }

    It 'All signing disabled gives CRITICAL or HIGH risk' {
        $report = Invoke-SmbSigningAudit
        $report.findings[0].risk_level | Should -BeIn @('CRITICAL', 'HIGH')
    }
}
