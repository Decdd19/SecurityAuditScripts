# OnPrem/Windows/netexpose-auditor/tests/netexpose_auditor.Tests.ps1
BeforeAll {
    function Test-NetConnection {
        param($ComputerName, $Port, $InformationLevel, $WarningAction)
        [PSCustomObject]@{ TcpTestSucceeded = $false }
    }

    . "$PSScriptRoot/../netexpose_auditor.ps1" -Target '10.0.0.1'
}

# ---------------------------------------------------------------------------
# Expand-CidrRange
# ---------------------------------------------------------------------------
Describe 'Expand-CidrRange' {
    It 'returns a single IP unchanged' {
        $result = Expand-CidrRange '10.0.0.5'
        $result | Should -HaveCount 1
        $result[0] | Should -Be '10.0.0.5'
    }

    It 'returns 2 host IPs for a /30' {
        $result = Expand-CidrRange '192.168.1.0/30'
        $result | Should -HaveCount 2
        $result | Should -Contain '192.168.1.1'
        $result | Should -Contain '192.168.1.2'
    }

    It 'returns 254 host IPs for a /24' {
        $result = Expand-CidrRange '10.0.0.0/24'
        $result | Should -HaveCount 254
        $result | Should -Contain '10.0.0.1'
        $result | Should -Contain '10.0.0.254'
        $result | Should -Not -Contain '10.0.0.0'
        $result | Should -Not -Contain '10.0.0.255'
    }

    It 'throws on invalid input' {
        { Expand-CidrRange 'not-an-ip' } | Should -Throw
    }
}

# ---------------------------------------------------------------------------
# Invoke-HostScan
# ---------------------------------------------------------------------------
Describe 'Invoke-HostScan' {
    It 'emits NE-01 CRITICAL ExposedService finding when RDP is open' {
        Mock Test-NetConnection {
            param($ComputerName, $Port)
            [PSCustomObject]@{ TcpTestSucceeded = ($Port -eq 3389) }
        }
        $findings = Invoke-HostScan -Ip '10.0.0.1' -AllPorts $script:DEFAULT_PORTS
        $f = $findings | Where-Object { $_.Port -eq 3389 }
        $f              | Should -Not -BeNullOrEmpty
        $f.FindingType  | Should -Be 'ExposedService'
        $f.Service      | Should -Be 'RDP'
        $f.Severity     | Should -Be 'CRITICAL'
        $f.Host         | Should -Be '10.0.0.1'
    }

    It 'emits NE-02 CRITICAL finding when SMB is open' {
        Mock Test-NetConnection {
            param($ComputerName, $Port)
            [PSCustomObject]@{ TcpTestSucceeded = ($Port -eq 445) }
        }
        $findings = Invoke-HostScan -Ip '10.0.0.1' -AllPorts $script:DEFAULT_PORTS
        $f = $findings | Where-Object { $_.Port -eq 445 }
        $f.Service  | Should -Be 'SMB'
        $f.Severity | Should -Be 'CRITICAL'
    }

    It 'emits no finding when port is closed' {
        Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $false } }
        $findings = Invoke-HostScan -Ip '10.0.0.1' -AllPorts $script:DEFAULT_PORTS
        $findings | Should -BeNullOrEmpty
    }

    It 'emits one finding per open port when multiple ports open on same host' {
        Mock Test-NetConnection {
            param($ComputerName, $Port)
            [PSCustomObject]@{ TcpTestSucceeded = ($Port -in @(3389, 445)) }
        }
        $findings = Invoke-HostScan -Ip '10.0.0.1' -AllPorts $script:DEFAULT_PORTS
        $findings | Should -HaveCount 2
    }

    It 'emits ExposedCustomPort MEDIUM finding for an extra port' {
        $customPorts = @(@{
            Port = 8080; Service = 'Port 8080'; FindingId = 'NE-XX'
            Severity = 'MEDIUM'; Score = 4; CisControl = 'CIS 12.2'
            Recommendation = 'Investigate port 8080 exposure.'
        })
        Mock Test-NetConnection {
            param($ComputerName, $Port)
            [PSCustomObject]@{ TcpTestSucceeded = ($Port -eq 8080) }
        }
        $findings = Invoke-HostScan -Ip '10.0.0.1' -AllPorts $customPorts
        $f = $findings | Where-Object { $_.Port -eq 8080 }
        $f              | Should -Not -BeNullOrEmpty
        $f.FindingType  | Should -Be 'ExposedCustomPort'
        $f.Severity     | Should -Be 'MEDIUM'
    }

    It 'returns empty array when all ports closed' {
        Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $false } }
        $findings = Invoke-HostScan -Ip '10.0.0.1' -AllPorts $script:DEFAULT_PORTS
        $findings | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-NetworkExposureFindings
# ---------------------------------------------------------------------------
Describe 'Get-NetworkExposureFindings' {
    It 'returns empty when all ports closed across multiple hosts' {
        Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $false } }
        $findings = Get-NetworkExposureFindings -Hosts @('10.0.0.1','10.0.0.2') `
                        -Ports $script:DEFAULT_PORTS -ExtraPorts @() -Sequential
        $findings | Should -BeNullOrEmpty
    }

    It 'aggregates findings from multiple hosts' {
        Mock Test-NetConnection {
            param($ComputerName, $Port)
            [PSCustomObject]@{ TcpTestSucceeded = ($Port -eq 3389) }
        }
        $findings = Get-NetworkExposureFindings -Hosts @('10.0.0.1','10.0.0.2') `
                        -Ports $script:DEFAULT_PORTS -ExtraPorts @() -Sequential
        $findings | Should -HaveCount 2
        ($findings | Select-Object -ExpandProperty Host | Sort-Object -Unique) | Should -HaveCount 2
    }
}

# ---------------------------------------------------------------------------
# ConvertTo-NetExposeJsonReport
# ---------------------------------------------------------------------------
Describe 'ConvertTo-NetExposeJsonReport' {
    It 'emits generated_at, target, summary, and findings fields' {
        $f = [PSCustomObject]@{
            FindingType = 'ExposedService'; Host = '10.0.0.1'; Port = 3389
            Service = 'RDP'; Severity = 'CRITICAL'; CisControl = 'CIS 12.2'
            Score = 9; Recommendation = 'Test'
        }
        $report = ConvertTo-NetExposeJsonReport -Findings @($f) -Target '10.0.0.0/24'
        $report.generated_at | Should -Not -BeNullOrEmpty
        $report.target       | Should -Be '10.0.0.0/24'
        $report.summary      | Should -Not -BeNullOrEmpty
        $report.findings     | Should -HaveCount 1
    }

    It 'summary counts match findings array' {
        $findings = @(
            [PSCustomObject]@{ FindingType='ExposedService'; Host='10.0.0.1'; Port=3389; Service='RDP';  Severity='CRITICAL'; CisControl='CIS 12.2'; Score=9; Recommendation='X' }
            [PSCustomObject]@{ FindingType='ExposedService'; Host='10.0.0.1'; Port=5985; Service='WinRM HTTP'; Severity='HIGH'; CisControl='CIS 12.2'; Score=7; Recommendation='X' }
        )
        $report = ConvertTo-NetExposeJsonReport -Findings $findings -Target '10.0.0.1'
        $report.summary.CRITICAL | Should -Be 1
        $report.summary.HIGH     | Should -Be 1
        $report.summary.MEDIUM   | Should -Be 0
    }
}
