BeforeAll {
    # Stub Az cmdlets — must be defined before dot-sourcing so the script's
    # conditional stubs see these commands and skip their own definitions.
    function Get-AzContext    { @{ Subscription = @{ Id = 'sub-001'; Name = 'TestSub' }; Tenant = @{ Id = 'tenant-001' } } }
    function Get-AzSubscription { param($SubscriptionId) @{ Id = 'sub-001'; Name = 'TestSub' } }
    function Set-AzContext    { }
    function Get-AzSecurityPricing                 { @() }
    function Get-AzSecurityContact                 { @() }
    function Get-AzSecurityAutoProvisioningSetting { @() }
    function Get-AzSecuritySecureScore             { @() }

    . "$PSScriptRoot/../defender_auditor.ps1"

    $script:Sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
}

# ── Defender Plans — disabled ─────────────────────────────────────────────────

Describe 'Get-DefenderFindings — Defender plan disabled' {
    It 'creates DefenderPlanDisabled finding with HIGH severity when plan is on Free tier' {
        Mock Get-AzSecurityPricing {
            @([PSCustomObject]@{ Name = 'VirtualMachines'; PricingTier = 'Free' })
        }
        Mock Get-AzSecurityContact { @([PSCustomObject]@{ Email = 'sec@example.com' }) }
        Mock Get-AzSecurityAutoProvisioningSetting { @([PSCustomObject]@{ Name = 'mma-agent'; AutoProvision = 'On' }) }
        Mock Get-AzSecuritySecureScore { @([PSCustomObject]@{ Name = 'ascScore'; SecureScore = 8; MaxSecureScore = 10; Percentage = 0.8 }) }

        $result = Get-DefenderFindings -Subscription $script:Sub
        $f = $result.Findings | Where-Object { $_.FindingType -eq 'DefenderPlanDisabled' -and $_.Resource -eq 'VirtualMachines' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
    }

    It 'creates no DefenderPlanDisabled findings when all important plans are Standard' {
        $plans = @('VirtualMachines','SqlServers','StorageAccounts','AppServices','KeyVaults','Containers','Arm')
        Mock Get-AzSecurityPricing {
            $plans | ForEach-Object { [PSCustomObject]@{ Name = $_; PricingTier = 'Standard' } }
        }
        Mock Get-AzSecurityContact { @([PSCustomObject]@{ Email = 'sec@example.com' }) }
        Mock Get-AzSecurityAutoProvisioningSetting { @([PSCustomObject]@{ Name = 'mma-agent'; AutoProvision = 'On' }) }
        Mock Get-AzSecuritySecureScore { @([PSCustomObject]@{ Name = 'ascScore'; SecureScore = 8; MaxSecureScore = 10; Percentage = 0.8 }) }

        $result = Get-DefenderFindings -Subscription $script:Sub
        $result.Findings | Where-Object FindingType -eq 'DefenderPlanDisabled' | Should -BeNullOrEmpty
    }
}

# ── Security Contact ──────────────────────────────────────────────────────────

Describe 'Get-DefenderFindings — security contact' {
    It 'creates NoSecurityContact finding with MEDIUM severity when no contacts configured' {
        Mock Get-AzSecurityPricing { @() }
        Mock Get-AzSecurityContact { @() }
        Mock Get-AzSecurityAutoProvisioningSetting { @() }
        Mock Get-AzSecuritySecureScore { @() }

        $result = Get-DefenderFindings -Subscription $script:Sub
        $f = $result.Findings | Where-Object FindingType -eq 'NoSecurityContact'
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'MEDIUM'
    }

    It 'creates no NoSecurityContact finding when a contact is present' {
        Mock Get-AzSecurityPricing { @() }
        Mock Get-AzSecurityContact { @([PSCustomObject]@{ Email = 'sec@example.com'; Phone = ''; AlertNotifications = 'On'; AlertsToAdmins = 'On' }) }
        Mock Get-AzSecurityAutoProvisioningSetting { @() }
        Mock Get-AzSecuritySecureScore { @() }

        $result = Get-DefenderFindings -Subscription $script:Sub
        $result.Findings | Where-Object FindingType -eq 'NoSecurityContact' | Should -BeNullOrEmpty
    }
}

# ── Auto-provisioning ─────────────────────────────────────────────────────────

Describe 'Get-DefenderFindings — auto-provisioning' {
    It 'creates AutoProvisioningOff finding when mma-agent AutoProvision is Off' {
        Mock Get-AzSecurityPricing { @() }
        Mock Get-AzSecurityContact { @([PSCustomObject]@{ Email = 'sec@example.com' }) }
        Mock Get-AzSecurityAutoProvisioningSetting {
            @([PSCustomObject]@{ Name = 'mma-agent'; AutoProvision = 'Off' })
        }
        Mock Get-AzSecuritySecureScore { @() }

        $result = Get-DefenderFindings -Subscription $script:Sub
        $f = $result.Findings | Where-Object FindingType -eq 'AutoProvisioningOff'
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'MEDIUM'
    }

    It 'creates no AutoProvisioningOff finding when mma-agent AutoProvision is On' {
        Mock Get-AzSecurityPricing { @() }
        Mock Get-AzSecurityContact { @([PSCustomObject]@{ Email = 'sec@example.com' }) }
        Mock Get-AzSecurityAutoProvisioningSetting {
            @([PSCustomObject]@{ Name = 'mma-agent'; AutoProvision = 'On' })
        }
        Mock Get-AzSecuritySecureScore { @() }

        $result = Get-DefenderFindings -Subscription $script:Sub
        $result.Findings | Where-Object FindingType -eq 'AutoProvisioningOff' | Should -BeNullOrEmpty
    }
}

# ── Secure Score ──────────────────────────────────────────────────────────────

Describe 'Get-DefenderFindings — secure score' {
    It 'creates LowSecureScore finding with HIGH severity when score percentage below 50%' {
        Mock Get-AzSecurityPricing { @() }
        Mock Get-AzSecurityContact { @([PSCustomObject]@{ Email = 'sec@example.com' }) }
        Mock Get-AzSecurityAutoProvisioningSetting { @() }
        Mock Get-AzSecuritySecureScore {
            @([PSCustomObject]@{ Name = 'ascScore'; SecureScore = 3.5; MaxSecureScore = 10; Percentage = 0.35 })
        }

        $result = Get-DefenderFindings -Subscription $script:Sub
        $f = $result.Findings | Where-Object FindingType -eq 'LowSecureScore'
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
    }

    It 'creates no LowSecureScore finding when score percentage is 50% or above' {
        Mock Get-AzSecurityPricing { @() }
        Mock Get-AzSecurityContact { @([PSCustomObject]@{ Email = 'sec@example.com' }) }
        Mock Get-AzSecurityAutoProvisioningSetting { @() }
        Mock Get-AzSecuritySecureScore {
            @([PSCustomObject]@{ Name = 'ascScore'; SecureScore = 7.2; MaxSecureScore = 10; Percentage = 0.72 })
        }

        $result = Get-DefenderFindings -Subscription $script:Sub
        $result.Findings | Where-Object FindingType -eq 'LowSecureScore' | Should -BeNullOrEmpty
    }
}

# ── PlansEnabled count ────────────────────────────────────────────────────────

Describe 'Get-DefenderFindings — plan count summary' {
    It 'returns correct PlansEnabled and TotalPlansChecked in result object' {
        Mock Get-AzSecurityPricing {
            @(
                [PSCustomObject]@{ Name = 'VirtualMachines'; PricingTier = 'Standard' },
                [PSCustomObject]@{ Name = 'StorageAccounts'; PricingTier = 'Standard' },
                [PSCustomObject]@{ Name = 'SqlServers';       PricingTier = 'Free' }
            )
        }
        Mock Get-AzSecurityContact { @([PSCustomObject]@{ Email = 'sec@example.com' }) }
        Mock Get-AzSecurityAutoProvisioningSetting { @() }
        Mock Get-AzSecuritySecureScore { @() }

        $result = Get-DefenderFindings -Subscription $script:Sub
        $result.TotalPlansChecked | Should -Be 7
        $result.PlansEnabled      | Should -Be 2
    }
}

# ── Get-SeverityLabel ─────────────────────────────────────────────────────────

Describe 'Get-SeverityLabel' {
    It 'returns CRITICAL for score 8 or above' {
        Get-SeverityLabel -Score 8  | Should -Be 'CRITICAL'
        Get-SeverityLabel -Score 10 | Should -Be 'CRITICAL'
    }

    It 'returns HIGH for score 6 or 7' {
        Get-SeverityLabel -Score 6 | Should -Be 'HIGH'
        Get-SeverityLabel -Score 7 | Should -Be 'HIGH'
    }

    It 'returns MEDIUM for score 3 to 5' {
        Get-SeverityLabel -Score 3 | Should -Be 'MEDIUM'
        Get-SeverityLabel -Score 5 | Should -Be 'MEDIUM'
    }

    It 'returns LOW for score below 3' {
        Get-SeverityLabel -Score 0 | Should -Be 'LOW'
        Get-SeverityLabel -Score 2 | Should -Be 'LOW'
    }
}

# ── Get-SeverityColour ────────────────────────────────────────────────────────

Describe 'Get-SeverityColour' {
    It 'returns correct hex colour for CRITICAL' {
        Get-SeverityColour -Severity 'CRITICAL' | Should -Be '#dc3545'
    }

    It 'returns correct hex colour for HIGH' {
        Get-SeverityColour -Severity 'HIGH' | Should -Be '#fd7e14'
    }

    It 'returns correct hex colour for MEDIUM' {
        Get-SeverityColour -Severity 'MEDIUM' | Should -Be '#ffc107'
    }

    It 'returns correct hex colour for LOW' {
        Get-SeverityColour -Severity 'LOW' | Should -Be '#28a745'
    }

    It 'returns grey hex for unknown severity' {
        Get-SeverityColour -Severity 'UNKNOWN' | Should -Be '#6c757d'
    }
}

# ── ConvertTo-JsonReport ──────────────────────────────────────────────────────

Describe 'ConvertTo-JsonReport' {
    It 'returns correct summary counts and findings array' {
        $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
        $findings.Add([PSCustomObject]@{ FindingType='DefenderPlanDisabled'; Resource='VirtualMachines'; Severity='HIGH';   Score=7; Description='...'; Recommendation='...'; SubscriptionId='sub-001'; SubscriptionName='TestSub' })
        $findings.Add([PSCustomObject]@{ FindingType='NoSecurityContact';    Resource='Contacts';        Severity='MEDIUM'; Score=5; Description='...'; Recommendation='...'; SubscriptionId='sub-001'; SubscriptionName='TestSub' })

        $results = @([PSCustomObject]@{
            SubscriptionId    = 'sub-001'
            SubscriptionName  = 'TestSub'
            Findings          = $findings
            SecureScore       = 7.0
            MaxSecureScore    = 10.0
            TotalPlansChecked = 7
            PlansEnabled      = 6
        })

        $report = ConvertTo-JsonReport -Results $results -TenantId 'tenant-001'
        $report.Summary.TotalFindings | Should -Be 2
        $report.Summary.High          | Should -Be 1
        $report.Summary.Medium        | Should -Be 1
        $report.Summary.Critical      | Should -Be 0
        $report.Findings.Count        | Should -Be 2
        $report.TenantId              | Should -Be 'tenant-001'
    }
}
