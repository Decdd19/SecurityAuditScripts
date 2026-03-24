BeforeAll {
    function Get-AzContext { @{ Subscription = @{ Id = 'sub-001'; Name = 'TestSub' }; Tenant = @{ Id = 'tenant-001' } } }
    function Get-AzSubscription { param($SubscriptionId) @{ Id = 'sub-001'; Name = 'TestSub' } }
    function Set-AzContext { }
    function Get-AzKeyVault          { @() }
    function Get-AzKeyVaultSecret    { param($VaultName) @() }
    function Get-AzKeyVaultCertificate { param($VaultName) @() }
    function Get-AzKeyVaultKey       { param($VaultName) @() }
    function Get-AzDiagnosticSetting { param($ResourceId) @([PSCustomObject]@{ Name = 'default' }) }

    . "$PSScriptRoot/../keyvault_auditor.ps1"

    # ── Helpers ──────────────────────────────────────────────────────────────

    function script:New-Vault {
        param(
            [string]$Name = 'test-vault',
            [bool]$Rbac = $true,
            [bool]$PurgeProtection = $true,
            [object]$SoftDelete = $true,
            [string]$ResourceId = '/subscriptions/sub-001/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-vault'
        )
        [PSCustomObject]@{
            VaultName                = $Name
            ResourceGroupName        = 'test-rg'
            EnableRbacAuthorization  = $Rbac
            EnablePurgeProtection    = $PurgeProtection
            EnableSoftDelete         = $SoftDelete
            ResourceId               = $ResourceId
        }
    }

    $script:Sub = [PSCustomObject]@{ Id = 'sub-001'; Name = 'TestSub' }
}

# ── LegacyAccessPolicyModel ──────────────────────────────────────────────────

Describe 'Get-KeyVaultFindings — access model' {
    It 'flags vault using legacy access policy model (RBAC disabled)' {
        $vault = New-Vault -Rbac $false
        Mock Get-AzKeyVault { @($vault) }
        $result = Get-KeyVaultFindings -Subscription $script:Sub
        $f = $result.Findings | Where-Object FindingType -eq 'LegacyAccessPolicyModel'
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
        $f.Recommendation | Should -Match 'Azure Portal'
    }

    It 'does not flag vault with RBAC enabled' {
        $vault = New-Vault -Rbac $true
        Mock Get-AzKeyVault { @($vault) }
        $result = Get-KeyVaultFindings -Subscription $script:Sub
        $result.Findings | Where-Object FindingType -eq 'LegacyAccessPolicyModel' | Should -BeNullOrEmpty
    }
}

# ── PurgeProtectionDisabled ──────────────────────────────────────────────────

Describe 'Get-KeyVaultFindings — purge protection' {
    It 'flags vault with purge protection disabled' {
        $vault = New-Vault -PurgeProtection $false
        Mock Get-AzKeyVault { @($vault) }
        $result = Get-KeyVaultFindings -Subscription $script:Sub
        $f = $result.Findings | Where-Object FindingType -eq 'PurgeProtectionDisabled'
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
    }

    It 'does not flag vault with purge protection enabled' {
        $vault = New-Vault -PurgeProtection $true
        Mock Get-AzKeyVault { @($vault) }
        $result = Get-KeyVaultFindings -Subscription $script:Sub
        $result.Findings | Where-Object FindingType -eq 'PurgeProtectionDisabled' | Should -BeNullOrEmpty
    }
}

# ── SoftDeleteDisabled ───────────────────────────────────────────────────────

Describe 'Get-KeyVaultFindings — soft delete' {
    It 'flags vault with soft delete explicitly disabled' {
        $vault = New-Vault -SoftDelete $false
        Mock Get-AzKeyVault { @($vault) }
        $result = Get-KeyVaultFindings -Subscription $script:Sub
        $f = $result.Findings | Where-Object FindingType -eq 'SoftDeleteDisabled'
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'CRITICAL'
    }

    It 'does not flag vault with soft delete enabled' {
        $vault = New-Vault -SoftDelete $true
        Mock Get-AzKeyVault { @($vault) }
        $result = Get-KeyVaultFindings -Subscription $script:Sub
        $result.Findings | Where-Object FindingType -eq 'SoftDeleteDisabled' | Should -BeNullOrEmpty
    }
}

# ── NoDiagnosticLogging ──────────────────────────────────────────────────────

Describe 'Get-KeyVaultFindings — diagnostic logging' {
    It 'flags vault with no diagnostic settings' {
        $vault = New-Vault
        Mock Get-AzKeyVault { @($vault) }
        Mock Get-AzDiagnosticSetting { @() }
        $result = Get-KeyVaultFindings -Subscription $script:Sub
        $f = $result.Findings | Where-Object FindingType -eq 'NoDiagnosticLogging'
        $f | Should -Not -BeNullOrEmpty
        $f.Recommendation | Should -Match 'Diagnostic settings'
    }

    It 'does not flag vault with diagnostic settings present' {
        $vault = New-Vault
        Mock Get-AzKeyVault { @($vault) }
        Mock Get-AzDiagnosticSetting { @([PSCustomObject]@{ Name = 'default' }) }
        $result = Get-KeyVaultFindings -Subscription $script:Sub
        $result.Findings | Where-Object FindingType -eq 'NoDiagnosticLogging' | Should -BeNullOrEmpty
    }
}

# ── Expiry: Secrets ──────────────────────────────────────────────────────────

Describe 'Get-KeyVaultFindings — secret expiry' {
    It 'flags already-expired secret as CRITICAL' {
        $vault = New-Vault
        Mock Get-AzKeyVault { @($vault) }
        Mock Get-AzKeyVaultSecret {
            @([PSCustomObject]@{ Name = 'db-password'; Expires = [datetime]::UtcNow.AddDays(-5) })
        }
        $result = Get-KeyVaultFindings -Subscription $script:Sub -ExpiryWarningDays 30
        $f = $result.Findings | Where-Object FindingType -eq 'SecretExpired'
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'CRITICAL'
        $f.ItemName | Should -Be 'db-password'
        $f.Recommendation | Should -Match 'EXPIRED'
    }

    It 'flags secret expiring within warning window' {
        $vault = New-Vault
        Mock Get-AzKeyVault { @($vault) }
        Mock Get-AzKeyVaultSecret {
            @([PSCustomObject]@{ Name = 'api-key'; Expires = [datetime]::UtcNow.AddDays(10) })
        }
        $result = Get-KeyVaultFindings -Subscription $script:Sub -ExpiryWarningDays 30
        $f = $result.Findings | Where-Object FindingType -eq 'SecretExpiringSoon'
        $f | Should -Not -BeNullOrEmpty
        $f.ItemName | Should -Be 'api-key'
    }

    It 'does not flag secret with no expiry set' {
        $vault = New-Vault
        Mock Get-AzKeyVault { @($vault) }
        Mock Get-AzKeyVaultSecret {
            @([PSCustomObject]@{ Name = 'no-expiry-secret'; Expires = $null })
        }
        $result = Get-KeyVaultFindings -Subscription $script:Sub
        $result.Findings | Where-Object { $_.ItemName -eq 'no-expiry-secret' } | Should -BeNullOrEmpty
    }

    It 'does not flag secret expiring after warning window' {
        $vault = New-Vault
        Mock Get-AzKeyVault { @($vault) }
        Mock Get-AzKeyVaultSecret {
            @([PSCustomObject]@{ Name = 'future-secret'; Expires = [datetime]::UtcNow.AddDays(90) })
        }
        $result = Get-KeyVaultFindings -Subscription $script:Sub -ExpiryWarningDays 30
        $result.Findings | Where-Object FindingType -like 'Secret*' | Should -BeNullOrEmpty
    }
}

# ── Expiry: Certificates ─────────────────────────────────────────────────────

Describe 'Get-KeyVaultFindings — certificate expiry' {
    It 'flags expired certificate as CRITICAL' {
        $vault = New-Vault
        Mock Get-AzKeyVault { @($vault) }
        Mock Get-AzKeyVaultCertificate {
            @([PSCustomObject]@{ Name = 'tls-cert'; Expires = [datetime]::UtcNow.AddDays(-1) })
        }
        $result = Get-KeyVaultFindings -Subscription $script:Sub -ExpiryWarningDays 30
        $f = $result.Findings | Where-Object FindingType -eq 'CertificateExpired'
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'CRITICAL'
    }

    It 'flags certificate expiring within warning window' {
        $vault = New-Vault
        Mock Get-AzKeyVault { @($vault) }
        Mock Get-AzKeyVaultCertificate {
            @([PSCustomObject]@{ Name = 'soon-cert'; Expires = [datetime]::UtcNow.AddDays(5) })
        }
        $result = Get-KeyVaultFindings -Subscription $script:Sub -ExpiryWarningDays 30
        $f = $result.Findings | Where-Object FindingType -eq 'CertificateExpiringSoon'
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'CRITICAL'  # <=7 days → score 8 → CRITICAL
    }
}

# ── Expiry: Keys ─────────────────────────────────────────────────────────────

Describe 'Get-KeyVaultFindings — key expiry' {
    It 'flags expired key as CRITICAL' {
        $vault = New-Vault
        Mock Get-AzKeyVault { @($vault) }
        Mock Get-AzKeyVaultKey {
            @([PSCustomObject]@{ Name = 'cmk-key'; Expires = [datetime]::UtcNow.AddDays(-10) })
        }
        $result = Get-KeyVaultFindings -Subscription $script:Sub -ExpiryWarningDays 30
        $f = $result.Findings | Where-Object FindingType -eq 'KeyExpired'
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'CRITICAL'
    }
}

# ── Empty vault ───────────────────────────────────────────────────────────────

Describe 'Get-KeyVaultFindings — no vaults' {
    It 'returns zero findings when no vaults exist' {
        Mock Get-AzKeyVault { @() }
        $result = Get-KeyVaultFindings -Subscription $script:Sub
        $result.Findings.Count | Should -Be 0
        $result.VaultCount | Should -Be 0
    }
}

# ── Get-ExpiryFinding helpers ─────────────────────────────────────────────────

Describe 'Get-ExpiryFinding' {
    It 'returns CRITICAL for expired item' {
        $f = Get-ExpiryFinding -ItemName 'sec' -VaultName 'v' -ItemType 'Secret' `
            -ExpiryDate ([datetime]::UtcNow.AddDays(-1)) `
            -ResourceGroup 'rg' -Subscription 'sub' -SubscriptionId 'id' -WarningDays 30
        $f.Severity | Should -Be 'CRITICAL'
        $f.FindingType | Should -Be 'SecretExpired'
    }

    It 'returns null for item expiring after warning window' {
        $f = Get-ExpiryFinding -ItemName 'sec' -VaultName 'v' -ItemType 'Secret' `
            -ExpiryDate ([datetime]::UtcNow.AddDays(60)) `
            -ResourceGroup 'rg' -Subscription 'sub' -SubscriptionId 'id' -WarningDays 30
        $f | Should -BeNullOrEmpty
    }

    It 'uses HIGH severity for item expiring 8-14 days from now' {
        $f = Get-ExpiryFinding -ItemName 'sec' -VaultName 'v' -ItemType 'Secret' `
            -ExpiryDate ([datetime]::UtcNow.AddDays(10)) `
            -ResourceGroup 'rg' -Subscription 'sub' -SubscriptionId 'id' -WarningDays 30
        $f.Severity | Should -Be 'HIGH'
        $f.FindingType | Should -Be 'SecretExpiringSoon'
    }
}

# ── ConvertTo-JsonReport ──────────────────────────────────────────────────────

Describe 'ConvertTo-JsonReport' {
    It 'returns correct summary counts' {
        $findings = @(
            [PSCustomObject]@{ FindingType='PurgeProtectionDisabled'; VaultName='v1'; ItemName=''; ResourceGroup='rg'; Subscription='sub'; SubscriptionId='id'; Severity='HIGH'; Score=7; Recommendation='...' },
            [PSCustomObject]@{ FindingType='SoftDeleteDisabled'; VaultName='v2'; ItemName=''; ResourceGroup='rg'; Subscription='sub'; SubscriptionId='id'; Severity='CRITICAL'; Score=8; Recommendation='...' }
        )
        $report = ConvertTo-JsonReport -Findings $findings -TenantId 'tenant-001' -VaultCount 2
        $report.summary.critical | Should -Be 1
        $report.summary.high | Should -Be 1
        $report.summary.total_findings | Should -Be 2
        $report.vaults_scanned | Should -Be 2
    }
}
