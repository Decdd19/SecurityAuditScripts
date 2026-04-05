# OnPrem/Windows/winpatch-auditor/tests/winpatch_auditor.Tests.ps1
BeforeAll {
    function Get-HotFix      { param([string]$Id) @() }
    function Get-CimInstance { param([string]$ClassName) [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-1) } }
    function Get-Service     { param([string]$Name, [string]$ErrorAction) [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
    function Get-ItemProperty { param($Path, $Name, $ErrorAction) $null }
    . "$PSScriptRoot/../winpatch_auditor.ps1"
}

Describe 'Get-WinPatchFindings' {
    # ── PATCH-01: Last patch age ──────────────────────────────────────────────

    It '1. PATCH-01 flags CRITICAL when last patch > 60 days ago' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-65); HotFixID = 'KB111111' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }
        Mock New-UpdateSearcher { throw 'skip' }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'LastPatchAge'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
        $finding.Score    | Should -Be 9
    }

    It '2. PATCH-01 flags HIGH when last patch 31-60 days ago' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-45); HotFixID = 'KB222222' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'LastPatchAge'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
        $finding.Score    | Should -Be 7
    }

    It '3. PATCH-01 flags MEDIUM when last patch 15-30 days ago' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-20); HotFixID = 'KB333333' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'LastPatchAge'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
        $finding.Score    | Should -Be 4
    }

    It '4. PATCH-01 produces no finding when last patch <= 14 days ago' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-7); HotFixID = 'KB444444' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'LastPatchAge'
        $finding | Should -BeNullOrEmpty
    }

    It '5. PATCH-01 flags CRITICAL when no hotfixes found' {
        Mock Get-HotFix { @() }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'LastPatchAge'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
        $finding.Score    | Should -Be 9
    }

    # ── PATCH-02: Uptime ──────────────────────────────────────────────────────

    It '6. PATCH-02 flags HIGH when uptime > 60 days' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB555555' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-65) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'UptimeExceeded'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
        $finding.Score    | Should -Be 7
    }

    It '7. PATCH-02 flags MEDIUM when uptime 31-60 days' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB666666' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-45) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'UptimeExceeded'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
        $finding.Score    | Should -Be 4
    }

    It '8. PATCH-02 produces no finding when uptime <= 30 days' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB777777' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-10) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'UptimeExceeded'
        $finding | Should -BeNullOrEmpty
    }

    # ── PATCH-03: Pending reboot ──────────────────────────────────────────────

    It '9. PATCH-03 flags HIGH when RebootRequired registry key exists' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB999999' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty {
            param($Path, $Name, $ErrorAction)
            # Return a non-null object for the RebootRequired WU key path
            if ($Path -like '*WindowsUpdate*Auto Update*RebootRequired*') {
                return [PSCustomObject]@{}
            }
            return $null
        }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'PendingRebootRequired'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
        $finding.Score    | Should -Be 7
        $result.summary.pending_reboot | Should -Be $true
    }

    It '10. PATCH-03 produces no finding when no reboot-pending keys present' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB888888' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'PendingRebootRequired'
        $finding | Should -BeNullOrEmpty
        $result.summary.pending_reboot | Should -Be $false
    }

    # ── PATCH-04: WU service disabled ─────────────────────────────────────────

    It '11. PATCH-04 flags HIGH when wuauserv is disabled' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB777000' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service {
            [PSCustomObject]@{ Name = 'wuauserv'; Status = 'Stopped'; StartType = 'Disabled' }
        }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'WindowsUpdateServiceDisabled'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
        $finding.Score    | Should -Be 8
    }

    It '12. PATCH-04 produces no finding when wuauserv is running' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB666000' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service {
            [PSCustomObject]@{ Name = 'wuauserv'; Status = 'Running'; StartType = 'Automatic' }
        }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'WindowsUpdateServiceDisabled'
        $finding | Should -BeNullOrEmpty
    }

    # ── PATCH-05: Auto-update disabled ────────────────────────────────────────

    It '13. PATCH-05 flags MEDIUM when AUOptions = 1 (disabled)' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB555000' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty {
            param($Path, $Name, $ErrorAction)
            if ($Path -like '*WindowsUpdate*AU*' -and $Name -eq 'AUOptions') {
                return [PSCustomObject]@{ AUOptions = 1 }
            }
            return $null
        }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'AutoUpdateDisabled'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
        $finding.Score    | Should -Be 5
        $result.summary.auto_update_enabled | Should -Be $false
    }

    It '13b. PATCH-05 flags MEDIUM when AUOptions = 2 (notify-only)' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB444000' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty {
            param($Path, $Name, $ErrorAction)
            if ($Path -like '*WindowsUpdate*AU*' -and $Name -eq 'AUOptions') {
                return [PSCustomObject]@{ AUOptions = 2 }
            }
            return $null
        }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'AutoUpdateDisabled'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
        $finding.Score    | Should -Be 5
        $result.summary.auto_update_enabled | Should -Be $false
    }

    # ── PATCH-03: Additional reboot-pending registry paths ────────────────────

    It '9b. PATCH-03 flags HIGH when PendingFileRenameOperations key is set' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB111000' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty {
            param($Path, $Name, $ErrorAction)
            if ($Path -like '*Session Manager*' -and $Name -eq 'PendingFileRenameOperations') {
                return [PSCustomObject]@{ PendingFileRenameOperations = @('\??\C:\TEMP\old.dll') }
            }
            return $null
        }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'PendingRebootRequired'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
        $result.summary.pending_reboot | Should -Be $true
    }

    It '9c. PATCH-03 flags HIGH when SoftwareDistribution RebootRequired key exists' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB222000' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty {
            param($Path, $Name, $ErrorAction)
            if ($Path -like '*SoftwareDistribution*RebootRequired*') {
                return [PSCustomObject]@{}
            }
            return $null
        }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'PendingRebootRequired'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
        $result.summary.pending_reboot | Should -Be $true
    }

    # ── PATCH-06: WSUS configured ─────────────────────────────────────────────

    It '14. PATCH-06 surfaces WsusConfigured finding when WUServer key present' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB333000' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty {
            param($Path, $Name, $ErrorAction)
            if ($Path -like '*WindowsUpdate' -and $Name -eq 'WUServer') {
                return [PSCustomObject]@{ WUServer = 'http://wsus.corp.local:8530' }
            }
            return $null
        }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'WsusConfigured'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'LOW'
        $finding.Score    | Should -Be 0
        $result.summary.wsus_server | Should -Be 'http://wsus.corp.local:8530'
    }

    It '15. PATCH-06 produces no WsusConfigured finding when WUServer absent' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB444001' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'WsusConfigured'
        $finding | Should -BeNullOrEmpty
        $result.summary.wsus_server | Should -BeNullOrEmpty
    }

    # ── PATCH-07: Pending security updates via COM API ────────────────────────

    It '16. PATCH-07 flags CRITICAL when COM API returns a Critical pending update' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB100' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }
        Mock New-UpdateSearcher {
            $fakeUpdate = [PSCustomObject]@{ MsrcSeverity = 'Critical'; Title = 'Critical Security Update' }
            $fakeResult = [PSCustomObject]@{ Updates = @($fakeUpdate) }
            $fakeSearcher = [PSCustomObject]@{}
            $fakeSearcher | Add-Member -MemberType ScriptMethod -Name Search -Value ({ param($criteria) $fakeResult }.GetNewClosure())
            return $fakeSearcher
        }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 60
        $finding = $result.findings | Where-Object FindingType -eq 'PendingSecurityUpdates'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
        $finding.Score    | Should -Be 9
        $result.summary.com_api_used | Should -Be $true
        $result.summary.pending_updates.critical | Should -Be 1
    }

    It '17. PATCH-07 produces no PendingSecurityUpdates finding when COM API returns empty' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB200' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }
        Mock New-UpdateSearcher {
            $fakeResult   = [PSCustomObject]@{ Updates = @() }
            $fakeSearcher = [PSCustomObject]@{}
            $fakeSearcher | Add-Member -MemberType ScriptMethod -Name Search -Value ({ param($criteria) $fakeResult }.GetNewClosure())
            return $fakeSearcher
        }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 60
        $finding = $result.findings | Where-Object FindingType -eq 'PendingSecurityUpdates'
        $finding | Should -BeNullOrEmpty
        $result.summary.com_api_used          | Should -Be $true
        $result.summary.pending_updates.total | Should -Be 0
    }

    # ── PATCH-08: COM API failure ─────────────────────────────────────────────

    It '18. PATCH-08 flags MEDIUM when COM API throws' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB300' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }
        Mock New-UpdateSearcher { throw 'COM object not available' }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 60
        $finding = $result.findings | Where-Object FindingType -eq 'WindowsUpdateQueryFailed'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
        $finding.Score    | Should -Be 4
        $result.summary.com_api_used | Should -Be $false
    }
}

Describe 'Get-SeverityLabel' {
    It 'returns CRITICAL for score 8+' {
        Get-SeverityLabel 9 | Should -Be 'CRITICAL'
    }
    It 'returns HIGH for score 6-7' {
        Get-SeverityLabel 7 | Should -Be 'HIGH'
    }
    It 'returns MEDIUM for score 3-5' {
        Get-SeverityLabel 4 | Should -Be 'MEDIUM'
    }
    It 'returns LOW for score 0-2' {
        Get-SeverityLabel 1 | Should -Be 'LOW'
    }
}
