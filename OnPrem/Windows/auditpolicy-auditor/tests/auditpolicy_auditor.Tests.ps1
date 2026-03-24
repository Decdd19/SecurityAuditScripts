BeforeAll {
    # Stub Invoke-Auditpol before dot-sourcing
    function Invoke-Auditpol { @() }

    . (Join-Path $PSScriptRoot '..' 'auditpolicy_auditor.ps1')
}

Describe 'Test-AuditSubcategory' {
    It 'Exact match Success and Failure passes' {
        Test-AuditSubcategory -Current 'Success and Failure' -Required 'Success and Failure' | Should -Be $true
    }

    It 'No Auditing fails Success and Failure requirement' {
        Test-AuditSubcategory -Current 'No Auditing' -Required 'Success and Failure' | Should -Be $false
    }

    It 'Success satisfies Success requirement' {
        Test-AuditSubcategory -Current 'Success' -Required 'Success' | Should -Be $true
    }

    It 'Success and Failure satisfies Success-only requirement' {
        Test-AuditSubcategory -Current 'Success and Failure' -Required 'Success' | Should -Be $true
    }

    It 'Success alone does not satisfy Failure requirement' {
        Test-AuditSubcategory -Current 'Success' -Required 'Failure' | Should -Be $false
    }

    It 'Success and Failure satisfies Failure requirement' {
        Test-AuditSubcategory -Current 'Success and Failure' -Required 'Failure' | Should -Be $true
    }

    It 'No Auditing fails any requirement' {
        Test-AuditSubcategory -Current 'No Auditing' -Required 'Success' | Should -Be $false
        Test-AuditSubcategory -Current 'No Auditing' -Required 'Failure' | Should -Be $false
    }
}

Describe 'Get-AuditPolicyMap' {
    It 'Returns empty hashtable when auditpol returns empty' {
        Mock Invoke-Auditpol { @() }
        $map = Get-AuditPolicyMap
        $map.Count | Should -Be 0
    }

    It 'Parses CSV output correctly' {
        Mock Invoke-Auditpol {
            @(
                'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting',
                'MYPC,System,Logon,{12345},Success and Failure,No Auditing',
                'MYPC,System,Logoff,{67890},Success,No Auditing'
            )
        }
        $map = Get-AuditPolicyMap
        $map['Logon'] | Should -Be 'Success and Failure'
        $map['Logoff'] | Should -Be 'Success'
    }
}

Describe 'Invoke-AuditPolicyAudit' {
    It 'Returns a report with findings' {
        Mock Invoke-Auditpol { @() }
        $report = Invoke-AuditPolicyAudit
        $report.findings.Count | Should -BeGreaterThan 0
    }

    It 'All findings have required keys' {
        Mock Invoke-Auditpol { @() }
        $report = Invoke-AuditPolicyAudit
        foreach ($f in $report.findings) {
            $f.subcategory    | Should -Not -BeNullOrEmpty
            $f.required       | Should -Not -BeNullOrEmpty
            $f.risk_level     | Should -Not -BeNullOrEmpty
            $f.flags.Count    | Should -Be $f.remediations.Count
        }
    }

    It 'All No Auditing produces non-zero overall score' {
        Mock Invoke-Auditpol { @() }  # empty → all map to No Auditing
        $report = Invoke-AuditPolicyAudit
        $report.summary.overall_score | Should -BeGreaterThan 0
    }

    It 'Fully compliant policy produces zero score' {
        # Provide all required subcategories as Success and Failure
        $csvLines = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting')
        foreach ($req in $REQUIRED_SUBCATEGORIES) {
            $csvLines += "MYPC,System,$($req.Name),{0000},Success and Failure,No Auditing"
        }
        Mock Invoke-Auditpol { $csvLines }
        $report = Invoke-AuditPolicyAudit
        $report.summary.overall_score | Should -Be 0
    }
}
