# 📋 Windows Audit Policy Auditor

Audits Windows audit policy subcategory configuration against CIS and security baseline requirements. Missing audit policies mean attacker activity — logons, privilege use, process execution — goes undetected and unloggable.

---

## ✨ Features

Checks 15 critical audit subcategories across key Windows audit categories:

| Category | Subcategories Checked |
|----------|----------------------|
| Logon/Logoff | Logon, Logoff, Account Lockout, Special Logon |
| Account Logon | Credential Validation, Kerberos Authentication, Kerberos Service Ticket |
| Detailed Tracking | Process Creation |
| Policy Change | Audit Policy Change, Authentication Policy Change |
| Privilege Use | Sensitive Privilege Use |
| System | Security System Extension |
| Account Management | User Account Management, Security Group Management |
| Object Access | Object Access (Failure) |

- Uses `auditpol.exe /get /category:* /r` (machine-parseable CSV output)
- Each subcategory flagged as compliant/non-compliant with required setting
- JSON, CSV, and colour-coded HTML output

---

## ⚙️ Requirements

- PowerShell 5.1+ or 7+
- Run as local administrator (required for `auditpol.exe`)

---

## 🚀 Usage

```powershell
.\auditpolicy_auditor.ps1                              # All formats
.\auditpolicy_auditor.ps1 -Format html                 # HTML only
.\auditpolicy_auditor.ps1 -Output policy_report        # Custom prefix
.\auditpolicy_auditor.ps1 -Format stdout               # Print JSON to terminal
```

---

## 📊 Risk Scoring

Each subcategory contributes to the overall score when non-compliant:

| Subcategory | Score if missing |
|-------------|-----------------|
| Logon, Process Creation | +4 each |
| Credential Validation, Kerberos, Sensitive Privilege Use, User Account Management, Audit Policy Change | +3 each |
| Account Lockout, Special Logon, Object Access | +2–3 each |
| Others | +2 each |

Overall score is the sum of missing subcategory scores, clamped to 10.

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | Multiple critical subcategories missing |
| 5–7 | HIGH | Key subcategories not audited |
| 3–4 | MEDIUM | Some gaps in coverage |
| 0–2 | LOW | Mostly compliant |

---

## 🛠️ Quick Fix

To enable all required subcategories at once:

```powershell
# Enable all required subcategories (Success and Failure)
$subcategories = @(
    'Logon', 'Logoff', 'Account Lockout', 'Special Logon',
    'Credential Validation', 'Kerberos Authentication Service',
    'Kerberos Service Ticket Operations', 'Process Creation',
    'Audit Policy Change', 'Authentication Policy Change',
    'Sensitive Privilege Use', 'Security System Extension',
    'User Account Management', 'Security Group Management'
)
foreach ($sub in $subcategories) {
    auditpol.exe /set /subcategory:"$sub" /success:enable /failure:enable
}
# Object Access — Failure only
auditpol.exe /set /subcategory:"Object Access" /failure:enable
```

Or deploy via Group Policy: `Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration`

---

## Running Tests

```powershell
Invoke-Pester .\tests\ -Output Detailed
```

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
