# 🔐 SMB Signing Auditor

Audits SMB signing configuration on Windows server and client. Missing server-side SMB signing enforcement is one of the most common prerequisites for NTLM relay attacks — a critical vector in internal network compromise.

---

## ✨ Features

- Server SMB signing required (`RequireSecuritySignature`) — missing → HIGH risk
- Server SMB signing enabled (`EnableSecuritySignature`) — inconsistency check
- Client SMB signing required — missing enables relay from client connections
- Client SMB signing enabled — informational flag
- JSON, CSV, and colour-coded HTML output

---

## ⚙️ Requirements

- PowerShell 5.1+ or 7+
- Run as local administrator (required to read SMB configuration)
- `SmbShare` module (included in Windows by default)

---

## 🚀 Usage

```powershell
.\smbsigning_auditor.ps1                           # All formats
.\smbsigning_auditor.ps1 -Format html              # HTML only
.\smbsigning_auditor.ps1 -Output smb_report        # Custom prefix
.\smbsigning_auditor.ps1 -Format stdout            # Print JSON to terminal
```

---

## 📊 Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| Server SMB signing not required | +5 |
| Client SMB signing not required | +2 |
| Server SMB signing not enabled | +2 |
| Client SMB signing not enabled | +1 |

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | Multiple signing gaps, high relay risk |
| 5–7 | HIGH | Server signing not required |
| 3–4 | MEDIUM | Partial signing gaps |
| 0–2 | LOW | Minor or no gaps |

---

## 🛠️ Remediation

```powershell
# Require SMB signing on the server
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

# Require SMB signing on the client
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
```

These changes take effect immediately without a reboot. Deploy via Group Policy for domain-wide enforcement:
`Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options`

---

## Running Tests

```powershell
Invoke-Pester .\tests\ -Output Detailed
```

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
