# 🔒 BitLocker Auditor

Audits BitLocker drive encryption status on all fixed drives. Checks protection status, encryption method strength, TPM key protector presence, and recovery password configuration.

---

## ✨ Features

- Encryption status per drive — unprotected drives flagged CRITICAL
- Encryption method strength — AES-128 and 3DES flagged as weak (HIGH); XTS-AES-256 preferred
- TPM key protector check — password-only protection flagged as weaker
- Recovery password / key presence check
- Handles no volumes found gracefully (e.g. not running as admin)
- JSON, CSV, and colour-coded HTML output

---

## ⚙️ Requirements

- PowerShell 5.1+ or 7+
- Run as local administrator (`Get-BitLockerVolume` requires admin rights)
- BitLocker feature installed (available on Windows Pro, Enterprise, Server)

---

## 🚀 Usage

```powershell
.\bitlocker_auditor.ps1                              # All formats
.\bitlocker_auditor.ps1 -Format html                 # HTML only
.\bitlocker_auditor.ps1 -Output bl_report            # Custom prefix
.\bitlocker_auditor.ps1 -Format stdout               # Print JSON to terminal
```

---

## 📊 Risk Scoring (per drive)

| Factor | Score Impact |
|--------|-------------|
| BitLocker protection off / not encrypted | +8 (CRITICAL) |
| Weak encryption method (AES-128, 3DES) | +4 (HIGH) |
| Unrecognised encryption method | +2 |
| No TPM key protector | +2 |
| No recovery password / key | +1 |

Overall risk = highest per-drive score.

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | Drive not encrypted |
| 5–7 | HIGH | Weak encryption method |
| 3–4 | MEDIUM | Missing TPM or recovery options |
| 0–2 | LOW | Well-configured encryption |

---

## 🛠️ Remediation

```powershell
# Enable BitLocker with XTS-AES-256 and TPM protector
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -TpmProtector

# Add a recovery password
Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector

# Check current status
Get-BitLockerVolume
```

---

## Running Tests

```powershell
Invoke-Pester .\tests\ -Output Detailed
```

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
