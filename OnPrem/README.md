# On-Premises Security Audit Scripts

Security auditing scripts for on-premises infrastructure: Windows domain-joined environments (Active Directory), standalone Windows machines, and Linux.

---

## Directory Structure

```
OnPrem/
├── Windows/
│   ├── ad-auditor/           # Active Directory domain hygiene (RSAT required)
│   ├── localuser-auditor/    # Windows local users, registry, and service config
│   ├── winfirewall-auditor/  # Windows Firewall profiles and rules
│   ├── smbsigning-auditor/   # SMB signing enforcement (NTLM relay prevention)
│   ├── auditpolicy-auditor/  # Windows audit policy subcategory checks
│   ├── bitlocker-auditor/    # BitLocker drive encryption status
│   └── laps-auditor/         # LAPS deployment coverage and configuration
└── Linux/
    ├── linux-user-auditor/   # Linux users, sudo, SSH, and password policy
    ├── linux-firewall-auditor/ # iptables/nftables/ufw/firewalld + auditd/syslog
    ├── linux-sysctl-auditor/ # 24 CIS kernel parameters via sysctl
    ├── linux-patch-auditor/  # Available updates, auto-update agent, kernel version
    └── linux-ssh-auditor/    # SSH daemon hardening via sshd -T (21 checks)
```

---

## Scripts

| Script | Platform | Domain Required | Language |
|--------|----------|-----------------|----------|
| [ad_auditor.ps1](./Windows/ad-auditor/) | Windows | Yes | PowerShell |
| [localuser_auditor.ps1](./Windows/localuser-auditor/) | Windows | No | PowerShell |
| [winfirewall_auditor.ps1](./Windows/winfirewall-auditor/) | Windows | No | PowerShell |
| [smbsigning_auditor.ps1](./Windows/smbsigning-auditor/) | Windows | No | PowerShell |
| [auditpolicy_auditor.ps1](./Windows/auditpolicy-auditor/) | Windows | No | PowerShell |
| [bitlocker_auditor.ps1](./Windows/bitlocker-auditor/) | Windows | No | PowerShell |
| [laps_auditor.ps1](./Windows/laps-auditor/) | Windows | Yes (domain-joined) | PowerShell |
| [linux_user_auditor.py](./Linux/linux-user-auditor/) | Linux | No | Python |
| [linux_firewall_auditor.py](./Linux/linux-firewall-auditor/) | Linux | No | Python |
| [linux_sysctl_auditor.py](./Linux/linux-sysctl-auditor/) | Linux | No | Python |
| [linux_patch_auditor.py](./Linux/linux-patch-auditor/) | Linux | No | Python |
| [linux_ssh_auditor.py](./Linux/linux-ssh-auditor/) | Linux | No | Python |

---

## Requirements

### Windows (PowerShell scripts)

- PowerShell 7+ (or Windows PowerShell 5.1)
- **ad-auditor only:** RSAT ActiveDirectory module — install via:
  ```powershell
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
  # or:
  Install-WindowsFeature RSAT-AD-PowerShell  # on Windows Server
  ```
- Run as a domain user with read access (ad-auditor) or local administrator (localuser-auditor, winfirewall-auditor)

### Linux (Python scripts)

- Python 3.7+
- Run as root (`sudo`) for full access to `/etc/shadow`, iptables, auditctl

---

## Quick Start

### Windows — Firewall audit (no domain required)
```powershell
cd SecurityAuditScripts
.\OnPrem\Windows\winfirewall-auditor\winfirewall_auditor.ps1 -Format html
```

### Windows — Local user audit (no domain required)
```powershell
.\OnPrem\Windows\localuser-auditor\localuser_auditor.ps1 -Format all
```

### Windows — Active Directory audit (domain-joined, RSAT required)
```powershell
.\OnPrem\Windows\ad-auditor\ad_auditor.ps1 -Format html -Output ad_report
```

### Linux — User & sudo audit
```bash
sudo python3 OnPrem/Linux/linux-user-auditor/linux_user_auditor.py --format html
```

### Linux — Firewall & logging audit
```bash
sudo python3 OnPrem/Linux/linux-firewall-auditor/linux_firewall_auditor.py --format all
```

### Linux — SSH daemon hardening audit
```bash
sudo python3 OnPrem/Linux/linux-ssh-auditor/linux_ssh_auditor.py --format html
```

---

## Output

All scripts produce up to three output files (owner-only permissions, mode 600):

| Format | File | Contents |
|--------|------|----------|
| JSON | `<prefix>.json` | Full machine-readable report with summary |
| CSV | `<prefix>.csv` | One row per finding, importable to Excel/SIEM |
| HTML | `<prefix>.html` | Colour-coded report with severity cards |

Use `--format stdout` (Python) or `-Format stdout` (PowerShell) to print JSON to terminal without writing files.

---

## Severity Scale

| Score | Label | Colour |
|-------|-------|--------|
| 8–10 | CRITICAL | Red |
| 6–7 | HIGH | Orange |
| 3–5 | MEDIUM | Yellow |
| 0–2 | LOW | Green |

---

## Notes

- All scripts are **read-only** — they query configuration and do not make changes
- Scripts are designed to run **locally on the target machine** — no WinRM, SSH, or remote parameters
- AD script uses ambient domain credentials (run as a domain account with AD read access)
