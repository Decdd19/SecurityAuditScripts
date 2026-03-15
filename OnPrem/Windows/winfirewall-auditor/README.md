# Windows Firewall Auditor

Audits Windows Firewall profiles and rules for dangerous misconfigurations, open ports, and logging gaps.

## Requirements

- PowerShell 5.1+ or PowerShell 7+
- Run as local administrator (required to read firewall rules)
- No additional modules — uses built-in `NetSecurity` module

## Usage

```powershell
# Full audit — writes winfirewall_report.json, .csv, .html
.\winfirewall_auditor.ps1

# HTML report only
.\winfirewall_auditor.ps1 -Format html -Output my_fw_report

# Print JSON to terminal
.\winfirewall_auditor.ps1 -Format stdout
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Output` | `winfirewall_report` | Output file prefix |
| `-Format` | `all` | `json` \| `csv` \| `html` \| `all` \| `stdout` |

## Checks

| Finding | Score | Severity | Description |
|---------|-------|----------|-------------|
| `FirewallProfileDisabled` | 9 | CRITICAL | A firewall profile (Domain/Private/Public) is disabled |
| `InboundDefaultAllow` | 8 | CRITICAL | A profile allows inbound connections by default |
| `RDPOpenToAll` | 10 | CRITICAL | RDP (3389) is open to any source address |
| `WinRMOpenToAll` | 9 | CRITICAL | WinRM (5985/5986) is open to any source |
| `SMBOpenToAll` | 9 | CRITICAL | SMB (445) open to any source on non-Domain profile |
| `TooManyAllowAllRules` | 5 | MEDIUM | More than 10 any-source allow rules (noisy rule set) |
| `NoLogDroppedPackets` | 4 | MEDIUM | A profile is not logging dropped packets |
| `ICMPEchoPublicOpen` | 2 | LOW | ICMP echo open to any source on Public profile |
| `OutboundDefaultAllow` | 2 | LOW | A profile allows all outbound by default |

## Output Files

All files are written with owner-only permissions (mode 600 / Windows ACL restricted).

- `winfirewall_report.json` — machine-readable full report
- `winfirewall_report.csv` — one row per finding
- `winfirewall_report.html` — colour-coded HTML summary

## Running Tests

```powershell
# Requires Pester 5+
Install-Module Pester -MinimumVersion 5.0 -Force -Scope CurrentUser
Invoke-Pester .\tests\winfirewall_auditor.Tests.ps1 -Output Detailed
```
