# Linux Firewall & Logging Auditor

Auto-detects and audits the active firewall backend (iptables, nftables, ufw, or firewalld) and checks auditd and syslog configuration.

## Requirements

- Python 3.7+
- Run as root (`sudo`) for iptables, auditctl, and systemctl access

## Usage

```bash
# Full audit — writes fw_report.json, .csv, .html
sudo python3 linux_firewall_auditor.py

# HTML report only
sudo python3 linux_firewall_auditor.py --format html --output my_fw_report

# Print JSON to terminal
sudo python3 linux_firewall_auditor.py --format stdout
```

## Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--output`, `-o` | `fw_report` | Output file prefix |
| `--format`, `-f` | `all` | `json` \| `csv` \| `html` \| `all` \| `stdout` |

## Backend Detection

The script auto-detects which firewall is active in this order:

1. **ufw** — checks `ufw status` for "Status: active"
2. **firewalld** — checks `firewall-cmd --state`
3. **nftables** — checks `nft list ruleset`
4. **iptables** — checks `iptables -L -n`
5. **none** — no firewall detected (immediate CRITICAL finding)

## Checks

| Finding | Score | Severity | Description |
|---------|-------|----------|-------------|
| `NoFirewallActive` | 9 | CRITICAL | No active firewall backend detected |
| `AllowAllInputRule` | 9 | CRITICAL | Rule accepting all input traffic from any source |
| `DockerBypassesIptables` | 8 | CRITICAL | Docker configured with `iptables: false` |
| `UFWInactive` | 8 | CRITICAL | UFW is installed but not active |
| `DefaultPolicyAccept` | 8 | CRITICAL | Default INPUT chain/zone policy is ACCEPT |
| `DangerousPortOpenToAll` | 7–10 | HIGH/CRITICAL | Dangerous service port open to 0.0.0.0/0 |
| `IPv6FirewallMissing` | 7 | HIGH | ip6tables INPUT chain has ACCEPT default policy |
| `AuditdNotRunning` | 7 | HIGH | auditd service is not running |
| `AuditdNoExecRules` | 6 | HIGH | auditd has no exec/syscall audit rules configured |
| `SyslogNotConfigured` | 6 | HIGH | No syslog daemon (rsyslog/syslog-ng) is active |
| `ForwardChainPermissive` | 6 | HIGH | FORWARD chain policy is ACCEPT |
| `AuditdNoPrivilegedCommandRules` | 5 | MEDIUM | auditd not auditing privileged command execution |
| `FirewallLoggingDisabled` | 5 | MEDIUM | Firewall drop/reject logging is not configured |
| `NATMasqueradeOpen` | 5 | MEDIUM | NAT masquerade rule present (routing/forwarding risk) |
| `FirewallRulesFlushable` | 3 | MEDIUM | Firewall rules not persistent across reboots |

## Output Files

All files are created with owner-only permissions (mode 600).

- `fw_report.json` — machine-readable full report
- `fw_report.csv` — one row per finding
- `fw_report.html` — colour-coded HTML summary

## Running Tests

```bash
pip install pytest
pytest OnPrem/Linux/linux-firewall-auditor/tests/ -v
```
