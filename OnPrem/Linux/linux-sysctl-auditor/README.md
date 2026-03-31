# 🔧 Linux Sysctl Hardening Auditor

Audits kernel security parameters via `sysctl` for CIS Benchmark compliance across network, TCP, kernel, and filesystem hardening pillars.

---

## ⚙️ Requirements

- Python 3.7+
- No elevated privileges required — `sysctl` parameters are world-readable

---

## 🚀 Usage

```bash
# Full audit — writes sysctl_report.json, .csv, .html
python3 linux_sysctl_auditor.py --format all

# HTML report only
python3 linux_sysctl_auditor.py --format html --output sysctl_report
```

---

## ✨ Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--output`, `-o` | `sysctl_report` | Output file prefix |
| `--format`, `-f` | `all` | `json` \| `csv` \| `html` \| `all` \| `stdout` |

---

## 📋 Checks

24 CIS Benchmark parameters checked across four pillars.

| Parameter | Severity | Description |
|-----------|----------|-------------|
| `net.ipv4.ip_forward` | HIGH | IP forwarding disabled (router mode off) |
| `net.ipv6.conf.all.forwarding` | HIGH | IPv6 forwarding disabled |
| `net.ipv4.conf.all.send_redirects` | MEDIUM | ICMP redirects sending disabled |
| `net.ipv4.conf.default.send_redirects` | MEDIUM | ICMP redirects sending disabled (default) |
| `net.ipv4.conf.all.accept_redirects` | MEDIUM | ICMP redirect acceptance disabled |
| `net.ipv4.conf.default.accept_redirects` | MEDIUM | ICMP redirect acceptance disabled (default) |
| `net.ipv6.conf.all.accept_redirects` | MEDIUM | IPv6 ICMP redirect acceptance disabled |
| `net.ipv6.conf.default.accept_redirects` | MEDIUM | IPv6 ICMP redirect acceptance disabled (default) |
| `net.ipv4.conf.all.accept_source_route` | HIGH | Source routing rejected |
| `net.ipv4.conf.default.accept_source_route` | HIGH | Source routing rejected (default) |
| `net.ipv6.conf.all.accept_source_route` | HIGH | IPv6 source routing rejected |
| `net.ipv4.conf.all.rp_filter` | HIGH | Reverse path filter enabled (anti-spoofing) |
| `net.ipv4.conf.default.rp_filter` | HIGH | Reverse path filter enabled (default) |
| `net.ipv4.icmp_ignore_bogus_error_responses` | LOW | Bogus ICMP error responses ignored |
| `net.ipv4.icmp_echo_ignore_broadcasts` | MEDIUM | ICMP echo broadcasts ignored (smurf protection) |
| `net.ipv4.tcp_syncookies` | HIGH | SYN cookies enabled (SYN flood protection) |
| `net.ipv4.tcp_timestamps` | LOW | TCP timestamps disabled (uptime leak) |
| `kernel.randomize_va_space` | HIGH | ASLR fully enabled (=2) |
| `kernel.dmesg_restrict` | MEDIUM | dmesg restricted to root |
| `kernel.kptr_restrict` | MEDIUM | Kernel pointer restriction enabled |
| `kernel.yama.ptrace_scope` | MEDIUM | ptrace restricted to parent processes |
| `fs.protected_hardlinks` | MEDIUM | Protected hardlinks enabled |
| `fs.protected_symlinks` | MEDIUM | Protected symlinks enabled |
| `fs.suid_dumpable` | MEDIUM | SUID coredumps disabled |

Parameters unavailable on the running kernel (e.g., IPv6 not loaded) are reported as `N/A` and excluded from scoring.

### Remediation

Non-compliant parameters are reported with a fix command. Apply permanently via:

```bash
# /etc/sysctl.d/99-hardening.conf
net.ipv4.ip_forward = 0
kernel.randomize_va_space = 2
# … add each flagged parameter

sysctl -p /etc/sysctl.d/99-hardening.conf
```

---

## 📊 Output Files

All files are created with owner-only permissions (mode 600).

- `sysctl_report.json` — machine-readable full report with per-param findings and summary
- `sysctl_report.csv` — one row per parameter with compliance status and remediation
- `sysctl_report.html` — colour-coded HTML summary with overall risk rating

---

## 🧪 Running Tests

```bash
# From repo root
pip install pytest
pytest OnPrem/Linux/linux-sysctl-auditor/tests/ -v
```

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
