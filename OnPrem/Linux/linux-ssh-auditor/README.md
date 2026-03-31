# 🔐 Linux SSH Hardening Auditor

Checks SSH daemon configuration hardening by reading the effective running configuration via `sshd -T` — the merged, applied config, not just the config file.

---

## ⚙️ Requirements

- Python 3.7+
- `sshd -T` requires root on most distributions — run with `sudo` to get full results. Without it all 21 checks return N/A and are excluded from scoring; the report will display a note explaining how many checks were skipped.

---

## 🚀 Usage

```bash
# Full audit with sudo (recommended — enables sshd -T config dump)
sudo python3 linux_ssh_auditor.py --format all

# Without sudo — runs but all checks return N/A (sshd -T unavailable)
python3 linux_ssh_auditor.py --format all
```

---

## ✨ Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--output`, `-o` | `ssh_report` | Output file prefix |
| `--format`, `-f` | `all` | `json` \| `csv` \| `html` \| `all` \| `stdout` |

---

## 📋 Checks (21 total)

### Configuration checks (16)

| Parameter | Expected | Severity | Description |
|-----------|----------|----------|-------------|
| `PermitRootLogin` | `no` | CRITICAL | Root login fully disabled |
| `PermitEmptyPasswords` | `no` | CRITICAL | Empty password login blocked |
| `PasswordAuthentication` | `no` | HIGH | Key-based auth enforced |
| `PubkeyAuthentication` | `yes` | HIGH | Public key auth enabled |
| `StrictModes` | `yes` | HIGH | Enforce `.ssh` directory permissions |
| `HostbasedAuthentication` | `no` | MEDIUM | Host-based trust disabled |
| `IgnoreRhosts` | `yes` | MEDIUM | `.rhosts`/`.shosts` ignored |
| `X11Forwarding` | `no` | MEDIUM | X11 tunnelling disabled |
| `LogLevel` | `VERBOSE` or `INFO` | MEDIUM | Audit-grade logging active |
| `MaxAuthTries` | `≤ 4` | MEDIUM | Brute-force throttle |
| `LoginGraceTime` | `≤ 60s` | MEDIUM | Unauthenticated connection timeout |
| `AllowAgentForwarding` | `no` | LOW | Agent forwarding disabled |
| `AllowTcpForwarding` | `no` | LOW | TCP tunnelling disabled |
| `UsePAM` | `yes` | LOW | PAM integration active |
| `ClientAliveInterval` | `≤ 300s` | LOW | Idle session timeout |
| `ClientAliveCountMax` | `≤ 3` | LOW | Max keepalive misses |

### Crypto checks (5)

Checks use a **denylist** approach — FAIL if any weak algorithm appears in the value. If the key is absent from `sshd -T` output (OpenSSH 8+ compiled-in modern defaults), the check is skipped rather than failed.

| Parameter | Weak algorithms flagged | Severity |
|-----------|------------------------|----------|
| `Ciphers` | `arcfour*`, `*-cbc` | HIGH |
| `MACs` | `hmac-md5*`, `hmac-sha1`, `umac-64*` | HIGH |
| `KexAlgorithms` | `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1` | HIGH |
| `HostKeyAlgorithms` | `ssh-dss` | HIGH |
| `PubkeyAcceptedAlgorithms` | `ssh-dss` | MEDIUM |

---

## 🔍 Data Source

- `sshd -T` — dumps the full merged effective SSH daemon configuration including compiled-in defaults, `sshd_config`, and all `Include` drop-ins. More accurate than parsing `sshd_config` directly.

---

## 📊 Output Files

All files are created with owner-only permissions (mode 600).

- `ssh_report.json` — machine-readable full report
- `ssh_report.csv` — one row per finding
- `ssh_report.html` — colour-coded HTML summary

---

## 🧪 Running Tests

```bash
# From repo root
pip install pytest
pytest OnPrem/Linux/linux-ssh-auditor/tests/ --import-mode=importlib -v
```

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
