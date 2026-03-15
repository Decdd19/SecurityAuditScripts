# Linux User & Sudo Auditor

Audits local user accounts, sudo configuration, SSH settings, and password policy on Linux systems.

## Requirements

- Python 3.7+
- Run as root (`sudo`) for access to `/etc/shadow` and lastlog data

## Usage

```bash
# Full audit — writes user_report.json, .csv, .html
sudo python3 linux_user_auditor.py

# HTML report only
sudo python3 linux_user_auditor.py --format html --output my_report

# Print JSON to terminal
sudo python3 linux_user_auditor.py --format stdout
```

## Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--output`, `-o` | `user_report` | Output file prefix |
| `--format`, `-f` | `all` | `json` \| `csv` \| `html` \| `all` \| `stdout` |

## Checks

| Finding | Score | Severity | Description |
|---------|-------|----------|-------------|
| `EmptyPasswordHash` | 10 | CRITICAL | User account with no password hash (empty field in /etc/shadow) |
| `PasswordlessRootEquivalent` | 10 | CRITICAL | `NOPASSWD: ALL` sudo rule granting passwordless root |
| `UidZeroNonRoot` | 9 | CRITICAL | Non-root account with UID 0 |
| `SudoAllNopasswd` | 9 | CRITICAL | NOPASSWD sudo rule for any command |
| `WorldWritableSudoers` | 8 | CRITICAL | /etc/sudoers or a file in sudoers.d is world-writable |
| `DirectRootSSH` | 8 | CRITICAL | sshd_config has `PermitRootLogin yes` |
| `SSHAuthorizedKeysWorldWritable` | 8 | CRITICAL | An authorized_keys file is world-writable |
| `SudoVersionVulnerable` | 7 | HIGH | sudo version below 1.9.5p2 (CVE-2021-3156 era) |
| `SudoAllCommandsGranted` | 7 | HIGH | ALL commands granted via sudo (with password) |
| `WeakPasswordPolicy` | 6 | HIGH | PASS_MIN_LEN < 12 in /etc/login.defs |
| `SSHPasswordAuthEnabled` | 6 | HIGH | SSH password authentication enabled |
| `NoPasswordExpiry` | 5 | MEDIUM | PASS_MAX_DAYS set to 99999 (no expiry) |
| `SudoersIncludesMissing` | 3 | MEDIUM | sudoers #include references a missing file |
| `StaleUser` | 4 | MEDIUM | Login-enabled user with no login in 90+ days |
| `HomeDirectoryWorldReadable` | 4 | MEDIUM | User home directory is world-readable |

## Data Sources

- `/etc/passwd` — user accounts and shells
- `/etc/shadow` — password hashes and expiry
- `/etc/sudoers` + `/etc/sudoers.d/*` — sudo rules
- `/etc/ssh/sshd_config` — SSH daemon settings
- `/etc/login.defs` — password policy defaults
- `lastlog` — last login timestamps

## Output Files

All files are created with owner-only permissions (mode 600).

- `user_report.json` — machine-readable full report
- `user_report.csv` — one row per finding
- `user_report.html` — colour-coded HTML summary

## Running Tests

```bash
# From repo root
pip install pytest
pytest OnPrem/Linux/linux-user-auditor/tests/ -v
```
