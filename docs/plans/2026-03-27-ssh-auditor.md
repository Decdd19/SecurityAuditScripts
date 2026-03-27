# SSH Auditor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `linux_ssh_auditor.py` — a Linux SSH hardening auditor using `sshd -T` for effective config, with 21 checks, standardised JSON/CSV/HTML output, and full integration into `audit.py` and `exec_summary.py`.

**Architecture:** Calls `sshd -T` to get the full merged effective SSH config as a flat `key value` dict. Runs 21 checks (16 config + 5 crypto) against that dict. Outputs `ssh_report.json/csv/html` in the identical format used by all other Linux auditors.

**Tech Stack:** Python 3.12, pytest, unittest.mock — no third-party deps.

**Spec:** `docs/specs/2026-03-27-ssh-auditor-design.md`

---

### Task 1: Scaffold module + `run_command` + `get_effective_config`

**Files:**
- Create: `OnPrem/Linux/linux-ssh-auditor/linux_ssh_auditor.py`
- Create: `OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py`

- [ ] **Step 1: Write failing tests for `run_command` and `get_effective_config`**

Create `OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py`:

```python
"""Tests for linux_ssh_auditor.py"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from unittest.mock import patch
import linux_ssh_auditor as lsa


# ── run_command ────────────────────────────────────────────────────────────────

def test_run_command_returns_tuple_on_bad_command():
    stdout, rc = lsa.run_command(['__nonexistent_cmd_xyz__'])
    assert isinstance(stdout, str)
    assert isinstance(rc, int)


# ── get_effective_config ───────────────────────────────────────────────────────

def test_get_effective_config_parses_output():
    sshd_output = "permitrootlogin no\npasswordauthentication yes\nport 22\n"
    with patch.object(lsa, 'run_command', return_value=(sshd_output, 0)):
        config = lsa.get_effective_config()
    assert config['permitrootlogin'] == 'no'
    assert config['passwordauthentication'] == 'yes'
    assert config['port'] == '22'


def test_get_effective_config_returns_empty_on_failure():
    with patch.object(lsa, 'run_command', return_value=('', 1)):
        config = lsa.get_effective_config()
    assert config == {}


def test_get_effective_config_lowercases_keys():
    with patch.object(lsa, 'run_command', return_value=('PermitRootLogin no\n', 0)):
        config = lsa.get_effective_config()
    assert 'permitrootlogin' in config


def test_get_effective_config_handles_multi_word_values():
    with patch.object(lsa, 'run_command', return_value=('ciphers aes128-ctr,aes256-ctr\n', 0)):
        config = lsa.get_effective_config()
    assert config['ciphers'] == 'aes128-ctr,aes256-ctr'
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /path/to/SecurityAuditScripts
python3 -m pytest OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py -v --import-mode=importlib
```

Expected: ERROR — `linux_ssh_auditor` module not found.

- [ ] **Step 3: Create the module with `run_command` and `get_effective_config`**

Create `OnPrem/Linux/linux-ssh-auditor/linux_ssh_auditor.py`:

```python
#!/usr/bin/env python3
"""
Linux SSH Hardening Auditor
============================
Checks SSH daemon configuration via `sshd -T` (effective running config):
- Authentication hardening (root login, password auth, empty passwords)
- Session hardening (X11, forwarding, timeouts, strict modes)
- Logging (log level, PAM)
- Cryptography (weak ciphers, MACs, key exchange algorithms)

Usage:
    sudo python3 linux_ssh_auditor.py
    python3 linux_ssh_auditor.py --format html --output ssh_report
    python3 linux_ssh_auditor.py --format all
"""

import os
import sys
import json
import csv
import socket
import argparse
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

NOW = datetime.now(timezone.utc)


# ── Thin wrapper (mockable in tests) ─────────────────────────────────────────

def run_command(cmd):
    """Run command, return (stdout, returncode). Returns ('', 1) on error."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout, r.returncode
    except Exception:
        return '', 1


# ── Config reader ─────────────────────────────────────────────────────────────

def get_effective_config():
    """Call sshd -T and parse output into a lowercase key→value dict.

    Returns {} if sshd is unavailable or returns non-zero.
    sshd -T outputs one 'key value' pair per line (space-separated).
    Multi-word values (e.g. cipher lists) are preserved as-is.
    """
    stdout, rc = run_command(['sshd', '-T'])
    if rc != 0 or not stdout.strip():
        return {}
    config = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(' ', 1)
        if len(parts) == 2:
            config[parts[0].lower()] = parts[1]
    return config
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py -v --import-mode=importlib
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add OnPrem/Linux/linux-ssh-auditor/linux_ssh_auditor.py \
        OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py
git commit -m "feat(ssh): scaffold module with run_command and get_effective_config"
```

---

### Task 2: `SSH_CHECKS` table + `analyse_ssh` (config checks)

**Files:**
- Modify: `OnPrem/Linux/linux-ssh-auditor/linux_ssh_auditor.py`
- Modify: `OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py`

- [ ] **Step 1: Write failing tests for `analyse_ssh` config checks**

Append to `tests/test_linux_ssh_auditor.py`:

```python
# ── analyse_ssh ────────────────────────────────────────────────────────────────

def test_analyse_ssh_compliant_exact_match():
    """permitrootlogin=no → compliant=True."""
    config = {'permitrootlogin': 'no'}
    findings = lsa.analyse_ssh(config)
    root_finding = next(f for f in findings if f['param'] == 'permitrootlogin')
    assert root_finding['compliant'] is True


def test_analyse_ssh_non_compliant_exact_match():
    """permitrootlogin=yes → compliant=False, severity=CRITICAL."""
    config = {'permitrootlogin': 'yes'}
    findings = lsa.analyse_ssh(config)
    root_finding = next(f for f in findings if f['param'] == 'permitrootlogin')
    assert root_finding['compliant'] is False
    assert root_finding['severity_if_wrong'] == 'CRITICAL'


def test_analyse_ssh_missing_key_returns_none():
    """Key absent from sshd -T → compliant=None (SKIP)."""
    config = {}
    findings = lsa.analyse_ssh(config)
    root_finding = next(f for f in findings if f['param'] == 'permitrootlogin')
    assert root_finding['compliant'] is None


def test_analyse_ssh_maxauthtries_pass_at_boundary():
    """maxauthtries=4 → compliant=True (≤4 passes)."""
    config = {'maxauthtries': '4'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'maxauthtries')
    assert f['compliant'] is True


def test_analyse_ssh_maxauthtries_fail_above_boundary():
    """maxauthtries=5 → compliant=False."""
    config = {'maxauthtries': '5'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'maxauthtries')
    assert f['compliant'] is False


def test_analyse_ssh_logingracetime_pass():
    """logingracetime=60 → compliant=True (≤60)."""
    config = {'logingracetime': '60'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'logingracetime')
    assert f['compliant'] is True


def test_analyse_ssh_logingracetime_fail():
    """logingracetime=120 → compliant=False."""
    config = {'logingracetime': '120'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'logingracetime')
    assert f['compliant'] is False


def test_analyse_ssh_loglevel_verbose_passes():
    """loglevel=VERBOSE → compliant=True."""
    config = {'loglevel': 'VERBOSE'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'loglevel')
    assert f['compliant'] is True


def test_analyse_ssh_loglevel_info_passes():
    """loglevel=INFO → compliant=True."""
    config = {'loglevel': 'INFO'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'loglevel')
    assert f['compliant'] is True


def test_analyse_ssh_loglevel_case_insensitive():
    """loglevel=verbose (lowercase) → compliant=True."""
    config = {'loglevel': 'verbose'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'loglevel')
    assert f['compliant'] is True


def test_analyse_ssh_loglevel_quiet_fails():
    """loglevel=QUIET → compliant=False."""
    config = {'loglevel': 'QUIET'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'loglevel')
    assert f['compliant'] is False


def test_analyse_ssh_finding_has_required_fields():
    """Every finding has all required fields."""
    findings = lsa.analyse_ssh({'permitrootlogin': 'no'})
    for f in findings:
        for field in ('param', 'expected', 'actual', 'compliant',
                      'severity_if_wrong', 'description', 'flag',
                      'remediation', 'risk_level'):
            assert field in f, f"Missing field '{field}' in finding for {f.get('param')}"


def test_analyse_ssh_clientaliveinterval_pass():
    """clientaliveinterval=300 → compliant=True (≤300)."""
    config = {'clientaliveinterval': '300'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'clientaliveinterval')
    assert f['compliant'] is True


def test_analyse_ssh_clientalivecountmax_fail():
    """clientalivecountmax=5 → compliant=False (>3)."""
    config = {'clientalivecountmax': '5'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'clientalivecountmax')
    assert f['compliant'] is False
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py -v --import-mode=importlib
```

Expected: FAIL — `analyse_ssh` not defined.

- [ ] **Step 3: Add `SSH_CHECKS` table and `analyse_ssh` to the module**

Append to `linux_ssh_auditor.py` (after `get_effective_config`):

```python
# ── Check helpers ─────────────────────────────────────────────────────────────

def _eq(expected):
    """Returns check_fn: passes if value == expected (case-insensitive)."""
    def check(val):
        ok = val.strip().lower() == expected.lower()
        return ok, expected
    return check


def _lte(threshold):
    """Returns check_fn: passes if int(value) <= threshold."""
    def check(val):
        try:
            ok = int(val.strip()) <= threshold
        except ValueError:
            ok = False
        return ok, f"≤{threshold}"
    return check


def _loglevel_ok():
    """Passes if loglevel is VERBOSE or INFO."""
    def check(val):
        ok = val.strip().upper() in ('VERBOSE', 'INFO')
        return ok, 'VERBOSE or INFO'
    return check


def _no_weak(weak_patterns):
    """Returns check_fn: passes if none of the weak patterns appear in the value.

    Used for crypto algorithm lists. Each pattern may end with '*' as a wildcard
    meaning 'starts with this prefix'.
    """
    def check(val):
        algos = [a.strip().lower() for a in val.split(',')]
        for algo in algos:
            for pat in weak_patterns:
                if pat.endswith('*'):
                    if algo.startswith(pat[:-1].lower()):
                        return False, f'no weak algorithms ({", ".join(weak_patterns)})'
                else:
                    if algo == pat.lower():
                        return False, f'no weak algorithms ({", ".join(weak_patterns)})'
        return True, f'no weak algorithms ({", ".join(weak_patterns)})'
    return check


# ── SSH checks table ──────────────────────────────────────────────────────────
# (key, check_fn, severity_if_wrong, description, remediation)

SSH_CHECKS = [
    # ── Authentication ────────────────────────────────────────────────────────
    ("permitrootlogin",       _eq("no"),       "CRITICAL",
     "Root login fully disabled",
     "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("permitemptypasswords",  _eq("no"),       "CRITICAL",
     "Empty password login blocked",
     "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("passwordauthentication",_eq("no"),       "HIGH",
     "Key-based authentication enforced (passwords disabled)",
     "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("pubkeyauthentication",  _eq("yes"),      "HIGH",
     "Public key authentication enabled",
     "Set 'PubkeyAuthentication yes' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    # ── Session hardening ─────────────────────────────────────────────────────
    ("strictmodes",           _eq("yes"),      "HIGH",
     "Enforce strict .ssh directory permission checks",
     "Set 'StrictModes yes' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("hostbasedauthentication",_eq("no"),      "MEDIUM",
     "Host-based trust disabled",
     "Set 'HostbasedAuthentication no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("ignorerhosts",          _eq("yes"),      "MEDIUM",
     ".rhosts and .shosts files ignored",
     "Set 'IgnoreRhosts yes' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("x11forwarding",         _eq("no"),       "MEDIUM",
     "X11 tunnelling disabled",
     "Set 'X11Forwarding no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("loglevel",              _loglevel_ok(),  "MEDIUM",
     "Audit-grade logging active (VERBOSE or INFO)",
     "Set 'LogLevel VERBOSE' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("maxauthtries",          _lte(4),         "MEDIUM",
     "Brute-force throttle: max 4 authentication attempts",
     "Set 'MaxAuthTries 4' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("logingracetime",        _lte(60),        "MEDIUM",
     "Unauthenticated connection timeout ≤60 seconds",
     "Set 'LoginGraceTime 60' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("allowagentforwarding",  _eq("no"),       "LOW",
     "SSH agent forwarding disabled (limits lateral movement)",
     "Set 'AllowAgentForwarding no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("allowtcpforwarding",    _eq("no"),       "LOW",
     "TCP tunnelling disabled",
     "Set 'AllowTcpForwarding no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("usepam",                _eq("yes"),      "LOW",
     "PAM integration active",
     "Set 'UsePAM yes' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("clientaliveinterval",   _lte(300),       "LOW",
     "Idle session keepalive interval ≤300 seconds",
     "Set 'ClientAliveInterval 300' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("clientalivecountmax",   _lte(3),         "LOW",
     "Max missed keepalives before disconnect ≤3",
     "Set 'ClientAliveCountMax 3' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    # ── Crypto ────────────────────────────────────────────────────────────────
    ("ciphers",
     _no_weak(["arcfour*", "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
               "blowfish-cbc", "cast128-cbc", "rijndael-cbc*"]),
     "HIGH",
     "No weak CBC/arcfour ciphers in use",
     "Remove CBC/arcfour ciphers from sshd_config Ciphers line; prefer aes*-ctr and chacha20-poly1305"),

    ("macs",
     _no_weak(["hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
               "umac-64*", "hmac-md5-etm*", "hmac-sha1-etm*"]),
     "HIGH",
     "No weak MD5/SHA1 MACs in use",
     "Remove hmac-md5/hmac-sha1/umac-64 from sshd_config MACs line; prefer hmac-sha2-* and umac-128*"),

    ("kexalgorithms",
     _no_weak(["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
               "diffie-hellman-group-exchange-sha1"]),
     "HIGH",
     "No weak Diffie-Hellman key exchange algorithms",
     "Remove group1/group14-sha1 from KexAlgorithms; prefer curve25519-sha256 and ecdh-sha2-nistp*"),

    ("hostkeyalgorithms",
     _no_weak(["ssh-dss"]),
     "HIGH",
     "DSA host key algorithm disabled",
     "Remove ssh-dss from HostKeyAlgorithms; prefer rsa-sha2-256/512 and ecdsa/ed25519"),

    ("pubkeyacceptedalgorithms",
     _no_weak(["ssh-dss"]),
     "MEDIUM",
     "DSA not accepted for public key authentication",
     "Remove ssh-dss from PubkeyAcceptedAlgorithms; prefer rsa-sha2-256/512 and ed25519"),
]


# ── Analysis ──────────────────────────────────────────────────────────────────

def analyse_ssh(config):
    """Run all SSH_CHECKS against the parsed config dict. Returns findings list."""
    severity_colors = {
        'CRITICAL': '#dc3545',
        'HIGH':     '#fd7e14',
        'MEDIUM':   '#ffc107',
        'LOW':      '#28a745',
    }
    findings = []
    for key, check_fn, severity, description, remediation in SSH_CHECKS:
        val = config.get(key)

        if val is None:
            # Key absent from sshd -T — compiled-in default; skip scoring
            _, expected_str = check_fn('yes')  # dummy call to extract expected label
            finding = {
                'param':             key,
                'expected':          expected_str,
                'actual':            'N/A',
                'compliant':         None,
                'severity_if_wrong': severity,
                'description':       description,
                'flag':              f'ℹ️ {key}: not present in sshd -T output',
                'remediation':       None,
                'risk_level':        'LOW',
            }
        else:
            ok, expected_str = check_fn(val)
            if ok:
                finding = {
                    'param':             key,
                    'expected':          expected_str,
                    'actual':            val,
                    'compliant':         True,
                    'severity_if_wrong': severity,
                    'description':       description,
                    'flag':              f'✅ {key} = {val}',
                    'remediation':       None,
                    'risk_level':        'LOW',
                }
            else:
                finding = {
                    'param':             key,
                    'expected':          expected_str,
                    'actual':            val,
                    'compliant':         False,
                    'severity_if_wrong': severity,
                    'description':       description,
                    'flag':              f'⚠️ {key} = {val} (expected {expected_str}): {description}',
                    'remediation':       remediation,
                    'risk_level':        severity,
                }
        findings.append(finding)
    return findings
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py -v --import-mode=importlib
```

Expected: 20 passed.

- [ ] **Step 5: Commit**

```bash
git add OnPrem/Linux/linux-ssh-auditor/linux_ssh_auditor.py \
        OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py
git commit -m "feat(ssh): add SSH_CHECKS table and analyse_ssh"
```

---

### Task 3: Crypto check tests

**Files:**
- Modify: `OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py`

- [ ] **Step 1: Write failing tests for crypto checks**

Append to `tests/test_linux_ssh_auditor.py`:

```python
# ── Crypto checks ──────────────────────────────────────────────────────────────

def test_analyse_ssh_ciphers_clean_passes():
    """Only strong ciphers → compliant=True."""
    config = {'ciphers': 'aes128-ctr,aes256-ctr,chacha20-poly1305@openssh.com'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'ciphers')
    assert f['compliant'] is True


def test_analyse_ssh_ciphers_cbc_fails():
    """CBC cipher present → compliant=False, severity=HIGH."""
    config = {'ciphers': 'aes128-ctr,aes256-cbc'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'ciphers')
    assert f['compliant'] is False
    assert f['severity_if_wrong'] == 'HIGH'


def test_analyse_ssh_ciphers_arcfour_fails():
    """arcfour cipher → compliant=False."""
    config = {'ciphers': 'arcfour,aes128-ctr'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'ciphers')
    assert f['compliant'] is False


def test_analyse_ssh_macs_clean_passes():
    """Strong MACs only → compliant=True."""
    config = {'macs': 'hmac-sha2-256,hmac-sha2-512,umac-128@openssh.com'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'macs')
    assert f['compliant'] is True


def test_analyse_ssh_macs_hmac_md5_fails():
    """hmac-md5 present → compliant=False."""
    config = {'macs': 'hmac-sha2-256,hmac-md5'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'macs')
    assert f['compliant'] is False


def test_analyse_ssh_macs_hmac_sha1_fails():
    """hmac-sha1 present → compliant=False."""
    config = {'macs': 'hmac-sha1,hmac-sha2-256'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'macs')
    assert f['compliant'] is False


def test_analyse_ssh_kex_clean_passes():
    """Modern KEX only → compliant=True."""
    config = {'kexalgorithms': 'curve25519-sha256,ecdh-sha2-nistp256'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'kexalgorithms')
    assert f['compliant'] is True


def test_analyse_ssh_kex_weak_fails():
    """diffie-hellman-group1-sha1 present → compliant=False."""
    config = {'kexalgorithms': 'curve25519-sha256,diffie-hellman-group1-sha1'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'kexalgorithms')
    assert f['compliant'] is False


def test_analyse_ssh_hostkeyalgorithms_dss_fails():
    """ssh-dss in hostkeyalgorithms → compliant=False."""
    config = {'hostkeyalgorithms': 'rsa-sha2-256,ssh-dss'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'hostkeyalgorithms')
    assert f['compliant'] is False


def test_analyse_ssh_crypto_absent_is_skip():
    """Crypto key absent from sshd -T → compliant=None (compiled-in default)."""
    config = {}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'ciphers')
    assert f['compliant'] is None
```

- [ ] **Step 2: Run tests to verify they pass (no new code needed)**

```bash
python3 -m pytest OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py -v --import-mode=importlib
```

Expected: 30 passed.

- [ ] **Step 3: Commit**

```bash
git add OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py
git commit -m "test(ssh): add crypto check tests"
```

---

### Task 4: `compute_risk` + output formatters (`write_json`, `write_csv`, `write_html`)

**Files:**
- Modify: `OnPrem/Linux/linux-ssh-auditor/linux_ssh_auditor.py`
- Modify: `OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_linux_ssh_auditor.py`:

```python
# ── compute_risk ───────────────────────────────────────────────────────────────

def test_compute_risk_no_findings():
    score, risk, c, h, m, l = lsa.compute_risk([])
    assert score == 0
    assert risk == 'LOW'


def test_compute_risk_critical_raises_to_critical():
    findings = [{'compliant': False, 'severity_if_wrong': 'CRITICAL'}]
    score, risk, c, h, m, l = lsa.compute_risk(findings)
    assert risk == 'CRITICAL'
    assert c == 1


def test_compute_risk_score_capped_at_10():
    findings = [{'compliant': False, 'severity_if_wrong': 'HIGH'}] * 10
    score, risk, c, h, m, l = lsa.compute_risk(findings)
    assert score == 10


def test_compute_risk_skips_none_compliant():
    findings = [{'compliant': None, 'severity_if_wrong': 'CRITICAL'}]
    score, risk, c, h, m, l = lsa.compute_risk(findings)
    assert score == 0
    assert risk == 'LOW'


def test_compute_risk_mixed_severity():
    findings = [
        {'compliant': False, 'severity_if_wrong': 'HIGH'},
        {'compliant': False, 'severity_if_wrong': 'MEDIUM'},
        {'compliant': True,  'severity_if_wrong': 'CRITICAL'},
    ]
    score, risk, c, h, m, l = lsa.compute_risk(findings)
    assert h == 1
    assert m == 1
    assert c == 0


# ── write_json ─────────────────────────────────────────────────────────────────

def test_write_json_creates_file(tmp_path):
    report = {'generated_at': '2026-01-01', 'findings': []}
    path = str(tmp_path / 'out.json')
    with patch('os.chmod'):
        lsa.write_json(report, path)
    assert os.path.exists(path)


def test_write_json_valid_json(tmp_path):
    report = {'generated_at': '2026-01-01', 'findings': []}
    path = str(tmp_path / 'out.json')
    with patch('os.chmod'):
        lsa.write_json(report, path)
    with open(path) as f:
        data = json.load(f)
    assert data['generated_at'] == '2026-01-01'


# ── write_html ─────────────────────────────────────────────────────────────────

def test_write_html_creates_file(tmp_path):
    report = {
        'generated_at': '2026-01-01', 'hostname': 'testhost',
        'findings': [],
        'summary': {
            'total_checks': 0, 'compliant': 0, 'non_compliant': 0,
            'unavailable': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'overall_risk': 'LOW', 'severity_score': 0,
        },
    }
    path = str(tmp_path / 'out.html')
    with patch('os.chmod'):
        lsa.write_html(report, path)
    assert os.path.exists(path)


def test_write_html_contains_green_gradient(tmp_path):
    report = {
        'generated_at': '2026-01-01', 'hostname': 'testhost',
        'findings': [],
        'summary': {
            'total_checks': 0, 'compliant': 0, 'non_compliant': 0,
            'unavailable': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'overall_risk': 'LOW', 'severity_score': 0,
        },
    }
    path = str(tmp_path / 'out.html')
    with patch('os.chmod'):
        lsa.write_html(report, path)
    with open(path) as f:
        content = f.read()
    assert '#28a745' in content


def test_write_html_contains_hostname(tmp_path):
    report = {
        'generated_at': '2026-01-01', 'hostname': 'my-special-host',
        'findings': [],
        'summary': {
            'total_checks': 0, 'compliant': 0, 'non_compliant': 0,
            'unavailable': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'overall_risk': 'LOW', 'severity_score': 0,
        },
    }
    path = str(tmp_path / 'out.html')
    with patch('os.chmod'):
        lsa.write_html(report, path)
    with open(path) as f:
        content = f.read()
    assert 'my-special-host' in content
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py -v --import-mode=importlib
```

Expected: FAIL — `compute_risk`, `write_json`, `write_html` not defined.

- [ ] **Step 3: Add `compute_risk` and output formatters to module**

Append to `linux_ssh_auditor.py`:

```python
# ── Scoring ───────────────────────────────────────────────────────────────────

def compute_risk(findings):
    """Compute overall risk from findings. Returns (score, risk, c, h, m, l)."""
    criticals = sum(1 for f in findings if f['compliant'] is False and f['severity_if_wrong'] == 'CRITICAL')
    highs     = sum(1 for f in findings if f['compliant'] is False and f['severity_if_wrong'] == 'HIGH')
    mediums   = sum(1 for f in findings if f['compliant'] is False and f['severity_if_wrong'] == 'MEDIUM')
    lows      = sum(1 for f in findings if f['compliant'] is False and f['severity_if_wrong'] == 'LOW')

    score = min(criticals * 8 + highs * 4 + mediums * 2 + int(lows * 0.5), 10)

    if score >= 8 or criticals > 0:
        risk = 'CRITICAL'
    elif score >= 5:
        risk = 'HIGH'
    elif score >= 2:
        risk = 'MEDIUM'
    else:
        risk = 'LOW'

    return score, risk, criticals, highs, mediums, lows


# ── Output formatters ─────────────────────────────────────────────────────────

def write_json(report, path):
    with open(path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    os.chmod(path, 0o600)
    log.info(f"JSON report: {path}")


def write_csv(findings, path):
    if not findings:
        return
    fieldnames = [
        'param', 'expected', 'actual', 'compliant', 'severity_if_wrong',
        'description', 'flag', 'remediation',
    ]
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)
    os.chmod(path, 0o600)
    log.info(f"CSV report: {path}")


def write_html(report, path):
    findings  = report['findings']
    summary   = report['summary']
    generated = report['generated_at']
    hostname  = report.get('hostname', 'unknown')

    severity_colors = {
        'CRITICAL': '#dc3545',
        'HIGH':     '#fd7e14',
        'MEDIUM':   '#ffc107',
        'LOW':      '#28a745',
    }

    def _row_color(f):
        if f['compliant'] is None:
            return '#95a5a6'
        if f['compliant']:
            return '#28a745'
        return severity_colors.get(f['severity_if_wrong'], '#fd7e14')

    rows = ''
    for f in findings:
        color = _row_color(f)
        label = 'SKIP' if f['compliant'] is None else ('PASS' if f['compliant'] else 'FAIL')
        icon  = 'ℹ️' if f['compliant'] is None else ('✅' if f['compliant'] else '❌')
        remediation = f.get('remediation') or ''
        rows += f"""
        <tr>
            <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{icon} {label}</span></td>
            <td><span style="background:{severity_colors.get(f['severity_if_wrong'], '#999')};color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:bold">{f['severity_if_wrong']}</span></td>
            <td style="font-family:monospace;font-size:0.85em">{f['param']}</td>
            <td style="font-family:monospace">{f['expected']}</td>
            <td style="font-family:monospace">{f['actual']}</td>
            <td style="font-size:0.85em">{f['description']}</td>
            <td style="font-size:0.8em;color:#28a745">{remediation}</td>
        </tr>"""

    risk_color = severity_colors.get(summary['overall_risk'], '#28a745')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Linux SSH Hardening Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f5f6fa; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #2c3e50, #28a745); color: white; padding: 30px 40px; }}
  .header h1 {{ margin: 0; font-size: 1.8em; }}
  .header p {{ margin: 5px 0 0; opacity: 0.8; }}
  .summary {{ display: flex; gap: 20px; padding: 20px 40px; flex-wrap: wrap; }}
  .card {{ background: white; border-radius: 8px; padding: 20px 30px; flex: 1; min-width: 140px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }}
  .card .num {{ font-size: 2.5em; font-weight: bold; }}
  .card .label {{ color: #666; font-size: 0.9em; margin-top: 4px; }}
  .compliant .num {{ color: #28a745; }}
  .noncompliant .num {{ color: #fd7e14; }}
  .high .num {{ color: #fd7e14; }}
  .medium .num {{ color: #ffc107; }}
  .low .num {{ color: #28a745; }}
  .total .num {{ color: #3498db; }}
  .risk-badge {{ display: inline-block; background: {risk_color}; color: white; border-radius: 6px; padding: 4px 14px; font-weight: bold; font-size: 1.1em; }}
  .table-wrap {{ padding: 0 40px 40px; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  th {{ background: #2c3e50; color: white; padding: 12px 15px; text-align: left; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }}
  td {{ padding: 10px 15px; border-bottom: 1px solid #ecf0f1; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f8f9ff; }}
  .footer {{ text-align: center; padding: 20px; color: #999; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔐 Linux SSH Hardening Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; Host: {hostname} &nbsp;|&nbsp; {summary['total_checks']} checks &nbsp;|&nbsp; Risk: <span class="risk-badge">{summary['overall_risk']}</span></p>
</div>
<div class="summary">
  <div class="card total"><div class="num">{summary['total_checks']}</div><div class="label">Total Checks</div></div>
  <div class="card compliant"><div class="num">{summary['compliant']}</div><div class="label">Compliant</div></div>
  <div class="card noncompliant"><div class="num">{summary['non_compliant']}</div><div class="label">Non-Compliant</div></div>
  <div class="card high"><div class="num">{summary['high']}</div><div class="label">HIGH Violations</div></div>
  <div class="card medium"><div class="num">{summary['medium']}</div><div class="label">MEDIUM Violations</div></div>
</div>
<div class="table-wrap">
  <table>
    <thead>
      <tr><th>Status</th><th>Severity</th><th>Parameter</th><th>Expected</th><th>Actual</th><th>Description</th><th>Remediation</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">Linux SSH Hardening Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, 'w') as f:
        f.write(html)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py -v --import-mode=importlib
```

Expected: 41 passed.

- [ ] **Step 5: Commit**

```bash
git add OnPrem/Linux/linux-ssh-auditor/linux_ssh_auditor.py \
        OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py
git commit -m "feat(ssh): add compute_risk and output formatters"
```

---

### Task 5: `run()` entry point + argparse

**Files:**
- Modify: `OnPrem/Linux/linux-ssh-auditor/linux_ssh_auditor.py`
- Modify: `OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py`

- [ ] **Step 1: Write failing tests for `run()`**

Append to `tests/test_linux_ssh_auditor.py`:

```python
# ── run() ──────────────────────────────────────────────────────────────────────

def _full_sshd_output():
    return (
        "permitrootlogin no\n"
        "permitemptypasswords no\n"
        "passwordauthentication no\n"
        "pubkeyauthentication yes\n"
        "strictmodes yes\n"
        "hostbasedauthentication no\n"
        "ignorerhosts yes\n"
        "x11forwarding no\n"
        "loglevel VERBOSE\n"
        "maxauthtries 4\n"
        "logingracetime 60\n"
        "allowagentforwarding no\n"
        "allowtcpforwarding no\n"
        "usepam yes\n"
        "clientaliveinterval 300\n"
        "clientalivecountmax 3\n"
    )


def test_run_returns_report_shape(tmp_path):
    with patch.object(lsa, 'run_command', return_value=(_full_sshd_output(), 0)):
        with patch('os.chmod'):
            report = lsa.run(output_prefix=str(tmp_path / 'ssh_report'), fmt='json')
    assert 'summary' in report
    assert 'findings' in report
    assert report['pillar'] == 'ssh'


def test_run_sshd_unavailable_scores_low(tmp_path):
    """When sshd -T fails, all checks are N/A; overall risk should be LOW."""
    with patch.object(lsa, 'run_command', return_value=('', 1)):
        with patch('os.chmod'):
            report = lsa.run(output_prefix=str(tmp_path / 'ssh_report'), fmt='json')
    assert report['summary']['overall_risk'] == 'LOW'
    assert report['summary']['non_compliant'] == 0


def test_run_findings_sorted_noncompliant_first(tmp_path):
    """Non-compliant findings appear before compliant ones."""
    with patch.object(lsa, 'run_command', return_value=(_full_sshd_output(), 0)):
        with patch('os.chmod'):
            report = lsa.run(output_prefix=str(tmp_path / 'ssh_report'), fmt='json')
    findings = report['findings']
    statuses = [f['compliant'] for f in findings]
    # All False entries must come before True entries
    seen_true = False
    for s in statuses:
        if s is True:
            seen_true = True
        if seen_true and s is False:
            pytest.fail("Non-compliant finding appeared after compliant finding")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py::test_run_returns_report_shape -v --import-mode=importlib
```

Expected: FAIL — `run` not defined.

- [ ] **Step 3: Add `run()` and `__main__` block to module**

Append to `linux_ssh_auditor.py`:

```python
# ── Main run function ─────────────────────────────────────────────────────────

def run(output_prefix='ssh_report', fmt='all'):
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = 'unknown'

    config   = get_effective_config()
    findings = analyse_ssh(config)

    # Sort: non-compliant first, then N/A (None), then compliant
    def _sort_key(f):
        if f['compliant'] is False:
            return 0
        if f['compliant'] is None:
            return 1
        return 2

    findings.sort(key=_sort_key)

    score, risk, criticals, highs, mediums, lows = compute_risk(findings)

    report = {
        'generated_at': NOW.isoformat(),
        'hostname':     hostname,
        'pillar':       'ssh',
        'risk_level':   risk,
        'summary': {
            'total_checks': len(findings),
            'compliant':     sum(1 for f in findings if f['compliant'] is True),
            'non_compliant': sum(1 for f in findings if f['compliant'] is False),
            'unavailable':   sum(1 for f in findings if f['compliant'] is None),
            'critical':      criticals,
            'high':          highs,
            'medium':        mediums,
            'low':           lows,
            'overall_risk':  risk,
            'severity_score': score,
        },
        'findings': findings,
    }

    if fmt in ('json', 'all'):
        write_json(report, f"{output_prefix}.json")
    if fmt in ('csv', 'all'):
        write_csv(findings, f"{output_prefix}.csv")
    if fmt in ('html', 'all'):
        write_html(report, f"{output_prefix}.html")
    if fmt == 'stdout':
        print(json.dumps(report, indent=2, default=str))

    s = report['summary']
    print(f"""
╔══════════════════════════════════════════════╗
║       SSH AUDITOR — SUMMARY                  ║
╠══════════════════════════════════════════════╣
║  Total checks:        {s['total_checks']:<22}║
║  Compliant:           {s['compliant']:<22}║
║  Non-compliant:       {s['non_compliant']:<22}║
║  Unavailable:         {s['unavailable']:<22}║
║  CRITICAL violations: {s['critical']:<22}║
║  HIGH violations:     {s['high']:<22}║
║  MEDIUM violations:   {s['medium']:<22}║
║  Overall risk:        {s['overall_risk']:<22}║
╚══════════════════════════════════════════════╝
""")

    return report


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Linux SSH Hardening Auditor')
    parser.add_argument('--output', '-o', default='ssh_report')
    parser.add_argument('--format', '-f', choices=['json', 'csv', 'html', 'all', 'stdout'], default='all')
    args = parser.parse_args()
    run(output_prefix=args.output, fmt=args.format)
```

- [ ] **Step 4: Run full test suite to verify all pass**

```bash
python3 -m pytest OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py -v --import-mode=importlib
```

Expected: 44 passed.

- [ ] **Step 5: Commit**

```bash
git add OnPrem/Linux/linux-ssh-auditor/linux_ssh_auditor.py \
        OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py
git commit -m "feat(ssh): add run() orchestrator and argparse entry point"
```

---

### Task 6: `audit.py` + `exec_summary.py` integration

**Files:**
- Modify: `audit.py` (lines 78–81, 111, 173–178, 282–285)
- Modify: `tools/exec_summary.py` (line 56)
- Modify: `OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py`

- [ ] **Step 1: Write failing integration tests**

Append to `tests/test_linux_ssh_auditor.py`:

```python
# ── audit.py integration ───────────────────────────────────────────────────────

def test_audit_linux_ssh_in_auditor_map():
    import importlib.util, pathlib
    spec = importlib.util.spec_from_file_location(
        'audit',
        pathlib.Path(__file__).parents[4] / 'audit.py'
    )
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    assert 'linux_ssh' in audit.AUDITOR_MAP


def test_audit_linux_ssh_in_linux_group():
    import importlib.util, pathlib
    spec = importlib.util.spec_from_file_location(
        'audit',
        pathlib.Path(__file__).parents[4] / 'audit.py'
    )
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    assert 'linux_ssh' in audit.LINUX_GROUP


def test_audit_ssh_output_prefix():
    import importlib.util, pathlib
    spec = importlib.util.spec_from_file_location(
        'audit',
        pathlib.Path(__file__).parents[4] / 'audit.py'
    )
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    assert audit.AUDITOR_MAP['linux_ssh'].output_prefix == 'ssh_report'


# ── exec_summary.py integration ───────────────────────────────────────────────

def test_exec_summary_ssh_report_in_known_patterns():
    import importlib.util, pathlib
    spec = importlib.util.spec_from_file_location(
        'exec_summary',
        pathlib.Path(__file__).parents[4] / 'tools' / 'exec_summary.py'
    )
    es = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(es)
    assert 'ssh_report.json' in es.KNOWN_PATTERNS
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py::test_audit_linux_ssh_in_auditor_map -v --import-mode=importlib
```

Expected: FAIL — `linux_ssh` not in `AUDITOR_MAP`.

- [ ] **Step 3: Update `audit.py`**

In `audit.py`, after line 81 (`"linux_patch": AuditorDef(...)`), add:

```python
    "linux_ssh":      AuditorDef(REPO_ROOT / "OnPrem/Linux/linux-ssh-auditor/linux_ssh_auditor.py",       "ssh_report",    False),
```

On line 111, change:

```python
LINUX_GROUP: List[str] = [
    "linux_user", "linux_firewall", "linux_sysctl", "linux_patch",
]
```

to:

```python
LINUX_GROUP: List[str] = [
    "linux_user", "linux_firewall", "linux_sysctl", "linux_patch", "linux_ssh",
]
```

On lines 173–178 (the `LINUX AUDITORS` help block), add after the `--linux_patch` line:

```
  --linux_ssh       SSH daemon configuration and crypto hardening
```

On lines 282–285 (the `_linux_help` dict), add after `"linux_patch"`:

```python
        "linux_ssh":      "SSH daemon configuration and crypto hardening",
```

- [ ] **Step 4: Update `tools/exec_summary.py`**

After line 56 (`"patch_report.json",`), add:

```python
    "ssh_report.json",
```

- [ ] **Step 5: Run all integration tests**

```bash
python3 -m pytest OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py -v --import-mode=importlib
```

Expected: all tests pass.

- [ ] **Step 6: Run the full repo test suite**

```bash
python3 -m pytest AWS/ OnPrem/Linux/ tests/ -v --import-mode=importlib
```

Expected: all pass, no regressions.

- [ ] **Step 7: Commit**

```bash
git add audit.py tools/exec_summary.py \
        OnPrem/Linux/linux-ssh-auditor/tests/test_linux_ssh_auditor.py
git commit -m "feat(ssh): integrate linux_ssh into audit.py and exec_summary"
```

---

### Task 7: Final smoke test + push

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite one final time**

```bash
python3 -m pytest AWS/ OnPrem/Linux/ tests/ -v --import-mode=importlib
```

Expected: all pass.

- [ ] **Step 2: Verify module runs without a live sshd**

```bash
python3 OnPrem/Linux/linux-ssh-auditor/linux_ssh_auditor.py --format stdout 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['pillar'], d['summary']['overall_risk'])"
```

Expected: `ssh LOW` (or similar — no crash).

- [ ] **Step 3: Push to GitHub**

```bash
git push origin main
```
