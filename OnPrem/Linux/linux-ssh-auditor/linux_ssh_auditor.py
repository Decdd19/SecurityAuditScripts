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
    """Call sshd -T and parse output into a lowercase key->value dict.

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
        return ok, f"<={threshold}"
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

    ("passwordauthentication", _eq("no"),      "HIGH",
     "Key-based authentication enforced (passwords disabled)",
     "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("pubkeyauthentication",  _eq("yes"),      "HIGH",
     "Public key authentication enabled",
     "Set 'PubkeyAuthentication yes' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    # ── Session hardening ─────────────────────────────────────────────────────
    ("strictmodes",           _eq("yes"),      "HIGH",
     "Enforce strict .ssh directory permission checks",
     "Set 'StrictModes yes' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("hostbasedauthentication", _eq("no"),     "MEDIUM",
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
     "Unauthenticated connection timeout <=60 seconds",
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
     "Idle session keepalive interval <=300 seconds",
     "Set 'ClientAliveInterval 300' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("clientalivecountmax",   _lte(3),         "LOW",
     "Max missed keepalives before disconnect <=3",
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
                'flag':              f'INFO {key}: not present in sshd -T output',
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
                    'flag':              f'PASS {key} = {val}',
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
                    'flag':              f'FAIL {key} = {val} (expected {expected_str}): {description}',
                    'remediation':       remediation,
                    'risk_level':        severity,
                }
        findings.append(finding)
    return findings
