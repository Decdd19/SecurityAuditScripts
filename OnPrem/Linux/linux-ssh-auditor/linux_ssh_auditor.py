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
