#!/usr/bin/env python3
"""
Email Security Auditor
=======================
Audits a domain's email security DNS configuration:
- MX record presence
- SPF: existence, permissiveness, lookup count (shallow)
- DKIM: record presence, key length
- DMARC: existence, policy enforcement, reporting configuration

Usage:
    python3 email_security_auditor.py --domain acme.ie
    python3 email_security_auditor.py --domain acme.ie --selector google
    python3 email_security_auditor.py --domain acme.ie --format all --output email_report
"""

import argparse
import base64
import csv
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import dns.resolver
import dns.exception

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

NOW = datetime.now(timezone.utc)

# DKIM selectors to probe in order (M365-first for Irish SMB market)
DKIM_SELECTORS = [
    "selector1", "selector2", "google", "default", "mail", "k1",
    "dkim", "mailjet", "sendgrid", "amazonses", "mandrill", "smtp",
    "email", "zoho", "protonmail",
]


# ── DNS wrappers (thin — mock these in tests) ─────────────────────────────────

def query_txt(name: str) -> Optional[list]:
    """
    Query TXT records for name.
    Returns list of strings on success, [] on NXDOMAIN/NoAnswer, None on transient error.
    """
    try:
        answer = dns.resolver.resolve(name, 'TXT')
        result = []
        for rdata in answer:
            for s in rdata.strings:
                result.append(s.decode('utf-8', errors='replace') if isinstance(s, bytes) else s)
        return result
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException):
        return None


def query_mx(domain: str) -> Optional[list]:
    """
    Query MX records for domain.
    Returns list of exchange hostname strings, [] on NXDOMAIN/NoAnswer, None on transient error.
    """
    try:
        answer = dns.resolver.resolve(domain, 'MX')
        return [str(rdata.exchange) for rdata in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException):
        return None


# ── Finding helpers ───────────────────────────────────────────────────────────

def _finding(check_id: str, name: str, status: str, risk_level: str,
             severity_score: int, detail: str, remediation: str) -> dict:
    return {
        "check_id": check_id,
        "name": name,
        "status": status,
        "risk_level": risk_level,
        "severity_score": severity_score if status == "FAIL" else 0,
        "detail": detail,
        "remediation": remediation,
        "pillar": "email",
    }


# ── MX check ──────────────────────────────────────────────────────────────────

def check_mx(domain: str) -> dict:
    """MX-01: Verify at least one MX record exists."""
    records = query_mx(domain)
    if records is None:
        return _finding(
            "MX-01", "MX Record Exists", "WARN", "LOW", 0,
            "DNS query failed — result may be incomplete",
            "Retry when DNS is available",
        )
    if not records:
        return _finding(
            "MX-01", "MX Record Exists", "FAIL", "LOW", 1,
            f"No MX records found for {domain}. Domain appears to have no active mail exchange. "
            "Note: DMARC enforcement is still recommended to prevent spoofing of parked domains.",
            "If this domain sends email, add MX records pointing to your mail provider. "
            "Regardless, configure DMARC to prevent domain spoofing.",
        )
    return _finding(
        "MX-01", "MX Record Exists", "PASS", "LOW", 0,
        f"MX records found: {', '.join(records[:3])}",
        "",
    )
