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


# ── SPF checks ────────────────────────────────────────────────────────────────

_SPF_LOOKUP_MECHS = re.compile(r'\b(include|a|mx|ptr|exists):', re.IGNORECASE)


def check_spf(domain: str) -> list:
    """SPF-01, SPF-02, SPF-03: existence, permissiveness, lookup count."""
    txts = query_txt(domain)

    if txts is None:
        return [_finding(
            "SPF-01", "SPF Record Exists", "WARN", "HIGH", 0,
            "DNS query failed — result may be incomplete",
            "Retry when DNS is available",
        )]

    spf_record = next((t for t in txts if t.strip().startswith('v=spf1')), None)

    if not spf_record:
        return [_finding(
            "SPF-01", "SPF Record Exists", "FAIL", "HIGH", 4,
            f"No SPF TXT record found for {domain}",
            "Add a TXT record: v=spf1 include:<your-mail-provider> -all",
        )]

    findings = [_finding(
        "SPF-01", "SPF Record Exists", "PASS", "HIGH", 0,
        f"SPF record found: {spf_record[:120]}",
        "",
    )]

    # SPF-02: permissiveness
    if '+all' in spf_record or '?all' in spf_record:
        qualifier = '+all' if '+all' in spf_record else '?all'
        findings.append(_finding(
            "SPF-02", "SPF Not Permissive", "FAIL", "CRITICAL", 8,
            f"SPF record uses '{qualifier}' — allows any server to send as {domain}",
            f"Change '{qualifier}' to '-all' (reject) or '~all' (softfail). "
            "Current setting renders SPF useless.",
        ))
    else:
        findings.append(_finding(
            "SPF-02", "SPF Not Permissive", "PASS", "CRITICAL", 0,
            "SPF record does not use permissive +all or ?all qualifier",
            "",
        ))

    # SPF-03: shallow lookup count
    count = len(_SPF_LOOKUP_MECHS.findall(spf_record))
    if count > 10:
        findings.append(_finding(
            "SPF-03", "SPF Lookup Count", "FAIL", "MEDIUM", 2,
            f"SPF record has {count} lookup mechanisms (limit is 10) — "
            "may cause legitimate email to be rejected",
            "Reduce SPF includes by consolidating mail providers or using macros.",
        ))
    else:
        findings.append(_finding(
            "SPF-03", "SPF Lookup Count", "PASS", "MEDIUM", 0,
            f"SPF record has {count} lookup mechanism(s) — within the limit of 10",
            "",
        ))

    return findings


# ── DKIM checks ───────────────────────────────────────────────────────────────

def _probe_dkim(domain: str, selector: str) -> Optional[str]:
    """Return the DKIM TXT record string for selector._domainkey.domain, or None."""
    name = f"{selector}._domainkey.{domain}"
    txts = query_txt(name)
    if not txts:
        return None
    for t in txts:
        if 'v=DKIM1' in t or 'k=rsa' in t or 'p=' in t:
            return t
    return None


def _parse_dkim_key_bits(p_value: str) -> Optional[int]:
    """
    Approximate RSA key strength from DER-encoded public key length.
    Returns an approximate bit count, or None if the key cannot be decoded.

    DER length thresholds (PKCS#1 SubjectPublicKeyInfo encoding):
      512-bit  ->  ~74-90 bytes
      1024-bit ->  ~140-162 bytes
      2048-bit ->  ~270-294 bytes

    We use length >= 140 as the 1024-bit pass threshold to avoid
    misclassifying legitimate 1024-bit keys.
    """
    try:
        der = base64.b64decode(p_value)
        # Map DER byte length to approximate bit strength
        if len(der) >= 256:
            return 2048
        elif len(der) >= 140:
            return 1024
        else:
            return 512
    except Exception:
        return None


def check_dkim(domain: str, selector: Optional[str]) -> list:
    """DKIM-01, DKIM-02: record existence and key strength."""
    # Build probe order: provided selector first, then standard list
    probes = []
    if selector:
        probes.append(selector)
    probes.extend(s for s in DKIM_SELECTORS if s != selector)

    found_record = None
    found_selector = None

    for sel in probes:
        record = _probe_dkim(domain, sel)
        if record is not None:
            found_record = record
            found_selector = sel
            break

    if found_record is None:
        return [_finding(
            "DKIM-01", "DKIM Record Exists", "FAIL", "HIGH", 4,
            f"No DKIM record found for {domain} (probed {len(probes)} selectors)",
            "Configure DKIM signing with your email provider and publish the public key "
            "as a TXT record at <selector>._domainkey." + domain,
        )]

    # Extract p= value
    p_match = re.search(r'p=([^;\s]*)', found_record)
    p_value = p_match.group(1).strip() if p_match else ''

    if not p_value:
        return [_finding(
            "DKIM-01", "DKIM Record Exists", "FAIL", "HIGH", 4,
            f"DKIM record found at {found_selector}._domainkey.{domain} but key is empty (revoked)",
            "Generate a new DKIM key pair and publish the new public key. "
            "Rotate the signing key in your mail provider settings.",
        )]

    dkim01 = _finding(
        "DKIM-01", "DKIM Record Exists", "PASS", "HIGH", 0,
        f"DKIM record found at {found_selector}._domainkey.{domain}",
        "",
    )
    dkim01["dkim_selector_used"] = found_selector

    # DKIM-02: key strength
    bits = _parse_dkim_key_bits(p_value)
    if bits is None:
        dkim02 = _finding(
            "DKIM-02", "DKIM Key Strength", "WARN", "MEDIUM", 0,
            "DKIM key format could not be decoded — key length undetectable",
            "Verify your DKIM key is at least 1024 bits (2048 recommended) with your mail provider.",
        )
    elif bits < 1024:
        dkim02 = _finding(
            "DKIM-02", "DKIM Key Strength", "FAIL", "MEDIUM", 2,
            f"DKIM key appears to be approximately {bits} bits — below the 1024-bit minimum",
            "Generate a new 2048-bit DKIM key pair and update your DNS record.",
        )
    else:
        dkim02 = _finding(
            "DKIM-02", "DKIM Key Strength", "PASS", "MEDIUM", 0,
            f"DKIM key length appears adequate (≥1024 bits)",
            "",
        )

    return [dkim01, dkim02]


# ── DMARC checks ──────────────────────────────────────────────────────────────

def check_dmarc(domain: str) -> list:
    """DMARC-01, DMARC-02, DMARC-03: existence, policy enforcement, reporting."""
    dmarc_name = f"_dmarc.{domain}"
    txts = query_txt(dmarc_name)

    if txts is None:
        return [_finding(
            "DMARC-01", "DMARC Record Exists", "WARN", "HIGH", 0,
            "DNS query failed — result may be incomplete",
            "Retry when DNS is available",
        )]

    record = next((t for t in txts if 'v=DMARC1' in t), None)

    if not record:
        return [_finding(
            "DMARC-01", "DMARC Record Exists", "FAIL", "HIGH", 4,
            f"No DMARC record found at {dmarc_name}",
            f"Add a TXT record at _dmarc.{domain}: "
            "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
        )]

    findings = [_finding(
        "DMARC-01", "DMARC Record Exists", "PASS", "HIGH", 0,
        f"DMARC record found: {record[:120]}",
        "",
    )]

    # DMARC-02: policy
    policy_match = re.search(r'\bp=(\w+)', record)
    policy = policy_match.group(1).lower() if policy_match else 'none'

    if policy in ('quarantine', 'reject'):
        findings.append(_finding(
            "DMARC-02", "DMARC Policy Enforced", "PASS", "HIGH", 0,
            f"DMARC policy is '{policy}' — spoofed emails will be {policy}d",
            "",
        ))
    else:
        findings.append(_finding(
            "DMARC-02", "DMARC Policy Enforced", "FAIL", "HIGH", 4,
            f"DMARC policy is 'p={policy}' — no enforcement, spoofed emails are delivered",
            "Change p=none to p=quarantine (sends to spam) or p=reject (blocks delivery). "
            "Start with p=quarantine, monitor rua reports, then move to p=reject.",
        ))

    # DMARC-03: reporting
    if 'rua=' in record:
        findings.append(_finding(
            "DMARC-03", "DMARC Reporting Configured", "PASS", "MEDIUM", 0,
            "DMARC aggregate reporting (rua=) is configured",
            "",
        ))
    else:
        findings.append(_finding(
            "DMARC-03", "DMARC Reporting Configured", "FAIL", "MEDIUM", 2,
            "DMARC record has no aggregate reporting address (rua= missing) — "
            "you will not receive reports of spoofing attempts",
            "Add rua=mailto:dmarc@yourdomain.com to your DMARC record. "
            "Consider a free DMARC reporting service (e.g. postmaster.google.com).",
        ))

    return findings
