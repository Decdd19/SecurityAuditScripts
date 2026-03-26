#!/usr/bin/env python3
"""
HTTP Security Headers Auditor
==============================
Audits a domain's HTTP security response headers over HTTPS:
- HDR-00: Connectivity (can we connect at all?)
- HDR-01: X-Frame-Options (absent = FAIL; ALLOWFROM = WARN)
- HDR-02: X-Content-Type-Options (nosniff required)
- HDR-03: Content-Security-Policy (absent = FAIL; unsafe-inline/eval = WARN)
- HDR-04: Referrer-Policy (unsafe-url/origin = FAIL; absent = FAIL)
- HDR-05: Permissions-Policy (absent = WARN)

Usage:
    python3 http_headers_auditor.py --domain acme.ie
    python3 http_headers_auditor.py --domain acme.ie --port 8443
    python3 http_headers_auditor.py --domain acme.ie --format all --output http_headers_report
"""

import argparse
import csv
import html as html_lib
import http.client
import json
import logging
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

NOW = datetime.now(timezone.utc)


# ── HTTPS wrapper (thin — mock this in tests) ─────────────────────────────────

def get_http_headers(host: str, port: int = 443, timeout: int = 10) -> Optional[dict]:
    """
    Open HTTPS connection to host:port, send GET /, return response headers.

    Returns dict with key:
        headers  - response headers with names lowercased

    Returns None on ConnectionRefusedError, socket.timeout, socket.gaierror,
    http.client.HTTPException, or OSError.
    """
    try:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        conn.request("GET", "/", headers={"Host": host, "Connection": "close"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return {"headers": headers}
    except (ConnectionRefusedError, socket.timeout, socket.gaierror,
            http.client.HTTPException, OSError):
        return None


# ── Finding helper ─────────────────────────────────────────────────────────────

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
        "pillar": "headers",
    }


# ── HDR-00: Connectivity ───────────────────────────────────────────────────────

def check_connectivity(conn: Optional[dict], domain: str, port: int) -> dict:
    """HDR-00: Verify we can establish an HTTPS connection to domain:port."""
    if conn is None:
        return _finding(
            "HDR-00", "HTTP Headers Connectivity", "FAIL", "CRITICAL", 10,
            f"Could not establish HTTPS connection to {domain}:{port}. "
            "Host may be unreachable, port closed, or TLS not enabled.",
            "Verify the server is running and accessible on port 443. "
            "Check firewall rules and that TLS is configured.",
        )
    return _finding(
        "HDR-00", "HTTP Headers Connectivity", "PASS", "CRITICAL", 0,
        f"HTTPS connection established to {domain}:{port}", "",
    )
