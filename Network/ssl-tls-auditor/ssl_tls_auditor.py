#!/usr/bin/env python3
"""
SSL/TLS Auditor
===============
Audits a domain's SSL/TLS certificate and TLS configuration:
- TLS-00: Connectivity (can we connect at all?)
- TLS-01: Certificate expiry (expired / <14d critical / <30d warning)
- TLS-02: Hostname match (domain in SAN or CN)
- TLS-03: Self-signed certificate (issuer == subject)
- TLS-04: Key algorithm (DSA = FAIL; RSA/EC = PASS)
- TLS-05: TLS version (must be 1.2 or 1.3)
- TLS-06: Weak cipher suite (RC4/DES/3DES/NULL/EXPORT/ANON = FAIL)
- TLS-07: HSTS header (absent = FAIL, max-age < 1 year = WARN)

Usage:
    python3 ssl_tls_auditor.py --domain acme.ie
    python3 ssl_tls_auditor.py --domain acme.ie --port 8443
    python3 ssl_tls_auditor.py --domain acme.ie --format all --output ssl_report
"""

import argparse
import csv
import json
import logging
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

NOW = datetime.now(timezone.utc)

# Key algorithm OID byte sequences present in DER SubjectPublicKeyInfo
_RSA_OID = bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])  # 1.2.840.113549.1.1.1
_EC_OID  = bytes([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])               # 1.2.840.10045.2.1
_DSA_OID = bytes([0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01])               # 1.2.840.10040.4.1

WEAK_CIPHER_KEYWORDS = frozenset({"RC4", "DES", "3DES", "NULL", "EXPORT", "ANON"})


# ── SSL/TLS wrapper (thin — mock this in tests) ───────────────────────────────

def _decode_cert(der: bytes) -> dict:
    """
    Decode DER cert bytes to ssl.getpeercert()-compatible dict using stdlib only.

    Loads the cert as a temporary trusted CA to obtain the decoded dict.
    Returns {} on any error (e.g. empty DER, malformed cert).
    """
    if not der:
        return {}
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        tmp = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tmp.load_verify_locations(cadata=pem)
        certs = tmp.get_ca_certs()
        return certs[0] if certs else {}
    except Exception:
        return {}


def ssl_connect(host: str, port: int = 443, timeout: int = 10) -> Optional[dict]:
    """
    Open TLS connection to host:port, send HTTP/1.0 GET, return data dict.

    Uses CERT_NONE so the connection succeeds even for self-signed/expired certs.
    The individual check functions implement their own validation logic.

    Returns None on ConnectionRefusedError, socket.timeout, socket.gaierror,
    ssl.SSLError, or OSError.

    Returns dict with keys:
        peercert     - decoded cert dict (ssl.getpeercert()-compatible); {} if decode fails
        peercert_der - raw DER bytes from server
        version      - negotiated TLS version string, e.g. "TLSv1.3"
        cipher       - tuple (name, protocol, bits)
        headers      - HTTP response headers, keys lowercased
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True) or b""
                peercert = _decode_cert(der)
                version = ssock.version() or ""
                cipher = ssock.cipher() or ("", "", 0)

                # Send HTTP/1.0 GET to retrieve response headers (needed for HSTS check)
                headers: dict = {}
                try:
                    req = (
                        f"GET / HTTP/1.0\r\n"
                        f"Host: {host}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    ssock.sendall(req.encode())
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                    hdr_block = buf.split(b"\r\n\r\n")[0].decode("utf-8", errors="replace")
                    for line in hdr_block.split("\r\n")[1:]:  # skip status line
                        if ":" in line:
                            k, _, v = line.partition(":")
                            headers[k.strip().lower()] = v.strip()
                except (ssl.SSLError, OSError):
                    pass  # headers may be partial; that's fine

                return {
                    "peercert": peercert,
                    "peercert_der": der,
                    "version": version,
                    "cipher": cipher,
                    "headers": headers,
                }
    except (ConnectionRefusedError, socket.timeout, socket.gaierror, ssl.SSLError, OSError):
        return None


# ── Finding helper ────────────────────────────────────────────────────────────

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
        "pillar": "tls",
    }


# ── Cert parsing helpers ──────────────────────────────────────────────────────

def _parse_cert_time(s: str) -> Optional[datetime]:
    """
    Parse ssl.getpeercert() notAfter string to datetime (UTC).
    Handles both zero-padded and space-padded day formats.
    """
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(s.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _domain_matches_san(domain: str, san: str) -> bool:
    """
    Return True if domain matches san (case-insensitive), including wildcard SANs.
    Wildcard *.example.com matches foo.example.com but NOT bar.foo.example.com.
    """
    domain = domain.lower()
    san = san.lower()
    if san.startswith("*."):
        suffix = san[2:]
        parts_d = domain.split(".")
        parts_s = suffix.split(".")
        if len(parts_d) == len(parts_s) + 1:
            return parts_d[1:] == parts_s
        return False
    return domain == san


def _key_algorithm(der: bytes) -> str:
    """
    Identify key algorithm from DER SubjectPublicKeyInfo OID bytes.
    Returns "RSA", "EC", "DSA", or "UNKNOWN".
    """
    if _RSA_OID in der:
        return "RSA"
    if _EC_OID in der:
        return "EC"
    if _DSA_OID in der:
        return "DSA"
    return "UNKNOWN"
