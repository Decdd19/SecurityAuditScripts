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


# ── TLS-00: Connectivity ──────────────────────────────────────────────────────

def check_connectivity(conn: Optional[dict], domain: str, port: int) -> dict:
    """TLS-00: Verify we can establish a TLS connection to domain:port."""
    if conn is None:
        return _finding(
            "TLS-00", "TLS Connectivity", "FAIL", "CRITICAL", 10,
            f"Could not establish TLS connection to {domain}:{port}. "
            "Host may be unreachable, port closed, or TLS not enabled.",
            "Verify the server is running, port is open (check firewall rules), "
            "and TLS/SSL is enabled in your web server configuration.",
        )
    return _finding(
        "TLS-00", "TLS Connectivity", "PASS", "CRITICAL", 0,
        f"TLS connection established to {domain}:{port}", "",
    )


# ── TLS-01: Certificate expiry ────────────────────────────────────────────────

def check_cert_expiry(conn: dict) -> dict:
    """TLS-01: Check certificate expiry. FAIL if expired or <14d; WARN if <30d."""
    pc = conn.get("peercert", {})
    not_after_str = pc.get("notAfter", "")

    if not pc or not not_after_str:
        return _finding(
            "TLS-01", "Certificate Expiry", "FAIL", "CRITICAL", 8,
            "Certificate could not be decoded — expiry date unavailable.",
            "Ensure the server presents a valid, CA-signed certificate.",
        )

    not_after = _parse_cert_time(not_after_str)
    if not_after is None:
        return _finding(
            "TLS-01", "Certificate Expiry", "FAIL", "CRITICAL", 8,
            f"Could not parse certificate notAfter date: {not_after_str!r}",
            "Verify your certificate is correctly formatted.",
        )

    days_left = (not_after - NOW).days

    if days_left < 0:
        return _finding(
            "TLS-01", "Certificate Expiry", "FAIL", "CRITICAL", 8,
            f"Certificate expired {abs(days_left)} day(s) ago ({not_after_str}). "
            "All browsers will reject this connection with a security error.",
            "Renew the certificate immediately. Let's Encrypt certificates "
            "can be renewed for free at letsencrypt.org.",
        )
    if days_left < 14:
        return _finding(
            "TLS-01", "Certificate Expiry", "FAIL", "CRITICAL", 6,
            f"Certificate expires in {days_left} day(s) ({not_after_str}). "
            "Imminent expiry — browsers will soon reject this connection.",
            "Renew the certificate today. Contact your certificate provider "
            "or use Let's Encrypt for automated renewal.",
        )
    if days_left < 30:
        return _finding(
            "TLS-01", "Certificate Expiry", "WARN", "HIGH", 0,
            f"Certificate expires in {days_left} day(s) ({not_after_str}). "
            "Schedule renewal before it expires.",
            "Renew the certificate within the next week to avoid downtime. "
            "Consider enabling automated renewal (Let's Encrypt + certbot).",
        )
    return _finding(
        "TLS-01", "Certificate Expiry", "PASS", "HIGH", 0,
        f"Certificate valid for {days_left} more day(s) (expires {not_after_str})", "",
    )


# ── TLS-02: Hostname match ────────────────────────────────────────────────────

def check_hostname_match(conn: dict, domain: str) -> dict:
    """TLS-02: Verify certificate SANs (or CN fallback) cover the target domain."""
    pc = conn.get("peercert", {})

    if not pc:
        return _finding(
            "TLS-02", "Hostname Match", "FAIL", "CRITICAL", 8,
            "Certificate could not be decoded — hostname validation skipped.",
            "Ensure the server presents a valid certificate.",
        )

    # Prefer SANs; fall back to CN only if no SANs present
    sans = [v for t, v in pc.get("subjectAltName", ()) if t == "DNS"]
    if sans:
        if any(_domain_matches_san(domain, san) for san in sans):
            return _finding(
                "TLS-02", "Hostname Match", "PASS", "CRITICAL", 0,
                f"Domain {domain!r} found in certificate subjectAltName", "",
            )
        return _finding(
            "TLS-02", "Hostname Match", "FAIL", "CRITICAL", 8,
            f"Domain {domain!r} not in certificate SANs: {', '.join(sans[:5])}. "
            "Browsers will show a security warning for this hostname.",
            "Obtain a certificate that includes your domain in the subjectAltName. "
            "Add www and apex variants.",
        )

    # CN fallback (deprecated but still in use)
    cn = next(
        (v for rdn in pc.get("subject", ()) for k, v in rdn if k == "commonName"),
        None,
    )
    if cn and _domain_matches_san(domain, cn):
        return _finding(
            "TLS-02", "Hostname Match", "PASS", "CRITICAL", 0,
            f"Domain {domain!r} matches certificate CN (no SAN present — consider adding SAN)", "",
        )
    return _finding(
        "TLS-02", "Hostname Match", "FAIL", "CRITICAL", 8,
        f"Domain {domain!r} does not match certificate CN {cn!r} and no SANs present.",
        "Obtain a certificate that includes your domain in the subjectAltName.",
    )


# ── TLS-03: Self-signed certificate ──────────────────────────────────────────

def check_self_signed(conn: dict) -> dict:
    """TLS-03: Detect self-signed certificate by comparing issuer to subject."""
    pc = conn.get("peercert", {})

    if not pc:
        return _finding(
            "TLS-03", "No Self-Signed Certificate", "WARN", "HIGH", 0,
            "Certificate could not be decoded — self-signed detection skipped.",
            "Verify the certificate chain manually with: "
            "openssl s_client -connect domain:443 -showcerts",
        )

    issuer = pc.get("issuer", ())
    subject = pc.get("subject", ())

    if issuer and subject and issuer == subject:
        return _finding(
            "TLS-03", "No Self-Signed Certificate", "FAIL", "HIGH", 5,
            "Certificate is self-signed (issuer equals subject). "
            "All browsers display a security warning for self-signed certificates.",
            "Replace with a certificate from a trusted CA. "
            "Let's Encrypt provides free, trusted certificates (letsencrypt.org).",
        )
    return _finding(
        "TLS-03", "No Self-Signed Certificate", "PASS", "HIGH", 0,
        "Certificate is signed by a CA (issuer differs from subject)", "",
    )

# ── TLS-04: Key algorithm ─────────────────────────────────────────────────────

def check_key_algorithm(conn: dict) -> dict:
    """
    TLS-04: Check certificate public key algorithm.
    FAIL if DSA (deprecated) or unknown. PASS for RSA or EC.
    Note: key size in bits is not checked (Python stdlib limitation).
    """
    der = conn.get("peercert_der", b"")
    alg = _key_algorithm(der) if der else "UNKNOWN"

    if alg in ("RSA", "EC"):
        return _finding(
            "TLS-04", "Key Algorithm", "PASS", "HIGH", 0,
            f"Certificate uses {alg} public key algorithm (acceptable)", "",
        )
    return _finding(
        "TLS-04", "Key Algorithm", "FAIL", "HIGH", 4,
        f"Certificate uses {alg} key algorithm — not recommended for new deployments. "
        "DSA is deprecated; unknown algorithms may indicate a misconfigured server.",
        "Replace with a certificate using RSA (2048-bit minimum) or EC (P-256 or P-384). "
        "Most modern CAs issue RSA or EC certificates by default.",
    )

# ── TLS-05: TLS version ───────────────────────────────────────────────────────

def check_tls_version(conn: dict) -> dict:
    """
    TLS-05: Verify the negotiated TLS version is 1.2 or higher.
    Note: this checks the negotiated version, not whether the server
    supports older versions. Use dedicated tools (testssl.sh) for full
    protocol range enumeration.
    """
    version = conn.get("version", "")
    if version in ("TLSv1.2", "TLSv1.3"):
        return _finding(
            "TLS-05", "TLS Version", "PASS", "HIGH", 0,
            f"Negotiated TLS version: {version}", "",
        )
    return _finding(
        "TLS-05", "TLS Version", "FAIL", "HIGH", 5,
        f"Weak TLS version negotiated: {version or 'unknown'} — below TLS 1.2 minimum. "
        "TLS 1.0 and 1.1 have known vulnerabilities (BEAST, POODLE).",
        "Configure your web server to support TLS 1.2 and TLS 1.3 only. "
        "Disable TLS 1.0 and TLS 1.1 in server configuration (nginx: ssl_protocols TLSv1.2 TLSv1.3).",
    )

# ── TLS-06: Weak cipher suite ─────────────────────────────────────────────────

def check_weak_cipher(conn: dict) -> dict:
    """TLS-06: Check the negotiated cipher suite for known weak patterns."""
    cipher_tuple = conn.get("cipher", ("", "", 0))
    cipher_name = cipher_tuple[0] if cipher_tuple else ""
    upper = cipher_name.upper()
    found = sorted(kw for kw in WEAK_CIPHER_KEYWORDS if kw in upper)
    # DES-CBC3 variants are 3DES — label explicitly
    if "CBC3" in upper and "3DES" not in found:
        found = sorted(found + ["3DES"])

    if found:
        return _finding(
            "TLS-06", "Cipher Suite Strength", "FAIL", "HIGH", 5,
            f"Weak cipher negotiated: {cipher_name!r} "
            f"(matched weak keyword(s): {', '.join(found)}). "
            "Weak ciphers can be exploited to decrypt traffic.",
            "Configure your server to use only strong ciphers: AES-GCM and CHACHA20-POLY1305. "
            "Example nginx config: ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'",
        )
    return _finding(
        "TLS-06", "Cipher Suite Strength", "PASS", "HIGH", 0,
        f"Negotiated cipher suite {cipher_name!r} contains no known weak patterns", "",
    )

# ── TLS-07: HSTS header ───────────────────────────────────────────────────────

def check_hsts(conn: dict) -> dict:
    """TLS-07: Check for Strict-Transport-Security header with adequate max-age."""
    headers = conn.get("headers", {})
    hsts = headers.get("strict-transport-security", "")

    if not hsts:
        return _finding(
            "TLS-07", "HSTS Header", "FAIL", "MEDIUM", 3,
            "Strict-Transport-Security header is absent. "
            "Browsers may allow HTTP downgrade attacks (SSL stripping).",
            "Add the header to your web server: "
            "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
        )

    # Parse max-age value
    max_age = 0
    for part in hsts.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1].strip())
            except ValueError:
                pass

    if max_age >= 31536000:  # 1 year in seconds
        return _finding(
            "TLS-07", "HSTS Header", "PASS", "MEDIUM", 0,
            f"HSTS header present with max-age={max_age}s (>= 1 year). "
            f"Full value: {hsts}", "",
        )
    return _finding(
        "TLS-07", "HSTS Header", "WARN", "LOW", 0,
        f"HSTS header present but max-age={max_age}s is below the recommended 1 year (31536000s). "
        f"Full value: {hsts}",
        "Increase max-age to at least 31536000 (1 year). "
        "Consider adding includeSubDomains and preload directives.",
    )
