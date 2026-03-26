"""Tests for ssl_tls_auditor.py"""
import sys
import os
import socket
import ssl
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import ssl_tls_auditor as sta

# ── Fixture helpers ───────────────────────────────────────────────────────────

# Fake DER bytes containing each key OID (for key algorithm tests)
_RSA_DER = bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]) + b'\x00' * 64
_DSA_DER = bytes([0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01]) + b'\x00' * 64
_EC_DER  = bytes([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]) + b'\x00' * 64
_UNK_DER = b'\x00' * 64


def _future(days: int) -> str:
    """Return a notAfter string N days from now in ssl.getpeercert() format."""
    dt = datetime.now(timezone.utc) + timedelta(days=days)
    return dt.strftime("%b %d %H:%M:%S %Y") + " GMT"


def make_conn(**overrides) -> dict:
    """Return a realistic ssl_connect() result dict with overridable fields."""
    base = {
        "peercert": {
            "subject": ((("commonName", "acme.ie"),),),
            "issuer":  ((("commonName", "Let's Encrypt Authority X3"),),),
            "subjectAltName": (("DNS", "acme.ie"), ("DNS", "www.acme.ie")),
            "notAfter": _future(60),
        },
        "peercert_der": _RSA_DER,
        "version": "TLSv1.3",
        "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        "headers": {"strict-transport-security": "max-age=63072000; includeSubDomains"},
    }
    base.update(overrides)
    return base


# ── ssl_connect() wrapper tests ───────────────────────────────────────────────

def test_ssl_connect_returns_none_on_connection_refused():
    """ssl_connect returns None when connection is refused."""
    with patch('socket.create_connection', side_effect=ConnectionRefusedError):
        result = sta.ssl_connect('refused.example.com', 443)
    assert result is None


def test_ssl_connect_returns_none_on_timeout():
    """ssl_connect returns None on socket timeout."""
    with patch('socket.create_connection', side_effect=socket.timeout):
        result = sta.ssl_connect('timeout.example.com', 443)
    assert result is None


def test_ssl_connect_returns_none_on_hostname_resolution_failure():
    """ssl_connect returns None when hostname cannot be resolved."""
    with patch('socket.create_connection', side_effect=socket.gaierror):
        result = sta.ssl_connect('notexist.example.com', 443)
    assert result is None


def test_ssl_connect_returns_none_on_ssl_error():
    """ssl_connect returns None on SSLError (e.g. handshake failure)."""
    with patch('socket.create_connection', side_effect=ssl.SSLError):
        result = sta.ssl_connect('sslbad.example.com', 443)
    assert result is None


def test_ssl_connect_returns_dict_on_success():
    """ssl_connect returns dict with required keys on successful connection."""
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.side_effect = lambda binary_form=False: (
        b'\x00' * 10 if binary_form else {}
    )
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssock.recv.return_value = b"HTTP/1.0 200 OK\r\n\r\n"
    mock_ssock.__enter__ = lambda s: s
    mock_ssock.__exit__ = MagicMock(return_value=False)

    mock_raw = MagicMock()
    mock_raw.__enter__ = lambda s: s
    mock_raw.__exit__ = MagicMock(return_value=False)

    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value = mock_ssock

    with patch('socket.create_connection', return_value=mock_raw), \
         patch('ssl.SSLContext', return_value=mock_ctx):
        result = sta.ssl_connect('example.com', 443)

    assert result is not None
    assert "peercert" in result
    assert "peercert_der" in result
    assert "version" in result
    assert "cipher" in result
    assert "headers" in result


# ── TLS-00: Connectivity ──────────────────────────────────────────────────────

def test_check_connectivity_none_returns_fail():
    """ssl_connect returned None → TLS-00 FAIL CRITICAL."""
    finding = sta.check_connectivity(None, "acme.ie", 443)
    assert finding["check_id"] == "TLS-00"
    assert finding["status"] == "FAIL"
    assert finding["risk_level"] == "CRITICAL"
    assert finding["severity_score"] > 0
    assert "acme.ie" in finding["detail"]


def test_check_connectivity_success_returns_pass():
    """Successful connection dict → TLS-00 PASS."""
    finding = sta.check_connectivity(make_conn(), "acme.ie", 443)
    assert finding["check_id"] == "TLS-00"
    assert finding["status"] == "PASS"
    assert finding["severity_score"] == 0


# ── TLS-01: Certificate expiry ────────────────────────────────────────────────

def test_check_cert_expiry_expired_returns_fail_critical():
    """Expired cert (notAfter in past) → TLS-01 FAIL CRITICAL."""
    conn = make_conn(peercert={
        **make_conn()["peercert"],
        "notAfter": _future(-1),
    })
    finding = sta.check_cert_expiry(conn)
    assert finding["check_id"] == "TLS-01"
    assert finding["status"] == "FAIL"
    assert finding["risk_level"] == "CRITICAL"
    assert finding["severity_score"] > 0


def test_check_cert_expiry_7_days_returns_fail_critical():
    """7 days remaining → TLS-01 FAIL CRITICAL (< 14-day threshold)."""
    conn = make_conn(peercert={**make_conn()["peercert"], "notAfter": _future(7)})
    finding = sta.check_cert_expiry(conn)
    assert finding["status"] == "FAIL"
    assert finding["risk_level"] == "CRITICAL"


def test_check_cert_expiry_15_days_returns_warn_high():
    """15 days remaining → TLS-01 WARN HIGH (14–30 day threshold)."""
    conn = make_conn(peercert={**make_conn()["peercert"], "notAfter": _future(15)})
    finding = sta.check_cert_expiry(conn)
    assert finding["status"] == "WARN"
    assert finding["risk_level"] == "HIGH"


def test_check_cert_expiry_60_days_returns_pass():
    """60 days remaining → TLS-01 PASS."""
    conn = make_conn(peercert={**make_conn()["peercert"], "notAfter": _future(60)})
    finding = sta.check_cert_expiry(conn)
    assert finding["status"] == "PASS"
    assert finding["severity_score"] == 0


def test_check_cert_expiry_empty_peercert_returns_fail():
    """Empty peercert dict (cert decode failed) → TLS-01 FAIL CRITICAL."""
    conn = make_conn(peercert={})
    finding = sta.check_cert_expiry(conn)
    assert finding["status"] == "FAIL"
    assert finding["risk_level"] == "CRITICAL"


# ── TLS-02: Hostname match ────────────────────────────────────────────────────

def test_check_hostname_match_san_match_passes():
    """Domain in subjectAltName (DNS) → TLS-02 PASS."""
    finding = sta.check_hostname_match(make_conn(), "acme.ie")
    assert finding["check_id"] == "TLS-02"
    assert finding["status"] == "PASS"


def test_check_hostname_match_san_mismatch_fails():
    """Domain not in SANs → TLS-02 FAIL CRITICAL."""
    conn = make_conn(peercert={
        **make_conn()["peercert"],
        "subjectAltName": (("DNS", "other.ie"),),
    })
    finding = sta.check_hostname_match(conn, "acme.ie")
    assert finding["status"] == "FAIL"
    assert finding["risk_level"] == "CRITICAL"


def test_check_hostname_match_cn_fallback_passes():
    """No SANs, domain matches CN → TLS-02 PASS."""
    conn = make_conn(peercert={
        **make_conn()["peercert"],
        "subjectAltName": (),
        "subject": ((("commonName", "acme.ie"),),),
    })
    finding = sta.check_hostname_match(conn, "acme.ie")
    assert finding["status"] == "PASS"


def test_check_hostname_match_wildcard_san_passes():
    """Domain matches wildcard SAN *.acme.ie → TLS-02 PASS."""
    conn = make_conn(peercert={
        **make_conn()["peercert"],
        "subjectAltName": (("DNS", "*.acme.ie"),),
    })
    finding = sta.check_hostname_match(conn, "www.acme.ie")
    assert finding["status"] == "PASS"


def test_check_hostname_match_wildcard_does_not_match_subdomain():
    """Wildcard *.acme.ie does NOT match foo.bar.acme.ie → TLS-02 FAIL."""
    conn = make_conn(peercert={
        **make_conn()["peercert"],
        "subjectAltName": (("DNS", "*.acme.ie"),),
    })
    finding = sta.check_hostname_match(conn, "foo.bar.acme.ie")
    assert finding["status"] == "FAIL"


def test_check_hostname_match_empty_peercert_fails():
    """Empty peercert → TLS-02 FAIL CRITICAL."""
    conn = make_conn(peercert={})
    finding = sta.check_hostname_match(conn, "acme.ie")
    assert finding["status"] == "FAIL"
    assert finding["risk_level"] == "CRITICAL"


# ── TLS-03: Self-signed certificate ──────────────────────────────────────────

def test_check_self_signed_ca_signed_passes():
    """Issuer differs from subject → TLS-03 PASS (CA-signed)."""
    finding = sta.check_self_signed(make_conn())  # default has different issuer/subject
    assert finding["check_id"] == "TLS-03"
    assert finding["status"] == "PASS"


def test_check_self_signed_self_signed_fails():
    """Issuer == subject → TLS-03 FAIL HIGH."""
    self_signed_pc = {
        **make_conn()["peercert"],
        "issuer":  ((("commonName", "acme.ie"),),),
        "subject": ((("commonName", "acme.ie"),),),
    }
    conn = make_conn(peercert=self_signed_pc)
    finding = sta.check_self_signed(conn)
    assert finding["status"] == "FAIL"
    assert finding["risk_level"] == "HIGH"
    assert finding["severity_score"] > 0


def test_check_self_signed_empty_peercert_warns():
    """Empty peercert → TLS-03 WARN (cannot determine)."""
    conn = make_conn(peercert={})
    finding = sta.check_self_signed(conn)
    assert finding["check_id"] == "TLS-03"
    assert finding["status"] == "WARN"

# ── TLS-04: Key algorithm ─────────────────────────────────────────────────────

def test_check_key_algorithm_rsa_passes():
    """RSA OID in DER → TLS-04 PASS."""
    conn = make_conn(peercert_der=_RSA_DER)
    finding = sta.check_key_algorithm(conn)
    assert finding["check_id"] == "TLS-04"
    assert finding["status"] == "PASS"


def test_check_key_algorithm_ec_passes():
    """EC OID in DER → TLS-04 PASS."""
    conn = make_conn(peercert_der=_EC_DER)
    finding = sta.check_key_algorithm(conn)
    assert finding["status"] == "PASS"


def test_check_key_algorithm_dsa_fails():
    """DSA OID in DER → TLS-04 FAIL HIGH."""
    conn = make_conn(peercert_der=_DSA_DER)
    finding = sta.check_key_algorithm(conn)
    assert finding["status"] == "FAIL"
    assert finding["risk_level"] == "HIGH"
    assert finding["severity_score"] > 0


def test_check_key_algorithm_unknown_fails():
    """Unknown OID → TLS-04 FAIL HIGH."""
    conn = make_conn(peercert_der=_UNK_DER)
    finding = sta.check_key_algorithm(conn)
    assert finding["status"] == "FAIL"


def test_check_key_algorithm_empty_der_fails():
    """Empty DER bytes → TLS-04 FAIL."""
    conn = make_conn(peercert_der=b"")
    finding = sta.check_key_algorithm(conn)
    assert finding["status"] == "FAIL"

# ── TLS-05: TLS version ───────────────────────────────────────────────────────

def test_check_tls_version_tls13_passes():
    """TLSv1.3 negotiated → TLS-05 PASS."""
    finding = sta.check_tls_version(make_conn(version="TLSv1.3"))
    assert finding["check_id"] == "TLS-05"
    assert finding["status"] == "PASS"


def test_check_tls_version_tls12_passes():
    """TLSv1.2 negotiated → TLS-05 PASS."""
    finding = sta.check_tls_version(make_conn(version="TLSv1.2"))
    assert finding["status"] == "PASS"


def test_check_tls_version_tls10_fails():
    """TLSv1.0 negotiated → TLS-05 FAIL HIGH."""
    finding = sta.check_tls_version(make_conn(version="TLSv1"))
    assert finding["status"] == "FAIL"
    assert finding["risk_level"] == "HIGH"
    assert finding["severity_score"] > 0


def test_check_tls_version_tls11_fails():
    """TLSv1.1 negotiated → TLS-05 FAIL HIGH."""
    finding = sta.check_tls_version(make_conn(version="TLSv1.1"))
    assert finding["status"] == "FAIL"
    assert finding["risk_level"] == "HIGH"
