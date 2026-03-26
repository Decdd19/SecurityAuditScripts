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
