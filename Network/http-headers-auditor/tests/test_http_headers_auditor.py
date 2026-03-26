"""Tests for http_headers_auditor.py"""
import sys
import os
import socket
import http.client
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import http_headers_auditor as hha


# ── Fixture helpers ───────────────────────────────────────────────────────────

def make_conn(**header_overrides) -> dict:
    """Build a get_http_headers() result. Pass header_name=None to remove it."""
    headers = {
        "x-frame-options": "SAMEORIGIN",
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'self'",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=()",
    }
    for k, v in header_overrides.items():
        if v is None:
            headers.pop(k, None)
        else:
            headers[k] = v
    return {"headers": headers}


# ── get_http_headers() wrapper tests ─────────────────────────────────────────

def test_get_http_headers_returns_none_on_connection_refused():
    with patch('http.client.HTTPSConnection') as mock_cls:
        mock_cls.return_value.request.side_effect = ConnectionRefusedError
        result = hha.get_http_headers('refused.example.com', 443)
    assert result is None


def test_get_http_headers_returns_none_on_timeout():
    with patch('http.client.HTTPSConnection') as mock_cls:
        mock_cls.return_value.request.side_effect = socket.timeout
        result = hha.get_http_headers('timeout.example.com', 443)
    assert result is None


def test_get_http_headers_returns_none_on_gaierror():
    with patch('http.client.HTTPSConnection') as mock_cls:
        mock_cls.return_value.request.side_effect = socket.gaierror
        result = hha.get_http_headers('notexist.example.com', 443)
    assert result is None


def test_get_http_headers_returns_none_on_http_exception():
    with patch('http.client.HTTPSConnection') as mock_cls:
        mock_cls.return_value.request.side_effect = http.client.HTTPException
        result = hha.get_http_headers('badhttp.example.com', 443)
    assert result is None


def test_get_http_headers_returns_dict_with_lowercased_headers():
    mock_resp = MagicMock()
    mock_resp.getheaders.return_value = [
        ("X-Frame-Options", "SAMEORIGIN"),
        ("Content-Security-Policy", "default-src 'self'"),
    ]
    with patch('http.client.HTTPSConnection') as mock_cls:
        mock_cls.return_value.getresponse.return_value = mock_resp
        result = hha.get_http_headers('acme.ie', 443)
    assert result is not None
    assert result["headers"]["x-frame-options"] == "SAMEORIGIN"
    assert result["headers"]["content-security-policy"] == "default-src 'self'"


# ── _finding() helper tests ───────────────────────────────────────────────────

def test_finding_structure():
    f = hha._finding("HDR-01", "X-Frame-Options", "FAIL", "HIGH", 7, "detail", "fix it")
    assert f["check_id"] == "HDR-01"
    assert f["name"] == "X-Frame-Options"
    assert f["status"] == "FAIL"
    assert f["risk_level"] == "HIGH"
    assert f["severity_score"] == 7
    assert f["detail"] == "detail"
    assert f["remediation"] == "fix it"
    assert f["pillar"] == "headers"


def test_finding_severity_score_zero_for_pass():
    f = hha._finding("HDR-01", "X-Frame-Options", "PASS", "HIGH", 7, "ok", "")
    assert f["severity_score"] == 0


def test_finding_severity_score_zero_for_warn():
    f = hha._finding("HDR-01", "X-Frame-Options", "WARN", "HIGH", 7, "weak", "fix")
    assert f["severity_score"] == 0


# ── HDR-00: Connectivity ──────────────────────────────────────────────────────

def test_check_connectivity_pass():
    conn = make_conn()
    f = hha.check_connectivity(conn, "acme.ie", 443)
    assert f["check_id"] == "HDR-00"
    assert f["status"] == "PASS"
    assert f["severity_score"] == 0


def test_check_connectivity_fail_on_none():
    f = hha.check_connectivity(None, "acme.ie", 443)
    assert f["check_id"] == "HDR-00"
    assert f["status"] == "FAIL"
    assert f["risk_level"] == "CRITICAL"
    assert f["severity_score"] == 10
    assert "acme.ie" in f["detail"]
    assert "443" in f["detail"]
