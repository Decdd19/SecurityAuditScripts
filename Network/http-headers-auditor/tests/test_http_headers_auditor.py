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


def test_get_http_headers_returns_none_on_oserror():
    with patch('http.client.HTTPSConnection') as mock_cls:
        mock_cls.return_value.request.side_effect = OSError
        result = hha.get_http_headers('oserror.example.com', 443)
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


# ── HDR-01: X-Frame-Options ───────────────────────────────────────────────────

def test_check_x_frame_options_pass_sameorigin():
    f = hha.check_x_frame_options(make_conn(**{"x-frame-options": "SAMEORIGIN"}))
    assert f["check_id"] == "HDR-01"
    assert f["status"] == "PASS"


def test_check_x_frame_options_pass_deny():
    f = hha.check_x_frame_options(make_conn(**{"x-frame-options": "DENY"}))
    assert f["status"] == "PASS"


def test_check_x_frame_options_warn_allowfrom():
    f = hha.check_x_frame_options(make_conn(**{"x-frame-options": "ALLOWFROM https://trusted.com"}))
    assert f["status"] == "WARN"
    assert f["severity_score"] == 0
    assert "deprecated" in f["detail"].lower()


def test_check_x_frame_options_fail_absent():
    f = hha.check_x_frame_options(make_conn(**{"x-frame-options": None}))
    assert f["status"] == "FAIL"
    assert f["risk_level"] == "HIGH"
    assert f["severity_score"] == 7


def test_check_x_frame_options_fail_unrecognised_value():
    f = hha.check_x_frame_options(make_conn(**{"x-frame-options": "INVALID"}))
    assert f["status"] == "FAIL"
    assert f["severity_score"] == 7


# ── HDR-02: X-Content-Type-Options ───────────────────────────────────────────

def test_check_x_content_type_options_pass():
    f = hha.check_x_content_type_options(make_conn(**{"x-content-type-options": "nosniff"}))
    assert f["check_id"] == "HDR-02"
    assert f["status"] == "PASS"


def test_check_x_content_type_options_fail_absent():
    f = hha.check_x_content_type_options(make_conn(**{"x-content-type-options": None}))
    assert f["status"] == "FAIL"
    assert f["risk_level"] == "MEDIUM"
    assert f["severity_score"] == 5


def test_check_x_content_type_options_fail_wrong_value():
    f = hha.check_x_content_type_options(make_conn(**{"x-content-type-options": "sniff"}))
    assert f["status"] == "FAIL"
    assert f["severity_score"] == 5


# ── HDR-03: Content-Security-Policy ──────────────────────────────────────────

def test_check_csp_pass_clean_policy():
    f = hha.check_content_security_policy(
        make_conn(**{"content-security-policy": "default-src 'self'; script-src 'self'; frame-ancestors 'self'"})
    )
    assert f["check_id"] == "HDR-03"
    assert f["status"] == "PASS"


def test_check_csp_warn_missing_frame_ancestors():
    f = hha.check_content_security_policy(
        make_conn(**{"content-security-policy": "default-src 'self'; script-src 'self'"})
    )
    assert f["status"] == "WARN"
    assert "frame-ancestors" in f["detail"]


def test_check_csp_warn_wildcard_default_src():
    f = hha.check_content_security_policy(
        make_conn(**{"content-security-policy": "default-src *; script-src 'self'"})
    )
    assert f["status"] == "WARN"
    assert "default-src *" in f["detail"] or "wildcard" in f["detail"].lower()


def test_check_csp_warn_unsafe_inline():
    f = hha.check_content_security_policy(
        make_conn(**{"content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"})
    )
    assert f["status"] == "WARN"
    assert f["severity_score"] == 0
    assert "unsafe-inline" in f["detail"]


def test_check_csp_warn_unsafe_eval():
    f = hha.check_content_security_policy(
        make_conn(**{"content-security-policy": "default-src 'self'; script-src 'unsafe-eval'"})
    )
    assert f["status"] == "WARN"
    assert "unsafe-eval" in f["detail"]


def test_check_csp_warn_both_unsafe_directives():
    f = hha.check_content_security_policy(
        make_conn(**{"content-security-policy": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'"})
    )
    assert f["status"] == "WARN"
    assert "'unsafe-eval'" in f["detail"]
    assert "'unsafe-inline'" in f["detail"]


def test_check_csp_fail_absent():
    f = hha.check_content_security_policy(make_conn(**{"content-security-policy": None}))
    assert f["status"] == "FAIL"
    assert f["risk_level"] == "HIGH"
    assert f["severity_score"] == 8


# ── HDR-04: Referrer-Policy ───────────────────────────────────────────────────

def test_check_referrer_policy_pass_strict_origin():
    f = hha.check_referrer_policy(
        make_conn(**{"referrer-policy": "strict-origin-when-cross-origin"})
    )
    assert f["check_id"] == "HDR-04"
    assert f["status"] == "PASS"


def test_check_referrer_policy_pass_no_referrer_when_downgrade():
    # Explicitly PASS per design decision
    f = hha.check_referrer_policy(
        make_conn(**{"referrer-policy": "no-referrer-when-downgrade"})
    )
    assert f["status"] == "PASS"


def test_check_referrer_policy_fail_absent():
    f = hha.check_referrer_policy(make_conn(**{"referrer-policy": None}))
    assert f["status"] == "FAIL"
    assert f["risk_level"] == "MEDIUM"
    assert f["severity_score"] == 4


def test_check_referrer_policy_fail_unsafe_url():
    f = hha.check_referrer_policy(make_conn(**{"referrer-policy": "unsafe-url"}))
    assert f["status"] == "FAIL"
    assert f["severity_score"] == 4


def test_check_referrer_policy_fail_origin():
    f = hha.check_referrer_policy(make_conn(**{"referrer-policy": "origin"}))
    assert f["status"] == "FAIL"


# ── HDR-05: Permissions-Policy ───────────────────────────────────────────────

def test_check_permissions_policy_pass():
    f = hha.check_permissions_policy(
        make_conn(**{"permissions-policy": "camera=(), microphone=()"})
    )
    assert f["check_id"] == "HDR-05"
    assert f["status"] == "PASS"


def test_check_permissions_policy_warn_absent():
    f = hha.check_permissions_policy(make_conn(**{"permissions-policy": None}))
    assert f["status"] == "WARN"
    assert f["risk_level"] == "LOW"
    assert f["severity_score"] == 0  # WARN → score always 0


# ── run_audit() ───────────────────────────────────────────────────────────────

def test_run_audit_returns_6_findings():
    with patch('http_headers_auditor.get_http_headers', return_value=make_conn()):
        findings = hha.run_audit("acme.ie", 443)
    assert len(findings) == 6


def test_run_audit_all_check_ids_present():
    with patch('http_headers_auditor.get_http_headers', return_value=make_conn()):
        findings = hha.run_audit("acme.ie", 443)
    ids = {f["check_id"] for f in findings}
    assert ids == {"HDR-00", "HDR-01", "HDR-02", "HDR-03", "HDR-04", "HDR-05"}


def test_run_audit_connectivity_fail_short_circuits_to_6_findings():
    with patch('http_headers_auditor.get_http_headers', return_value=None):
        findings = hha.run_audit("unreachable.ie", 443)
    assert len(findings) == 6
    assert findings[0]["check_id"] == "HDR-00"
    assert findings[0]["status"] == "FAIL"
    # Remaining 5 should all be FAIL with skip message
    for f in findings[1:]:
        assert f["status"] == "FAIL"
        assert "skipped" in f["detail"].lower()


def test_run_audit_all_findings_have_pillar_headers():
    with patch('http_headers_auditor.get_http_headers', return_value=make_conn()):
        findings = hha.run_audit("acme.ie", 443)
    for f in findings:
        assert f["pillar"] == "headers", f"Expected pillar='headers', got '{f['pillar']}' for {f['check_id']}"
