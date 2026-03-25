"""Tests for email_security_auditor.py"""
import sys
import os
import json
import base64
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import email_security_auditor as esa


# ── DNS wrapper tests ─────────────────────────────────────────────────────────

def test_query_txt_returns_strings():
    """query_txt returns list of strings for a real-looking domain."""
    import dns.resolver
    mock_answer = MagicMock()
    mock_rdata = MagicMock()
    mock_rdata.strings = [b'v=spf1 include:_spf.google.com ~all']
    mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))
    with patch('dns.resolver.resolve', return_value=mock_answer):
        result = esa.query_txt('example.com')
    assert result == ['v=spf1 include:_spf.google.com ~all']


def test_query_txt_nxdomain_returns_empty():
    """query_txt returns empty list on NXDOMAIN."""
    import dns.resolver
    with patch('dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN):
        result = esa.query_txt('notexist.example.com')
    assert result == []


def test_query_txt_servfail_returns_none():
    """query_txt returns None on transient DNS error (SERVFAIL/NoNameservers)."""
    import dns.resolver
    with patch('dns.resolver.resolve', side_effect=dns.resolver.NoNameservers):
        result = esa.query_txt('broken.example.com')
    assert result is None


def test_query_mx_returns_hostnames():
    """query_mx returns list of MX hostname strings."""
    import dns.resolver
    mock_answer = MagicMock()
    mock_rdata = MagicMock()
    mock_rdata.exchange = MagicMock()
    mock_rdata.exchange.__str__ = MagicMock(return_value='mail.example.com.')
    mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))
    with patch('dns.resolver.resolve', return_value=mock_answer):
        result = esa.query_mx('example.com')
    assert result == ['mail.example.com.']


def test_query_mx_nxdomain_returns_empty():
    """query_mx returns empty list when no MX records."""
    import dns.resolver
    with patch('dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN):
        result = esa.query_mx('nomail.example.com')
    assert result == []


def test_query_txt_no_answer_returns_empty():
    """query_txt returns empty list on NoAnswer (domain exists, no TXT record)."""
    import dns.resolver
    with patch('dns.resolver.resolve', side_effect=dns.resolver.NoAnswer):
        result = esa.query_txt('notxt.example.com')
    assert result == []


def test_query_mx_no_answer_returns_empty():
    """query_mx returns empty list on NoAnswer (domain exists, no MX record)."""
    import dns.resolver
    with patch('dns.resolver.resolve', side_effect=dns.resolver.NoAnswer):
        result = esa.query_mx('nomx.example.com')
    assert result == []


# ── MX check tests ────────────────────────────────────────────────────────────

def test_check_mx_found():
    """MX record found → PASS, risk LOW."""
    with patch.object(esa, 'query_mx', return_value=['mail.example.com.']):
        finding = esa.check_mx('example.com')
    assert finding['check_id'] == 'MX-01'
    assert finding['status'] == 'PASS'
    assert finding['risk_level'] == 'LOW'


def test_check_mx_missing():
    """No MX record → FAIL, detail mentions parked domain."""
    with patch.object(esa, 'query_mx', return_value=[]):
        finding = esa.check_mx('example.com')
    assert finding['status'] == 'FAIL'
    assert 'parked' in finding['detail'].lower() or 'no mail' in finding['detail'].lower()
    assert 'DMARC' in finding['remediation']


def test_check_mx_dns_error():
    """DNS transient error → WARN."""
    with patch.object(esa, 'query_mx', return_value=None):
        finding = esa.check_mx('example.com')
    assert finding['status'] == 'WARN'


# ── SPF check tests ───────────────────────────────────────────────────────────

def test_spf_missing():
    """No SPF record → SPF-01 FAIL HIGH."""
    with patch.object(esa, 'query_txt', return_value=[]):
        findings = esa.check_spf('example.com')
    spf01 = next(f for f in findings if f['check_id'] == 'SPF-01')
    assert spf01['status'] == 'FAIL'
    assert spf01['risk_level'] == 'HIGH'


def test_spf_plus_all_critical():
    """SPF with +all → SPF-02 CRITICAL FAIL."""
    with patch.object(esa, 'query_txt', return_value=['v=spf1 include:_spf.google.com +all']):
        findings = esa.check_spf('example.com')
    spf02 = next(f for f in findings if f['check_id'] == 'SPF-02')
    assert spf02['status'] == 'FAIL'
    assert spf02['risk_level'] == 'CRITICAL'


def test_spf_question_all_critical():
    """SPF with ?all → SPF-02 CRITICAL FAIL."""
    with patch.object(esa, 'query_txt', return_value=['v=spf1 include:_spf.google.com ?all']):
        findings = esa.check_spf('example.com')
    spf02 = next(f for f in findings if f['check_id'] == 'SPF-02')
    assert spf02['status'] == 'FAIL'
    assert spf02['risk_level'] == 'CRITICAL'


def test_spf_tilde_all_pass():
    """SPF with ~all → SPF-01 and SPF-02 both PASS."""
    with patch.object(esa, 'query_txt', return_value=['v=spf1 include:_spf.google.com ~all']):
        findings = esa.check_spf('example.com')
    spf01 = next(f for f in findings if f['check_id'] == 'SPF-01')
    spf02 = next(f for f in findings if f['check_id'] == 'SPF-02')
    assert spf01['status'] == 'PASS'
    assert spf02['status'] == 'PASS'


def test_spf_lookup_count_pass():
    """SPF with ≤10 mechanisms → SPF-03 PASS."""
    spf = 'v=spf1 include:a.com include:b.com include:c.com ~all'
    with patch.object(esa, 'query_txt', return_value=[spf]):
        findings = esa.check_spf('example.com')
    spf03 = next(f for f in findings if f['check_id'] == 'SPF-03')
    assert spf03['status'] == 'PASS'


def test_spf_lookup_count_fail():
    """SPF with >10 mechanisms → SPF-03 MEDIUM FAIL."""
    mechs = ' '.join(f'include:{i}.example.com' for i in range(11))
    spf = f'v=spf1 {mechs} ~all'
    with patch.object(esa, 'query_txt', return_value=[spf]):
        findings = esa.check_spf('example.com')
    spf03 = next(f for f in findings if f['check_id'] == 'SPF-03')
    assert spf03['status'] == 'FAIL'
    assert spf03['risk_level'] == 'MEDIUM'


def test_spf_dns_error_warn():
    """DNS transient error on SPF lookup → SPF-01 WARN."""
    with patch.object(esa, 'query_txt', return_value=None):
        findings = esa.check_spf('example.com')
    spf01 = next(f for f in findings if f['check_id'] == 'SPF-01')
    assert spf01['status'] == 'WARN'


# ── DKIM check tests ──────────────────────────────────────────────────────────

# A minimal valid RSA-1024 public key in base64 (real key, 1024-bit)
_VALID_1024_KEY = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2a1TM2f9j6LLgHp7e"
    "jLxR6HGkZq4K7b8G5pT1ZpViVqK9pAXFJxQR5V7Ukg0VdW9cFbbXWJDr"
    "ZsD6oZHuFqxGQpBOdN+m6FQsBMrqJIB/ZRlCTkbWpX3pR2hWzxFd0KhB"
    "XkT0c1tCgY0AiBnZM1c3FGcQa4M3bPNnYCrLbwIDAQAB"
)

# A 512-bit key (too short)
_SHORT_KEY = base64.b64encode(b'\x00' * 64).decode()


def test_dkim_found_on_provided_selector():
    """DKIM found on provided selector → DKIM-01 PASS."""
    txt = f'v=DKIM1; k=rsa; p={_VALID_1024_KEY}'
    with patch.object(esa, 'query_txt', return_value=[txt]):
        findings = esa.check_dkim('example.com', selector='google')
    dkim01 = next(f for f in findings if f['check_id'] == 'DKIM-01')
    assert dkim01['status'] == 'PASS'


def test_dkim_found_on_fallback_selector():
    """DKIM not found on custom selector, found on selector1 fallback."""
    txt = f'v=DKIM1; k=rsa; p={_VALID_1024_KEY}'

    def fake_query(name):
        if 'selector1' in name:
            return [txt]
        return []

    with patch.object(esa, 'query_txt', side_effect=fake_query):
        findings = esa.check_dkim('example.com', selector='customselector')
    dkim01 = next(f for f in findings if f['check_id'] == 'DKIM-01')
    assert dkim01['status'] == 'PASS'
    assert 'selector1' in dkim01['detail']


def test_dkim_not_found():
    """No DKIM record on any selector → DKIM-01 FAIL HIGH, DKIM-02 absent."""
    with patch.object(esa, 'query_txt', return_value=[]):
        findings = esa.check_dkim('example.com', selector=None)
    dkim01 = next(f for f in findings if f['check_id'] == 'DKIM-01')
    assert dkim01['status'] == 'FAIL'
    assert dkim01['risk_level'] == 'HIGH'
    assert not any(f['check_id'] == 'DKIM-02' for f in findings)


def test_dkim_empty_p_revoked():
    """DKIM record with empty p= (revoked key) → DKIM-01 FAIL."""
    with patch.object(esa, 'query_txt', return_value=['v=DKIM1; k=rsa; p=']):
        findings = esa.check_dkim('example.com', selector='default')
    dkim01 = next(f for f in findings if f['check_id'] == 'DKIM-01')
    assert dkim01['status'] == 'FAIL'
    assert 'revoked' in dkim01['detail'].lower()


def test_dkim_undecodable_p_warn():
    """DKIM with p= that can't be decoded → DKIM-02 WARN."""
    with patch.object(esa, 'query_txt', return_value=['v=DKIM1; k=rsa; p=notvalidbase64!!!']):
        findings = esa.check_dkim('example.com', selector='default')
    dkim02 = next((f for f in findings if f['check_id'] == 'DKIM-02'), None)
    assert dkim02 is not None
    assert dkim02['status'] == 'WARN'


def test_dkim02_absent_when_dkim01_fails():
    """DKIM-02 is omitted from findings when DKIM-01 fails (no record found)."""
    with patch.object(esa, 'query_txt', return_value=[]):
        findings = esa.check_dkim('example.com', selector=None)
    check_ids = [f['check_id'] for f in findings]
    assert 'DKIM-01' in check_ids
    assert 'DKIM-02' not in check_ids


# ── DMARC check tests ─────────────────────────────────────────────────────────

def test_dmarc_missing():
    """No DMARC record → DMARC-01 FAIL HIGH."""
    with patch.object(esa, 'query_txt', return_value=[]):
        findings = esa.check_dmarc('example.com')
    dmarc01 = next(f for f in findings if f['check_id'] == 'DMARC-01')
    assert dmarc01['status'] == 'FAIL'
    assert dmarc01['risk_level'] == 'HIGH'


def test_dmarc_policy_none():
    """DMARC p=none → DMARC-02 FAIL HIGH."""
    txt = 'v=DMARC1; p=none; rua=mailto:dmarc@example.com'
    with patch.object(esa, 'query_txt', return_value=[txt]):
        findings = esa.check_dmarc('example.com')
    dmarc02 = next(f for f in findings if f['check_id'] == 'DMARC-02')
    assert dmarc02['status'] == 'FAIL'
    assert dmarc02['risk_level'] == 'HIGH'


def test_dmarc_policy_quarantine():
    """DMARC p=quarantine → DMARC-02 PASS."""
    txt = 'v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com'
    with patch.object(esa, 'query_txt', return_value=[txt]):
        findings = esa.check_dmarc('example.com')
    dmarc02 = next(f for f in findings if f['check_id'] == 'DMARC-02')
    assert dmarc02['status'] == 'PASS'


def test_dmarc_policy_reject():
    """DMARC p=reject → DMARC-02 PASS."""
    txt = 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com'
    with patch.object(esa, 'query_txt', return_value=[txt]):
        findings = esa.check_dmarc('example.com')
    dmarc02 = next(f for f in findings if f['check_id'] == 'DMARC-02')
    assert dmarc02['status'] == 'PASS'


def test_dmarc_with_rua():
    """DMARC with rua= tag → DMARC-03 PASS."""
    txt = 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com'
    with patch.object(esa, 'query_txt', return_value=[txt]):
        findings = esa.check_dmarc('example.com')
    dmarc03 = next(f for f in findings if f['check_id'] == 'DMARC-03')
    assert dmarc03['status'] == 'PASS'


def test_dmarc_without_rua():
    """DMARC without rua= tag → DMARC-03 FAIL MEDIUM."""
    txt = 'v=DMARC1; p=reject'
    with patch.object(esa, 'query_txt', return_value=[txt]):
        findings = esa.check_dmarc('example.com')
    dmarc03 = next(f for f in findings if f['check_id'] == 'DMARC-03')
    assert dmarc03['status'] == 'FAIL'
    assert dmarc03['risk_level'] == 'MEDIUM'


def test_dmarc_dns_error_warn():
    """DNS transient error on DMARC lookup → DMARC-01 WARN."""
    with patch.object(esa, 'query_txt', return_value=None):
        findings = esa.check_dmarc('example.com')
    dmarc01 = next(f for f in findings if f['check_id'] == 'DMARC-01')
    assert dmarc01['status'] == 'WARN'


# ── Integration / run() tests ─────────────────────────────────────────────────

_VALID_1024_KEY_FOR_RUN = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2a1TM2f9j6LLgHp7e"
    "jLxR6HGkZq4K7b8G5pT1ZpViVqK9pAXFJxQR5V7Ukg0VdW9cFbbXWJDr"
    "ZsD6oZHuFqxGQpBOdN+m6FQsBMrqJIB/ZRlCTkbWpX3pR2hWzxFd0KhB"
    "XkT0c1tCgY0AiBnZM1c3FGcQa4M3bPNnYCrLbwIDAQAB"
)


def test_full_passing_domain_overall_risk_low():
    """All checks pass → overall_risk LOW."""
    good_spf = 'v=spf1 include:_spf.google.com -all'
    good_dkim = f'v=DKIM1; k=rsa; p={_VALID_1024_KEY_FOR_RUN}'
    good_dmarc = 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com'

    def fake_txt(name):
        if name == 'example.com':
            return [good_spf]
        if '_domainkey' in name:
            return [good_dkim]
        if '_dmarc' in name:
            return [good_dmarc]
        return []

    with patch.object(esa, 'query_mx', return_value=['mail.example.com.']), \
         patch.object(esa, 'query_txt', side_effect=fake_txt):
        report = esa.run('example.com', None, '/tmp/test_email_pass', 'json')

    assert report['summary']['overall_risk'] == 'LOW'


def test_full_failing_domain_overall_risk_critical():
    """All checks fail → overall_risk CRITICAL."""
    with patch.object(esa, 'query_mx', return_value=[]), \
         patch.object(esa, 'query_txt', return_value=[]):
        report = esa.run('example.com', None, '/tmp/test_email_fail', 'json')

    assert report['summary']['overall_risk'] == 'CRITICAL'


def test_run_produces_json_file(tmp_path):
    """run() with format=json creates a .json file."""
    prefix = str(tmp_path / 'email_report')
    with patch.object(esa, 'query_mx', return_value=[]), \
         patch.object(esa, 'query_txt', return_value=[]):
        esa.run('example.com', None, prefix, 'json')
    assert (tmp_path / 'email_report.json').exists()


def test_run_produces_html_file(tmp_path):
    """run() with format=html creates a .html file."""
    prefix = str(tmp_path / 'email_report')
    with patch.object(esa, 'query_mx', return_value=[]), \
         patch.object(esa, 'query_txt', return_value=[]):
        esa.run('example.com', None, prefix, 'html')
    assert (tmp_path / 'email_report.html').exists()


def test_run_produces_csv_file(tmp_path):
    """run() with format=csv creates a .csv file."""
    prefix = str(tmp_path / 'email_report')
    with patch.object(esa, 'query_mx', return_value=[]), \
         patch.object(esa, 'query_txt', return_value=[]):
        esa.run('example.com', None, prefix, 'csv')
    assert (tmp_path / 'email_report.csv').exists()
