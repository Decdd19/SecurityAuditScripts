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
