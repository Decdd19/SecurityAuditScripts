"""Tests for sg_auditor.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../AWS/sg-auditor"))

import pytest
import sg_auditor as sg


# ── is_open_to_world ───────────────────────────────────────────────────────────

def test_is_open_to_world_ipv4():
    rule = {"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}
    assert sg.is_open_to_world(rule) is True


def test_is_open_to_world_ipv6():
    rule = {"IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
    assert sg.is_open_to_world(rule) is True


def test_is_open_to_world_restricted():
    rule = {"IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": []}
    assert sg.is_open_to_world(rule) is False


def test_is_open_to_world_sg_reference():
    # SG-to-SG rules have no IpRanges/Ipv6Ranges — must NOT be flagged as world-open
    rule = {"UserIdGroupPairs": [{"GroupId": "sg-abc123"}], "IpRanges": [], "Ipv6Ranges": []}
    assert sg.is_open_to_world(rule) is False


# ── port_in_range ──────────────────────────────────────────────────────────────

def test_port_in_range_exact():
    assert sg.port_in_range(22, 22, 22) is True


def test_port_in_range_within():
    assert sg.port_in_range(80, 0, 65535) is True


def test_port_in_range_outside():
    assert sg.port_in_range(443, 80, 80) is False


def test_port_in_range_all_traffic():
    assert sg.port_in_range(22, -1, -1) is True


# ── analyse_rules ──────────────────────────────────────────────────────────────

def test_analyse_rules_ssh_open():
    rules = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
               "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}]
    _, high_risk, _, open_ssh, _ = sg.analyse_rules(rules)
    assert open_ssh is True
    assert any("SSH" in p for p in high_risk)


def test_analyse_rules_rdp_open():
    rules = [{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
               "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}]
    _, high_risk, _, _, open_rdp = sg.analyse_rules(rules)
    assert open_rdp is True


def test_analyse_rules_all_traffic():
    rules = [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}]
    _, _, all_traffic, _, _ = sg.analyse_rules(rules)
    assert all_traffic is True


def test_analyse_rules_restricted_no_findings():
    rules = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
               "IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": []}]
    open_ports, high_risk, all_traffic, open_ssh, open_rdp = sg.analyse_rules(rules)
    assert open_ssh is False
    assert high_risk == []


# ── high risk ports coverage ───────────────────────────────────────────────────

def test_smtp_in_high_risk_ports():
    assert 25 in sg.HIGH_RISK_PORTS


def test_ldap_in_high_risk_ports():
    assert 389 in sg.HIGH_RISK_PORTS


def test_ldaps_in_high_risk_ports():
    assert 636 in sg.HIGH_RISK_PORTS


def test_nfs_in_high_risk_ports():
    assert 111 in sg.HIGH_RISK_PORTS


# ── calculate_score ────────────────────────────────────────────────────────────

def test_score_all_traffic_open():
    score, level = sg.calculate_score(False, False, True, [], False, False, 1)
    assert score >= 6


def test_score_ssh_open():
    score, level = sg.calculate_score(True, False, False, [], False, False, 1)
    assert score >= 4


def test_score_clean():
    score, level = sg.calculate_score(False, False, False, [], False, False, 0)
    assert score == 0
