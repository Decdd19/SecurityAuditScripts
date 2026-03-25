"""Tests for elb_auditor.py"""
import sys
import os
import json as json_module
import csv as csv_module
from unittest.mock import MagicMock, patch, call
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import elb_auditor as ea


def _client_error(code):
    error = {"Error": {"Code": code, "Message": ""}}
    return ClientError(error, "test")


# ── calculate_score ───────────────────────────────────────────────────────────

def test_calculate_score_all_good_low():
    score, risk = ea.calculate_score(
        no_access_logs=False, no_deletion_protection=False,
        http_no_redirect=False, outdated_ssl_policy=False,
        no_waf=False, lb_type="application"
    )
    assert score == 0
    assert risk == "LOW"


def test_calculate_score_http_no_redirect_alb():
    score, risk = ea.calculate_score(
        no_access_logs=False, no_deletion_protection=False,
        http_no_redirect=True, outdated_ssl_policy=False,
        no_waf=False, lb_type="application"
    )
    assert score == 3
    assert risk == "MEDIUM"


def test_calculate_score_http_no_redirect_ignored_for_nlb():
    score, risk = ea.calculate_score(
        no_access_logs=False, no_deletion_protection=False,
        http_no_redirect=True, outdated_ssl_policy=False,
        no_waf=False, lb_type="network"
    )
    assert score == 0
    assert risk == "LOW"


def test_calculate_score_outdated_ssl_policy():
    score, risk = ea.calculate_score(
        no_access_logs=False, no_deletion_protection=False,
        http_no_redirect=False, outdated_ssl_policy=True,
        no_waf=False, lb_type="application"
    )
    assert score == 3
    assert risk == "MEDIUM"


def test_calculate_score_no_access_logs():
    score, risk = ea.calculate_score(
        no_access_logs=True, no_deletion_protection=False,
        http_no_redirect=False, outdated_ssl_policy=False,
        no_waf=False, lb_type="application"
    )
    assert score == 2
    assert risk == "MEDIUM"


def test_calculate_score_no_waf_alb():
    score, risk = ea.calculate_score(
        no_access_logs=False, no_deletion_protection=False,
        http_no_redirect=False, outdated_ssl_policy=False,
        no_waf=True, lb_type="application"
    )
    assert score == 2
    assert risk == "MEDIUM"


def test_calculate_score_no_waf_ignored_for_nlb():
    score, risk = ea.calculate_score(
        no_access_logs=False, no_deletion_protection=False,
        http_no_redirect=False, outdated_ssl_policy=False,
        no_waf=True, lb_type="network"
    )
    assert score == 0
    assert risk == "LOW"


def test_calculate_score_no_deletion_protection():
    score, risk = ea.calculate_score(
        no_access_logs=False, no_deletion_protection=True,
        http_no_redirect=False, outdated_ssl_policy=False,
        no_waf=False, lb_type="application"
    )
    assert score == 1
    assert risk == "LOW"


def test_calculate_score_combined_high():
    score, risk = ea.calculate_score(
        no_access_logs=True, no_deletion_protection=True,
        http_no_redirect=True, outdated_ssl_policy=True,
        no_waf=True, lb_type="application"
    )
    assert score >= 8
    assert risk == "CRITICAL"


def test_calculate_score_capped_at_10():
    score, risk = ea.calculate_score(
        no_access_logs=True, no_deletion_protection=True,
        http_no_redirect=True, outdated_ssl_policy=True,
        no_waf=True, lb_type="application"
    )
    assert score <= 10


# ── check_access_logs ─────────────────────────────────────────────────────────

def test_check_access_logs_enabled():
    attrs = [{"Key": "access_logs.s3.enabled", "Value": "true"}]
    assert ea.check_access_logs(attrs) is True


def test_check_access_logs_disabled():
    attrs = [{"Key": "access_logs.s3.enabled", "Value": "false"}]
    assert ea.check_access_logs(attrs) is False


def test_check_access_logs_missing_key():
    attrs = [{"Key": "deletion_protection.enabled", "Value": "true"}]
    assert ea.check_access_logs(attrs) is False


# ── check_deletion_protection ─────────────────────────────────────────────────

def test_check_deletion_protection_enabled():
    attrs = [{"Key": "deletion_protection.enabled", "Value": "true"}]
    assert ea.check_deletion_protection(attrs) is True


def test_check_deletion_protection_disabled():
    attrs = [{"Key": "deletion_protection.enabled", "Value": "false"}]
    assert ea.check_deletion_protection(attrs) is False


# ── check_http_redirect ───────────────────────────────────────────────────────

def test_check_http_redirect_with_redirect_action():
    listeners = [
        {
            "Port": 80,
            "Protocol": "HTTP",
            "DefaultActions": [
                {
                    "Type": "redirect",
                    "RedirectConfig": {"Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301"},
                }
            ],
        }
    ]
    has_http, redirects = ea.check_http_redirect(listeners)
    assert has_http is True
    assert redirects is True


def test_check_http_redirect_without_redirect():
    listeners = [
        {
            "Port": 80,
            "Protocol": "HTTP",
            "DefaultActions": [
                {"Type": "forward", "TargetGroupArn": "arn:aws:elasticloadbalancing:..."}
            ],
        }
    ]
    has_http, redirects = ea.check_http_redirect(listeners)
    assert has_http is True
    assert redirects is False


def test_check_http_redirect_no_port80_listener():
    listeners = [
        {
            "Port": 443,
            "Protocol": "HTTPS",
            "DefaultActions": [{"Type": "forward"}],
        }
    ]
    has_http, redirects = ea.check_http_redirect(listeners)
    assert has_http is False
    assert redirects is None


# ── check_ssl_policy ──────────────────────────────────────────────────────────

def test_check_ssl_policy_outdated_alb():
    listeners = [
        {
            "Port": 443,
            "Protocol": "HTTPS",
            "SslPolicy": "ELBSecurityPolicy-2016-08",
        }
    ]
    outdated, policies = ea.check_ssl_policy(listeners, "application")
    assert outdated is True
    assert "ELBSecurityPolicy-2016-08" in policies


def test_check_ssl_policy_current_alb():
    listeners = [
        {
            "Port": 443,
            "Protocol": "HTTPS",
            "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
        }
    ]
    outdated, policies = ea.check_ssl_policy(listeners, "application")
    assert outdated is False
    assert "ELBSecurityPolicy-TLS13-1-2-2021-06" in policies


def test_check_ssl_policy_no_https_listener():
    listeners = [
        {"Port": 80, "Protocol": "HTTP"}
    ]
    outdated, policies = ea.check_ssl_policy(listeners, "application")
    assert outdated is False
    assert policies == []


def test_check_ssl_policy_outdated_nlb():
    listeners = [
        {
            "Port": 443,
            "Protocol": "TLS",
            "SslPolicy": "ELBSecurityPolicy-TLS-1-0-2015-04",
        }
    ]
    outdated, policies = ea.check_ssl_policy(listeners, "network")
    assert outdated is True
    assert "ELBSecurityPolicy-TLS-1-0-2015-04" in policies


# ── check_waf_association ─────────────────────────────────────────────────────

def test_check_waf_association_present():
    wafv2 = MagicMock()
    lb_arn = "arn:aws:elasticloadbalancing:eu-west-1:123:loadbalancer/app/my-alb/abc"
    wafv2.list_web_acls.return_value = {
        "WebACLs": [{"ARN": "arn:aws:wafv2:eu-west-1:123:regional/webacl/my-acl/xyz"}]
    }
    wafv2.list_resources_by_web_acl.return_value = {"ResourceArns": [lb_arn]}
    result = ea.check_waf_association(wafv2, lb_arn)
    assert result is True


def test_check_waf_association_no_waf():
    wafv2 = MagicMock()
    lb_arn = "arn:aws:elasticloadbalancing:eu-west-1:123:loadbalancer/app/my-alb/abc"
    wafv2.list_web_acls.return_value = {"WebACLs": []}
    result = ea.check_waf_association(wafv2, lb_arn)
    assert result is False


def test_check_waf_association_api_error():
    wafv2 = MagicMock()
    lb_arn = "arn:aws:elasticloadbalancing:eu-west-1:123:loadbalancer/app/my-alb/abc"
    wafv2.list_web_acls.side_effect = _client_error("AccessDeniedException")
    result = ea.check_waf_association(wafv2, lb_arn)
    assert result is False


def test_check_waf_association_inner_client_error_skipped():
    """Inner list_resources_by_web_acl error should be caught; returns False overall."""
    wafv2 = MagicMock()
    lb_arn = "arn:aws:elasticloadbalancing:eu-west-1:123:loadbalancer/app/my-alb/abc"
    wafv2.list_web_acls.return_value = {
        "WebACLs": [{"ARN": "arn:aws:wafv2:eu-west-1:123:regional/webacl/my-acl/xyz"}]
    }
    wafv2.list_resources_by_web_acl.side_effect = _client_error("WAFNonexistentItemException")
    result = ea.check_waf_association(wafv2, lb_arn)
    assert result is False


# ── analyse_lb ────────────────────────────────────────────────────────────────

def _make_alb_dict(name="my-alb", scheme="internet-facing"):
    return {
        "LoadBalancerArn": f"arn:aws:elasticloadbalancing:eu-west-1:123:loadbalancer/app/{name}/abc",
        "LoadBalancerName": name,
        "Type": "application",
        "Scheme": scheme,
        "State": {"Code": "active"},
        "VpcId": "vpc-123",
        "AvailabilityZones": [{"ZoneName": "eu-west-1a"}],
    }


def _make_nlb_dict(name="my-nlb"):
    return {
        "LoadBalancerArn": f"arn:aws:elasticloadbalancing:eu-west-1:123:loadbalancer/net/{name}/def",
        "LoadBalancerName": name,
        "Type": "network",
        "Scheme": "internal",
        "State": {"Code": "active"},
        "VpcId": "vpc-456",
        "AvailabilityZones": [],
    }


def _make_elbv2_client(listeners=None, attributes=None):
    client = MagicMock()
    client.describe_listeners.return_value = {
        "Listeners": listeners if listeners is not None else []
    }
    client.describe_load_balancer_attributes.return_value = {
        "Attributes": attributes if attributes is not None else []
    }
    return client


def _make_wafv2_client(associated=False, lb_arn=""):
    client = MagicMock()
    if associated:
        client.list_web_acls.return_value = {
            "WebACLs": [{"ARN": "arn:aws:wafv2:eu-west-1:123:regional/webacl/acl/xyz"}]
        }
        client.list_resources_by_web_acl.return_value = {"ResourceArns": [lb_arn]}
    else:
        client.list_web_acls.return_value = {"WebACLs": []}
    return client


def test_analyse_lb_alb_all_issues():
    """ALB with every possible issue should have HIGH or CRITICAL risk."""
    alb = _make_alb_dict()
    attrs = [
        {"Key": "access_logs.s3.enabled", "Value": "false"},
        {"Key": "deletion_protection.enabled", "Value": "false"},
    ]
    listeners = [
        {
            "Port": 80,
            "Protocol": "HTTP",
            "DefaultActions": [{"Type": "forward"}],
        },
        {
            "Port": 443,
            "Protocol": "HTTPS",
            "SslPolicy": "ELBSecurityPolicy-2016-08",
            "DefaultActions": [{"Type": "forward"}],
        },
    ]
    elbv2 = _make_elbv2_client(listeners=listeners, attributes=attrs)
    wafv2 = _make_wafv2_client(associated=False, lb_arn=alb["LoadBalancerArn"])
    result = ea.analyse_lb(elbv2, wafv2, alb, "eu-west-1")
    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert result["access_logs_enabled"] is False
    assert result["deletion_protection"] is False
    assert result["http_redirect_to_https"] is False
    assert result["outdated_ssl_policy"] is True
    assert result["waf_associated"] is False
    warning_flags = [f for f in result["flags"] if not f.startswith("✅")]
    assert len(result["remediations"]) == len(warning_flags)


def test_analyse_lb_nlb_waf_and_redirect_not_applicable():
    """NLB should have waf_associated=None and http_redirect_to_https=None."""
    nlb = _make_nlb_dict()
    attrs = [
        {"Key": "access_logs.s3.enabled", "Value": "true"},
        {"Key": "deletion_protection.enabled", "Value": "true"},
    ]
    listeners = [
        {
            "Port": 443,
            "Protocol": "TLS",
            "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
            "DefaultActions": [{"Type": "forward"}],
        }
    ]
    elbv2 = _make_elbv2_client(listeners=listeners, attributes=attrs)
    wafv2 = MagicMock()
    result = ea.analyse_lb(elbv2, wafv2, nlb, "eu-west-1")
    assert result["waf_associated"] is None
    assert result["http_redirect_to_https"] is None
    assert result["lb_type"] == "network"


def test_analyse_lb_alb_clean_low_risk():
    """ALB with all good settings should be LOW risk."""
    alb = _make_alb_dict(scheme="internal")
    attrs = [
        {"Key": "access_logs.s3.enabled", "Value": "true"},
        {"Key": "deletion_protection.enabled", "Value": "true"},
    ]
    listeners = [
        {
            "Port": 443,
            "Protocol": "HTTPS",
            "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
            "DefaultActions": [{"Type": "forward"}],
        }
    ]
    elbv2 = _make_elbv2_client(listeners=listeners, attributes=attrs)
    wafv2 = _make_wafv2_client(associated=True, lb_arn=alb["LoadBalancerArn"])
    result = ea.analyse_lb(elbv2, wafv2, alb, "eu-west-1")
    assert result["risk_level"] == "LOW"
    assert result["severity_score"] == 0


# ── Writers ───────────────────────────────────────────────────────────────────

SAMPLE_FINDING = {
    "lb_name": "my-alb",
    "lb_arn": "arn:aws:elasticloadbalancing:eu-west-1:123:loadbalancer/app/my-alb/abc",
    "lb_type": "application",
    "scheme": "internet-facing",
    "region": "eu-west-1",
    "vpc_id": "vpc-123",
    "state": "active",
    "access_logs_enabled": False,
    "deletion_protection": False,
    "http_redirect_to_https": False,
    "has_http_listener": True,
    "outdated_ssl_policy": True,
    "ssl_policies_found": ["ELBSecurityPolicy-2016-08"],
    "waf_associated": False,
    "severity_score": 8,
    "risk_level": "CRITICAL",
    "flags": [
        "⚠️ Access logging to S3 is not enabled",
        "❌ HTTP listener (port 80) does not redirect to HTTPS",
        "❌ Outdated SSL/TLS security policy in use: ELBSecurityPolicy-2016-08",
        "⚠️ No WAF WebACL associated with this ALB",
        "⚠️ Deletion protection is not enabled",
        "ℹ️ Load balancer is internet-facing (verify this is intentional)",
    ],
    "remediations": [
        "Enable access logging.",
        "Add HTTPS redirect.",
        "Update SSL policy.",
        "Associate a WAF WebACL.",
        "Enable deletion protection.",
        "Confirm internet-facing exposure is required.",
    ],
}


def test_write_json_creates_file_with_600_perms(tmp_path):
    report = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "account_id": "123456789012",
        "findings": [SAMPLE_FINDING],
        "summary": {},
    }
    out = str(tmp_path / "test.json")
    ea.write_json(report, out)
    assert (tmp_path / "test.json").exists()
    assert (tmp_path / "test.json").stat().st_mode & 0o777 == 0o600


def test_write_json_content_is_valid(tmp_path):
    report = {"generated_at": "2026-01-01", "findings": [SAMPLE_FINDING], "summary": {}}
    out = str(tmp_path / "test.json")
    ea.write_json(report, out)
    with open(out) as f:
        data = json_module.load(f)
    assert data["findings"][0]["lb_name"] == "my-alb"


def test_write_csv_creates_file_with_600_perms(tmp_path):
    out = str(tmp_path / "test.csv")
    ea.write_csv([SAMPLE_FINDING], out)
    assert (tmp_path / "test.csv").exists()
    assert (tmp_path / "test.csv").stat().st_mode & 0o777 == 0o600


def test_write_csv_empty_no_file(tmp_path):
    out = str(tmp_path / "empty.csv")
    ea.write_csv([], out)
    assert not (tmp_path / "empty.csv").exists()


def test_write_csv_includes_expected_columns(tmp_path):
    out = str(tmp_path / "test.csv")
    ea.write_csv([SAMPLE_FINDING], out)
    with open(out) as f:
        reader = csv_module.DictReader(f)
        assert "remediations" in reader.fieldnames
        assert "lb_name" in reader.fieldnames
        assert "risk_level" in reader.fieldnames


def test_write_html_creates_file_with_600_perms(tmp_path):
    report = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "account_id": "123456789012",
        "findings": [SAMPLE_FINDING],
        "summary": {
            "total_load_balancers": 1, "critical": 1, "high": 0,
            "medium": 0, "low": 0, "no_access_logs": 1,
            "http_no_redirect": 1, "outdated_ssl_policy": 1, "no_waf": 1,
        },
    }
    out = str(tmp_path / "test.html")
    ea.write_html(report, out)
    assert (tmp_path / "test.html").exists()
    assert (tmp_path / "test.html").stat().st_mode & 0o777 == 0o600


def test_write_html_contains_lb_name(tmp_path):
    report = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "account_id": "123456789012",
        "findings": [SAMPLE_FINDING],
        "summary": {
            "total_load_balancers": 1, "critical": 1, "high": 0,
            "medium": 0, "low": 0, "no_access_logs": 1,
            "http_no_redirect": 1, "outdated_ssl_policy": 1, "no_waf": 1,
        },
    }
    out = str(tmp_path / "test.html")
    ea.write_html(report, out)
    with open(out) as f:
        content = f.read()
    assert "my-alb" in content


# ── run (integration) ─────────────────────────────────────────────────────────

def test_run_returns_report_structure():
    """run() should return a dict with expected top-level keys."""
    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_elbv2 = MagicMock()
    mock_wafv2 = MagicMock()

    # Paginator returns one page with one ALB
    mock_page_iter = [
        {
            "LoadBalancers": [
                {
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:eu-west-1:123:loadbalancer/app/test-alb/abc",
                    "LoadBalancerName": "test-alb",
                    "Type": "application",
                    "Scheme": "internal",
                    "State": {"Code": "active"},
                    "VpcId": "vpc-001",
                    "AvailabilityZones": [],
                }
            ]
        }
    ]
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = mock_page_iter
    mock_elbv2.get_paginator.return_value = mock_paginator
    mock_elbv2.describe_listeners.return_value = {"Listeners": []}
    mock_elbv2.describe_load_balancer_attributes.return_value = {"Attributes": []}
    mock_wafv2.list_web_acls.return_value = {"WebACLs": []}

    def session_client(service, **kwargs):
        if service == "sts":
            return mock_sts
        if service == "elbv2":
            return mock_elbv2
        if service == "wafv2":
            return mock_wafv2
        return MagicMock()

    mock_session.client.side_effect = session_client

    with patch("boto3.Session", return_value=mock_session):
        report = ea.run(output_prefix="/dev/null/elb_report", fmt="stdout",
                        profile=None, regions=["eu-west-1"])

    assert report is not None
    assert "generated_at" in report
    assert "account_id" in report
    assert "summary" in report
    assert "findings" in report
    assert report["account_id"] == "123456789012"
    assert report["summary"]["total_load_balancers"] == 1
    assert isinstance(report["findings"], list)
    assert report["findings"][0]["lb_name"] == "test-alb"
