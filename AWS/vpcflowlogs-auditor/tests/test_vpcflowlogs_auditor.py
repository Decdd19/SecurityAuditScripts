"""Tests for vpcflowlogs_auditor.py"""
import sys
import os
import json
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import vpcflowlogs_auditor as vfa


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _vpc(vpc_id="vpc-aaa", is_default=False, name=None):
    tags = [{"Key": "Name", "Value": name}] if name else []
    return {
        "VpcId": vpc_id,
        "IsDefault": is_default,
        "Tags": tags,
        "_region": "eu-west-1",
    }


def _flow_log(vpc_id, traffic_type="ALL", status="ACTIVE",
              dest_type="cloud-watch-logs", log_group="/vpc/flow", fmt=None):
    fl = {
        "ResourceId": vpc_id,
        "TrafficType": traffic_type,
        "FlowLogStatus": status,
        "LogDestinationType": dest_type,
        "LogGroupName": log_group,
    }
    if fmt:
        fl["LogFormat"] = fmt
    return fl


def _make_clients(flow_logs=None, cw_retention=None):
    ec2 = MagicMock()
    logs = MagicMock()

    if cw_retention is None:
        logs.describe_log_groups.return_value = {"logGroups": []}
    else:
        logs.describe_log_groups.return_value = {
            "logGroups": [{"logGroupName": "/vpc/flow", "retentionInDays": cw_retention}]
        }

    return ec2, logs


# ── build_flags_and_remediations ──────────────────────────────────────────────

def test_flags_no_logs():
    flags, rems = vfa.build_flags_and_remediations(
        vpc_id="vpc-1", has_any_logs=False,
        has_all=False, has_accept=False, has_reject=False,
        uses_custom_format=False, cw_short_retention=False, is_default=False,
    )
    assert any("No flow logs" in f for f in flags)
    assert any("create-flow-logs" in r for r in rems)
    assert len(flags) == len(rems)


def test_flags_accept_only():
    flags, rems = vfa.build_flags_and_remediations(
        vpc_id="vpc-1", has_any_logs=True,
        has_all=False, has_accept=True, has_reject=False,
        uses_custom_format=False, cw_short_retention=False, is_default=False,
    )
    assert any("ACCEPT" in f for f in flags)
    assert len(flags) == len(rems)


def test_flags_reject_only():
    flags, rems = vfa.build_flags_and_remediations(
        vpc_id="vpc-1", has_any_logs=True,
        has_all=False, has_accept=False, has_reject=True,
        uses_custom_format=False, cw_short_retention=False, is_default=False,
    )
    assert any("REJECT" in f for f in flags)


def test_flags_default_format_uses_info_prefix():
    flags, rems = vfa.build_flags_and_remediations(
        vpc_id="vpc-1", has_any_logs=True,
        has_all=True, has_accept=False, has_reject=False,
        uses_custom_format=False, cw_short_retention=False, is_default=False,
    )
    assert any(f.startswith("ℹ️") and "format" in f.lower() for f in flags)


def test_flags_cw_short_retention_uses_info_prefix():
    flags, rems = vfa.build_flags_and_remediations(
        vpc_id="vpc-1", has_any_logs=True,
        has_all=True, has_accept=False, has_reject=False,
        uses_custom_format=True, cw_short_retention=True, is_default=False,
    )
    assert any(f.startswith("ℹ️") and "retention" in f.lower() for f in flags)


def test_flags_all_good_has_positive_flag():
    flags, rems = vfa.build_flags_and_remediations(
        vpc_id="vpc-1", has_any_logs=True,
        has_all=True, has_accept=False, has_reject=False,
        uses_custom_format=True, cw_short_retention=False, is_default=False,
    )
    assert any("✅" in f for f in flags)
    assert len(flags) == len(rems)


def test_flags_parallel_lengths():
    for scenario in [
        dict(has_any_logs=False, has_all=False, has_accept=False, has_reject=False,
             uses_custom_format=False, cw_short_retention=False),
        dict(has_any_logs=True, has_all=False, has_accept=True, has_reject=False,
             uses_custom_format=False, cw_short_retention=True),
        dict(has_any_logs=True, has_all=True, has_accept=False, has_reject=False,
             uses_custom_format=True, cw_short_retention=False),
    ]:
        flags, rems = vfa.build_flags_and_remediations(vpc_id="vpc-1", is_default=False, **scenario)
        assert len(flags) == len(rems), f"Mismatch in scenario {scenario}"


# ── calculate_score ────────────────────────────────────────────────────────────

def test_score_no_logs_is_critical():
    score, risk = vfa.calculate_score(has_any_logs=False, has_all=False)
    assert risk == "CRITICAL"
    assert score == 8


def test_score_partial_coverage_is_high():
    score, risk = vfa.calculate_score(has_any_logs=True, has_all=False)
    assert risk == "HIGH"


def test_score_full_coverage_is_low():
    score, risk = vfa.calculate_score(has_any_logs=True, has_all=True)
    assert risk == "LOW"


# ── analyse_vpc ───────────────────────────────────────────────────────────────

def test_analyse_vpc_no_flow_logs_is_critical():
    ec2, logs = _make_clients()
    vpc = _vpc("vpc-111")
    result = vfa.analyse_vpc(ec2, logs, vpc, flow_logs=[])
    assert result["risk_level"] == "CRITICAL"
    assert result["flow_log_count"] == 0
    assert result["vpc_id"] == "vpc-111"


def test_analyse_vpc_all_traffic_is_low():
    ec2, logs = _make_clients()
    vpc = _vpc("vpc-222")
    fl = _flow_log("vpc-222", traffic_type="ALL")
    result = vfa.analyse_vpc(ec2, logs, vpc, flow_logs=[fl])
    assert result["risk_level"] == "LOW"
    assert result["has_all_traffic_log"] is True
    assert result["flow_log_count"] == 1


def test_analyse_vpc_accept_only_is_high():
    ec2, logs = _make_clients()
    vpc = _vpc("vpc-333")
    fl = _flow_log("vpc-333", traffic_type="ACCEPT")
    result = vfa.analyse_vpc(ec2, logs, vpc, flow_logs=[fl])
    assert result["risk_level"] == "HIGH"
    assert result["has_accept_only_log"] is True


def test_analyse_vpc_inactive_log_not_counted():
    ec2, logs = _make_clients()
    vpc = _vpc("vpc-444")
    fl = _flow_log("vpc-444", traffic_type="ALL", status="ERROR")
    result = vfa.analyse_vpc(ec2, logs, vpc, flow_logs=[fl])
    assert result["risk_level"] == "CRITICAL"  # inactive log doesn't count
    assert result["flow_log_count"] == 0


def test_analyse_vpc_cw_short_retention_flagged():
    ec2, logs = _make_clients(cw_retention=30)
    logs.describe_log_groups.return_value = {
        "logGroups": [{"logGroupName": "/vpc/flow", "retentionInDays": 30}]
    }
    vpc = _vpc("vpc-555")
    fl = _flow_log("vpc-555", traffic_type="ALL", log_group="/vpc/flow")
    result = vfa.analyse_vpc(ec2, logs, vpc, flow_logs=[fl])
    assert result["cw_short_retention"] is True
    assert any("retention" in f.lower() for f in result["flags"])


def test_analyse_vpc_result_has_required_keys():
    ec2, logs = _make_clients()
    vpc = _vpc("vpc-666", name="my-vpc")
    result = vfa.analyse_vpc(ec2, logs, vpc, flow_logs=[])
    for key in ["vpc_id", "vpc_name", "region", "risk_level", "severity_score",
                "flags", "remediations", "flow_log_count", "has_all_traffic_log"]:
        assert key in result, f"Missing key: {key}"


def test_analyse_vpc_flags_rems_same_length():
    ec2, logs = _make_clients()
    vpc = _vpc("vpc-777")
    fl = _flow_log("vpc-777", traffic_type="ACCEPT")
    result = vfa.analyse_vpc(ec2, logs, vpc, flow_logs=[fl])
    assert len(result["flags"]) == len(result["remediations"])


# ── get_vpc_name ──────────────────────────────────────────────────────────────

def test_get_vpc_name_returns_name_tag():
    vpc = {"Tags": [{"Key": "Name", "Value": "prod-vpc"}, {"Key": "Env", "Value": "prod"}]}
    assert vfa.get_vpc_name(vpc) == "prod-vpc"


def test_get_vpc_name_empty_when_no_name_tag():
    vpc = {"Tags": [{"Key": "Env", "Value": "prod"}]}
    assert vfa.get_vpc_name(vpc) == ""


def test_get_vpc_name_empty_when_no_tags():
    assert vfa.get_vpc_name({}) == ""


# ── write_json ────────────────────────────────────────────────────────────────

def _sample_report():
    return {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "summary": {"total_vpcs": 1, "vpcs_without_flow_logs": 0,
                    "critical": 0, "high": 0, "medium": 0, "low": 1},
        "findings": [{
            "vpc_id": "vpc-aaa", "vpc_name": "prod-vpc", "region": "eu-west-1",
            "is_default": False, "flow_log_count": 1,
            "has_all_traffic_log": True, "has_accept_only_log": False,
            "has_reject_only_log": False, "destinations": ["s3"],
            "uses_custom_format": True, "cw_short_retention": False,
            "risk_level": "LOW", "severity_score": 1,
            "flags": ["✅ ALL traffic flow logs active"], "remediations": [""],
        }],
    }


def test_write_json_creates_valid_json(tmp_path):
    path = str(tmp_path / "report.json")
    vfa.write_json(_sample_report(), path)
    data = json.loads(open(path).read())
    assert data["findings"][0]["vpc_id"] == "vpc-aaa"


def test_write_json_600_permissions(tmp_path):
    path = str(tmp_path / "report.json")
    vfa.write_json(_sample_report(), path)
    assert oct(os.stat(path).st_mode)[-3:] == "600"


def test_write_html_creates_file(tmp_path):
    path = str(tmp_path / "report.html")
    vfa.write_html(_sample_report(), path)
    content = open(path).read()
    assert "vpc-aaa" in content
    assert "VPC Flow Logs" in content


def test_write_html_600_permissions(tmp_path):
    path = str(tmp_path / "report.html")
    vfa.write_html(_sample_report(), path)
    assert oct(os.stat(path).st_mode)[-3:] == "600"


def test_write_csv_creates_file(tmp_path):
    path = str(tmp_path / "report.csv")
    vfa.write_csv(_sample_report()["findings"], path)
    content = open(path).read()
    assert "vpc-aaa" in content
