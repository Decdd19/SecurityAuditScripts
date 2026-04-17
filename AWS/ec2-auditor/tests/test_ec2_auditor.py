"""Tests for ec2_auditor.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
import ec2_auditor as ec2


def _client_error(code):
    error = {"Error": {"Code": code, "Message": ""}}
    return ClientError(error, "test")


# ── check_imds ────────────────────────────────────────────────────────────────

def test_check_imds_v2_required():
    """IMDSv2-only → imds_v2_required=True, imds_hop_limit=integer"""
    meta = {"HttpEndpoint": "enabled", "HttpTokens": "required", "HttpPutResponseHopLimit": 1}
    v2_required, hop_limit = ec2.check_imds(meta)
    assert v2_required is True
    assert hop_limit == 1


def test_check_imds_v1_optional():
    meta = {"HttpEndpoint": "enabled", "HttpTokens": "optional", "HttpPutResponseHopLimit": 2}
    v2_required, hop_limit = ec2.check_imds(meta)
    assert v2_required is False
    assert hop_limit == 2


def test_check_imds_endpoint_disabled():
    meta = {"HttpEndpoint": "disabled", "HttpTokens": "optional", "HttpPutResponseHopLimit": 1}
    v2_required, hop_limit = ec2.check_imds(meta)
    assert v2_required is False


# ── check_ebs_encryption ──────────────────────────────────────────────────────

def test_check_ebs_all_encrypted():
    volumes = [
        {"Ebs": {"VolumeId": "vol-1", "DeleteOnTermination": True}},
    ]
    ec2_client = MagicMock()
    ec2_client.describe_volumes.return_value = {
        "Volumes": [{"VolumeId": "vol-1", "Encrypted": True}]
    }
    unencrypted = ec2.check_ebs_encryption(ec2_client, volumes)
    assert unencrypted == []


def test_check_ebs_unencrypted_found():
    volumes = [{"Ebs": {"VolumeId": "vol-1", "DeleteOnTermination": True}}]
    ec2_client = MagicMock()
    ec2_client.describe_volumes.return_value = {
        "Volumes": [{"VolumeId": "vol-1", "Encrypted": False}]
    }
    unencrypted = ec2.check_ebs_encryption(ec2_client, volumes)
    assert "vol-1" in unencrypted


def test_check_ebs_no_volumes():
    ec2_client = MagicMock()
    unencrypted = ec2.check_ebs_encryption(ec2_client, [])
    assert unencrypted == []


# ── calculate_score ───────────────────────────────────────────────────────────

def test_calculate_score_all_clean():
    score, level = ec2.calculate_score(
        no_imds_v2=False, public_ip=False, unencrypted_volumes=[],
        no_instance_profile=False, hop_limit_high=False,
        in_default_vpc=False, public_snapshots=[]
    )
    assert score == 0
    assert level == "LOW"


def test_calculate_score_no_imds_raises():
    score, level = ec2.calculate_score(
        no_imds_v2=True, public_ip=False, unencrypted_volumes=[],
        no_instance_profile=False, hop_limit_high=False,
        in_default_vpc=False, public_snapshots=[]
    )
    assert score >= 3


def test_calculate_score_capped_at_10():
    score, level = ec2.calculate_score(
        no_imds_v2=True, public_ip=True, unencrypted_volumes=["vol-1"],
        no_instance_profile=True, hop_limit_high=True,
        in_default_vpc=True, public_snapshots=["snap-1"]
    )
    assert score <= 10


def test_calculate_score_critical_threshold():
    score, level = ec2.calculate_score(
        no_imds_v2=True, public_ip=True, unencrypted_volumes=["vol-1", "vol-2"],
        no_instance_profile=False, hop_limit_high=True,
        in_default_vpc=False, public_snapshots=["snap-1"]
    )
    assert score >= 8
    assert level == "CRITICAL"


# ── analyse_instance ──────────────────────────────────────────────────────────

RUNNING_INSTANCE = {
    "InstanceId": "i-0abc123",
    "InstanceType": "t3.micro",
    "State": {"Name": "running"},
    "PublicIpAddress": None,
    "PrivateIpAddress": "10.0.0.5",
    "VpcId": "vpc-normal",
    "SubnetId": "subnet-abc",
    "IamInstanceProfile": {"Arn": "arn:aws:iam::123:instance-profile/MyRole"},
    "ImageId": "ami-0abc123",
    "LaunchTime": "2025-01-01T00:00:00+00:00",
    "MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "required", "HttpPutResponseHopLimit": 1},
    "BlockDeviceMappings": [],
    "Tags": [{"Key": "Name", "Value": "web-prod"}],
    "Placement": {"AvailabilityZone": "eu-west-1a"},
    "Architecture": "x86_64",
    "PlatformDetails": "Linux/UNIX",
    "NetworkInterfaces": [],
}


def _make_ec2_client_for_instance(unencrypted_vols=None, public_snaps=None):
    mock = MagicMock()
    mock.describe_volumes.return_value = {
        "Volumes": [
            {"VolumeId": v, "Encrypted": False}
            for v in (unencrypted_vols or [])
        ]
    }
    mock.describe_snapshots.return_value = {
        "Snapshots": public_snaps or []
    }
    return mock


def test_analyse_instance_low_risk():
    ec2_client = _make_ec2_client_for_instance()
    result = ec2.analyse_instance(ec2_client, RUNNING_INSTANCE.copy())
    assert result["risk_level"] == "LOW"
    assert result["imds_v2_required"] is True
    assert result["has_public_ip"] is False
    assert "remediations" in result
    assert isinstance(result["remediations"], list)


def test_analyse_instance_no_imds_v2_flagged():
    instance = RUNNING_INSTANCE.copy()
    instance["MetadataOptions"] = {"HttpEndpoint": "enabled", "HttpTokens": "optional", "HttpPutResponseHopLimit": 1}
    ec2_client = _make_ec2_client_for_instance()
    result = ec2.analyse_instance(ec2_client, instance)
    assert result["imds_v2_required"] is False
    assert any("IMDSv2" in f for f in result["flags"])


def test_analyse_instance_public_ip_flagged():
    instance = RUNNING_INSTANCE.copy()
    instance["PublicIpAddress"] = "1.2.3.4"
    ec2_client = _make_ec2_client_for_instance()
    result = ec2.analyse_instance(ec2_client, instance)
    assert result["has_public_ip"] is True
    assert any("public ip" in f.lower() for f in result["flags"])


def test_analyse_instance_flagged_has_paired_remediations():
    """Every non-✅ flag must have a matching remediation."""
    instance = RUNNING_INSTANCE.copy()
    instance["MetadataOptions"] = {"HttpEndpoint": "enabled", "HttpTokens": "optional", "HttpPutResponseHopLimit": 2}
    instance["PublicIpAddress"] = "1.2.3.4"
    instance["IamInstanceProfile"] = None
    instance["VpcId"] = "vpc-default-000"
    ec2_client = _make_ec2_client_for_instance()
    result = ec2.analyse_instance(ec2_client, instance, default_vpc_id="vpc-default-000")
    warning_flags = [f for f in result["flags"] if not f.startswith("✅")]
    assert len(result["remediations"]) == len(warning_flags)
    assert all(len(r) > 0 for r in result["remediations"])


def test_analyse_instance_default_vpc_flagged():
    instance = RUNNING_INSTANCE.copy()
    ec2_client = _make_ec2_client_for_instance()
    result = ec2.analyse_instance(ec2_client, instance, default_vpc_id="vpc-normal")
    assert result["in_default_vpc"] is True
    assert any("default VPC" in f for f in result["flags"])


# ── Writers ───────────────────────────────────────────────────────────────────

import stat
import csv as csv_module
import json as json_module


SAMPLE_FINDING = {
    "instance_id": "i-0abc123",
    "name": "web-prod",
    "instance_type": "t3.micro",
    "region": "eu-west-1",
    "vpc_id": "vpc-abc",
    "state": "running",
    "launch_time": "2025-01-01T00:00:00+00:00",
    "image_id": "ami-0abc",
    "platform": "Linux/UNIX",
    "has_public_ip": False,
    "public_ip": None,
    "private_ip": "10.0.0.5",
    "imds_v2_required": True,
    "imds_hop_limit": 1,
    "has_instance_profile": True,
    "in_default_vpc": False,
    "unencrypted_volumes": [],
    "public_snapshots": [],
    "severity_score": 0,
    "risk_level": "LOW",
    "flags": ["✅ IMDSv2 enforced", "✅ All EBS volumes encrypted"],
    "remediations": [],
}


def test_write_json_creates_file_with_600_perms(tmp_path):
    report = {"generated_at": "2026-01-01", "findings": [SAMPLE_FINDING]}
    out = str(tmp_path / "test.json")
    ec2.write_json(report, out)
    assert (tmp_path / "test.json").exists()
    mode = (tmp_path / "test.json").stat().st_mode & 0o777
    assert mode == 0o600


def test_write_csv_creates_file_with_600_perms(tmp_path):
    out = str(tmp_path / "test.csv")
    ec2.write_csv([SAMPLE_FINDING], out)
    assert (tmp_path / "test.csv").exists()
    mode = (tmp_path / "test.csv").stat().st_mode & 0o777
    assert mode == 0o600


def test_write_csv_empty_no_file(tmp_path):
    out = str(tmp_path / "empty.csv")
    ec2.write_csv([], out)
    assert not (tmp_path / "empty.csv").exists()


def test_write_csv_includes_remediations_column(tmp_path):
    out = str(tmp_path / "test.csv")
    ec2.write_csv([SAMPLE_FINDING], out)
    with open(out) as f:
        reader = csv_module.DictReader(f)
        assert "remediations" in reader.fieldnames


def test_write_html_creates_file_with_600_perms(tmp_path):
    report = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "account_id": "123456789012",
        "findings": [],
        "summary": {
            "total_instances": 0, "critical": 0, "high": 0,
            "medium": 0, "low": 0, "no_imds_v2": 0,
            "public_instances": 0, "unencrypted_ebs": 0,
        },
    }
    out = str(tmp_path / "test.html")
    ec2.write_html(report, out)
    assert (tmp_path / "test.html").exists()
    mode = (tmp_path / "test.html").stat().st_mode & 0o777
    assert mode == 0o600


# ── UNKNOWN behaviour (ClientError → None sentinel) ───────────────────────────

def test_check_ebs_encryption_client_error_returns_none():
    """ClientError on describe_volumes → None (UNKNOWN), not [] (appears safe)."""
    volumes = [{"Ebs": {"VolumeId": "vol-1", "DeleteOnTermination": True}}]
    ec2_client = MagicMock()
    ec2_client.describe_volumes.side_effect = _client_error("AccessDenied")
    result = ec2.check_ebs_encryption(ec2_client, volumes)
    assert result is None


def test_analyse_instance_ebs_unknown_emits_unknown_flag():
    """When EBS check returns None, analyse_instance must emit an UNKNOWN flag."""
    instance = dict(RUNNING_INSTANCE)
    instance["BlockDeviceMappings"] = [{"Ebs": {"VolumeId": "vol-x", "DeleteOnTermination": True}}]
    ec2_client = MagicMock()
    ec2_client.describe_volumes.side_effect = _client_error("AccessDenied")

    result = ec2.analyse_instance(ec2_client, instance, account_public_snapshots=[])

    unknown_flags = [f for f in result["flags"] if "UNKNOWN" in f]
    assert len(unknown_flags) >= 1
    assert not any("All EBS volumes encrypted" in f for f in result["flags"])


def test_analyse_instance_ebs_unknown_conservative_score():
    """EBS UNKNOWN should increase severity score vs. confirmed-clean EBS."""
    instance = dict(RUNNING_INSTANCE)
    instance["BlockDeviceMappings"] = [{"Ebs": {"VolumeId": "vol-x", "DeleteOnTermination": True}}]
    ec2_client_unknown = MagicMock()
    ec2_client_unknown.describe_volumes.side_effect = _client_error("AccessDenied")

    ec2_client_clean = MagicMock()
    ec2_client_clean.describe_volumes.return_value = {"Volumes": [{"VolumeId": "vol-x", "Encrypted": True}]}

    unknown_result = ec2.analyse_instance(ec2_client_unknown, instance, account_public_snapshots=[])
    clean_result = ec2.analyse_instance(ec2_client_clean, instance, account_public_snapshots=[])

    assert unknown_result["severity_score"] >= clean_result["severity_score"]
