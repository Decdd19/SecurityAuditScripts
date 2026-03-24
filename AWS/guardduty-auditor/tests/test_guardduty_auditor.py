"""Tests for guardduty_auditor.py"""
import sys
import os
import json
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import guardduty_auditor as gda


# ── build_flags_and_remediations ──────────────────────────────────────────────

ENABLED_PLANS = {
    "s3_protection": True, "eks_protection": True,
    "malware_protection": True, "rds_protection": True, "runtime_monitoring": True,
}
DISABLED_PLANS = {k: False for k in ENABLED_PLANS}


def test_flags_disabled_detector():
    flags, rems = gda.build_flags_and_remediations(
        enabled=False, high=0, medium=0, low=0,
        plans=DISABLED_PLANS, export_enabled=False
    )
    assert any("not enabled" in f for f in flags)
    assert len(flags) == len(rems)


def test_flags_high_findings():
    flags, rems = gda.build_flags_and_remediations(
        enabled=True, high=3, medium=0, low=0,
        plans=ENABLED_PLANS, export_enabled=True
    )
    assert any("HIGH" in f or "high" in f.lower() for f in flags)
    assert any("GuardDuty Console" in r for r in rems)


def test_flags_missing_s3_protection_uses_info_prefix():
    plans = {**ENABLED_PLANS, "s3_protection": False}
    flags, rems = gda.build_flags_and_remediations(
        enabled=True, high=0, medium=0, low=0,
        plans=plans, export_enabled=True
    )
    assert any(f.startswith("ℹ️") and "S3" in f for f in flags)


def test_flags_missing_malware_protection_uses_info_prefix():
    plans = {**ENABLED_PLANS, "malware_protection": False}
    flags, rems = gda.build_flags_and_remediations(
        enabled=True, high=0, medium=0, low=0,
        plans=plans, export_enabled=True
    )
    assert any(f.startswith("ℹ️") and "Malware" in f for f in flags)


def test_flags_no_export_uses_info_prefix():
    flags, rems = gda.build_flags_and_remediations(
        enabled=True, high=0, medium=0, low=0,
        plans=ENABLED_PLANS, export_enabled=False
    )
    assert any(f.startswith("ℹ️") and "export" in f.lower() for f in flags)


def test_flags_clean_all_good():
    flags, rems = gda.build_flags_and_remediations(
        enabled=True, high=0, medium=0, low=0,
        plans=ENABLED_PLANS, export_enabled=True
    )
    assert any("✅" in f for f in flags)
    assert len(flags) == len(rems)


def test_flags_parallel_lengths_always_equal():
    for high, medium, low in [(0, 0, 0), (3, 2, 1), (1, 0, 0)]:
        flags, rems = gda.build_flags_and_remediations(
            enabled=True, high=high, medium=medium, low=low,
            plans=DISABLED_PLANS, export_enabled=False
        )
        assert len(flags) == len(rems), f"Mismatch at high={high} medium={medium} low={low}"


# ── calculate_score ────────────────────────────────────────────────────────────

def test_score_not_enabled_is_critical():
    score, risk = gda.calculate_score(enabled=False, high=0, medium=0, low=0)
    assert risk == "CRITICAL"
    assert score == 10


def test_score_high_findings():
    score, risk = gda.calculate_score(enabled=True, high=2, medium=0, low=0)
    assert risk == "HIGH"
    assert score >= 6


def test_score_only_medium():
    score, risk = gda.calculate_score(enabled=True, high=0, medium=3, low=0)
    assert risk == "MEDIUM"


def test_score_clean():
    score, risk = gda.calculate_score(enabled=True, high=0, medium=0, low=0)
    assert risk == "LOW"
    assert score == 0


# ── audit_region (mocked) ─────────────────────────────────────────────────────

def _make_session(detector_ids=None, status="ENABLED", features=None):
    session = MagicMock()
    gd = MagicMock()
    session.client.return_value = gd

    ids = ["det-abc123"] if detector_ids is None else detector_ids
    gd.list_detectors.return_value = {"DetectorIds": ids}
    gd.get_detector.return_value = {
        "Status": status,
        "Features": features or [],
    }
    # list_findings returns no findings by default
    paginator = MagicMock()
    paginator.paginate.return_value = [{"FindingIds": []}]
    gd.get_paginator.return_value = paginator
    gd.list_publishing_destinations.return_value = {"Destinations": []}
    return session, gd


def test_audit_region_no_detector_is_critical():
    session, gd = _make_session(detector_ids=[])
    result = gda.audit_region(session, "eu-west-1")
    assert result is not None
    assert result["enabled"] is False
    assert result["risk_level"] == "CRITICAL"
    assert result["region"] == "eu-west-1"


def test_audit_region_enabled_no_findings_is_low():
    session, _ = _make_session()
    result = gda.audit_region(session, "eu-west-1")
    assert result["enabled"] is True
    assert result["risk_level"] == "LOW"
    assert result["high_findings"] == 0


def test_audit_region_finding_dict_has_required_keys():
    session, _ = _make_session()
    result = gda.audit_region(session, "us-east-1")
    for key in ["region", "detector_id", "enabled", "risk_level", "severity_score",
                "flags", "remediations", "high_findings", "medium_findings", "low_findings"]:
        assert key in result, f"Missing key: {key}"


def test_audit_region_flags_rems_same_length():
    session, _ = _make_session()
    result = gda.audit_region(session, "us-east-1")
    assert len(result["flags"]) == len(result["remediations"])


# ── write_json ────────────────────────────────────────────────────────────────

def _sample_report():
    return {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "regions_audited": 1,
        "summary": {
            "total_regions": 1, "disabled_regions": 0, "disabled_region_names": [],
            "critical": 0, "high": 0, "medium": 0, "low": 1,
        },
        "findings": [{
            "region": "eu-west-1", "detector_id": "det-abc123",
            "enabled": True, "status": "ENABLED",
            "high_findings": 0, "medium_findings": 0, "low_findings": 0,
            "s3_protection": True, "eks_protection": False,
            "malware_protection": True, "rds_protection": False, "runtime_monitoring": False,
            "findings_export_enabled": False,
            "risk_level": "LOW", "severity_score": 0,
            "flags": ["✅ No active findings"], "remediations": [""],
        }],
    }


def test_write_json_creates_valid_json(tmp_path):
    path = str(tmp_path / "guardduty_report.json")
    gda.write_json(_sample_report(), path)
    assert os.path.exists(path)
    data = json.loads(open(path).read())
    assert "findings" in data
    assert data["findings"][0]["region"] == "eu-west-1"


def test_write_json_sets_600_permissions(tmp_path):
    path = str(tmp_path / "guardduty_report.json")
    gda.write_json(_sample_report(), path)
    assert oct(os.stat(path).st_mode)[-3:] == "600"


def test_write_html_creates_file(tmp_path):
    path = str(tmp_path / "guardduty_report.html")
    gda.write_html(_sample_report(), path)
    assert os.path.exists(path)
    content = open(path).read()
    assert "GuardDuty" in content
    assert "eu-west-1" in content


def test_write_html_sets_600_permissions(tmp_path):
    path = str(tmp_path / "guardduty_report.html")
    gda.write_html(_sample_report(), path)
    assert oct(os.stat(path).st_mode)[-3:] == "600"


def test_write_csv_creates_file(tmp_path):
    path = str(tmp_path / "guardduty_report.csv")
    gda.write_csv(_sample_report()["findings"], path)
    assert os.path.exists(path)
    content = open(path).read()
    assert "eu-west-1" in content
