"""Tests for exec_summary.py"""
import sys
import os
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import exec_summary as es


# ── load_report ────────────────────────────────────────────────────────────────

def test_load_report_reads_valid_json(tmp_path):
    data = {"generated_at": "2026-01-01", "findings": [], "summary": {"total_buckets": 0}}
    p = tmp_path / "s3_report.json"
    p.write_text(json.dumps(data))
    result = es.load_report(str(p))
    assert result["generated_at"] == "2026-01-01"


def test_load_report_returns_none_on_missing_file():
    result = es.load_report("/nonexistent/path.json")
    assert result is None


def test_load_report_returns_none_on_invalid_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("not json {{{")
    result = es.load_report(str(p))
    assert result is None


# ── discover_reports ───────────────────────────────────────────────────────────

REPORT_PATTERNS = [
    "s3_report.json",
    "sg_report.json",
    "cloudtrail_report.json",
    "root_report.json",
    "iam_report.json",
    "ec2_report.json",
    "rds_report.json",
]


def test_discover_reports_finds_known_patterns(tmp_path):
    for fname in REPORT_PATTERNS[:3]:
        (tmp_path / fname).write_text('{"findings": [], "summary": {}}')
    (tmp_path / "unrelated.json").write_text('{}')
    found = es.discover_reports(str(tmp_path))
    assert len(found) == 3
    names = [os.path.basename(p) for p in found]
    assert "s3_report.json" in names
    assert "unrelated.json" not in names


def test_discover_reports_empty_dir(tmp_path):
    found = es.discover_reports(str(tmp_path))
    assert found == []


# ── compute_pillar_stats ───────────────────────────────────────────────────────

MOCK_REPORT = {
    "generated_at": "2026-01-01",
    "findings": [
        {"risk_level": "CRITICAL", "severity_score": 9, "flags": ["❌ bad"], "remediations": ["fix it"]},
        {"risk_level": "HIGH", "severity_score": 6, "flags": ["⚠️ warn"], "remediations": ["fix this"]},
        {"risk_level": "LOW", "severity_score": 1, "flags": ["✅ good"], "remediations": []},
    ],
    "summary": {"total_buckets": 3, "critical": 1, "high": 1, "medium": 0, "low": 1},
}


def test_compute_pillar_stats_returns_counts():
    stats = es.compute_pillar_stats("s3", MOCK_REPORT)
    assert stats["pillar"] == "s3"
    assert stats["critical"] == 1
    assert stats["high"] == 1
    assert stats["total"] == 3


def test_compute_pillar_stats_overall_risk():
    stats = es.compute_pillar_stats("s3", MOCK_REPORT)
    # Has a CRITICAL finding → pillar risk = CRITICAL
    assert stats["pillar_risk"] == "CRITICAL"


def test_compute_pillar_stats_all_low():
    report = {
        "findings": [{"risk_level": "LOW", "severity_score": 0}],
        "summary": {},
    }
    stats = es.compute_pillar_stats("cloudtrail", report)
    assert stats["pillar_risk"] == "LOW"


# ── compute_overall_score ──────────────────────────────────────────────────────

def test_compute_overall_score_no_findings():
    score, grade = es.compute_overall_score([])
    assert score == 100
    assert grade == "A"


def test_compute_overall_score_all_critical():
    pillar_stats = [
        {"critical": 3, "high": 0, "medium": 0, "low": 0, "total": 3, "pillar_risk": "CRITICAL"},
    ]
    score, grade = es.compute_overall_score(pillar_stats)
    assert score < 50
    assert grade in ("D", "F")


def test_compute_overall_score_mixed():
    pillar_stats = [
        {"critical": 1, "high": 2, "medium": 3, "low": 10, "total": 16, "pillar_risk": "CRITICAL"},
        {"critical": 0, "high": 0, "medium": 1, "low": 5, "total": 6, "pillar_risk": "MEDIUM"},
    ]
    score, grade = es.compute_overall_score(pillar_stats)
    assert 0 <= score <= 100


def test_compute_overall_score_grade_a():
    pillar_stats = [
        {"critical": 0, "high": 0, "medium": 0, "low": 2, "total": 2, "pillar_risk": "LOW"},
    ]
    score, grade = es.compute_overall_score(pillar_stats)
    assert grade == "A"
    assert score >= 85


# ── get_top_findings ───────────────────────────────────────────────────────────

def test_get_top_findings_returns_critical_first():
    all_findings = [
        {"risk_level": "LOW", "severity_score": 1, "pillar": "s3"},
        {"risk_level": "CRITICAL", "severity_score": 9, "pillar": "sg"},
        {"risk_level": "HIGH", "severity_score": 6, "pillar": "cloudtrail"},
    ]
    top = es.get_top_findings(all_findings, n=2)
    assert len(top) == 2
    assert top[0]["risk_level"] == "CRITICAL"
    assert top[1]["risk_level"] == "HIGH"


def test_get_top_findings_respects_n():
    findings = [{"risk_level": "HIGH", "severity_score": i, "pillar": "x"} for i in range(10)]
    top = es.get_top_findings(findings, n=3)
    assert len(top) == 3


# ── get_quick_wins ─────────────────────────────────────────────────────────────

def test_get_quick_wins_returns_informational_on_high():
    """ℹ️ flags on HIGH/CRITICAL findings are quick wins (low-effort, high-impact)."""
    findings = [
        {
            "risk_level": "HIGH",
            "severity_score": 6,
            "pillar": "s3",
            "flags": ["❌ no encryption", "ℹ️ versioning disabled"],
            "remediations": ["encrypt it", "enable versioning"],
        },
        {
            "risk_level": "LOW",
            "severity_score": 1,
            "pillar": "sg",
            "flags": ["ℹ️ unused group"],
            "remediations": ["delete it"],
        },
    ]
    wins = es.get_quick_wins(findings, max_wins=5)
    # Only ℹ️ flags on HIGH findings should be returned
    assert len(wins) >= 1
    assert all(w["risk_level"] in ("HIGH", "CRITICAL") for w in wins)
