# 📊 Executive Summary Tool

Aggregates JSON report files from all AWS, Azure, and on-premises auditors into a single HTML executive summary. Computes an overall security score (0–100) with a letter grade, per-pillar risk cards, top findings, and quick wins.

---

## ✨ Features

- Auto-discovers known `*_report.json` files **plus** any unknown `*_report.json` via glob fallback — new auditors appear without manual `KNOWN_PATTERNS` edits
- Supports 30+ auditor report types across AWS, Azure, M365, Linux, Windows, Email, and Network
- Per-pillar risk summary cards (CRITICAL / HIGH / MEDIUM / LOW counts)
- Overall security score (0–100) with letter grade (A–F) and grade hard-caps (see [scoring.py](../scoring.py))
- UNKNOWN pillar handling — SSH auditor run without `sudo` is flagged UNKNOWN rather than false-safe LOW; caps grade at B
- Top 5 critical/high findings sorted by severity, with resource identifier and remediation (configurable via `--top-n`)
- CRITICAL callout section — up to 3 most severe findings highlighted above the findings table
- Quick wins table — low-effort, high-impact actions from ℹ️-prefixed flags on HIGH/CRITICAL findings
- Output written to a single portable HTML file (mode 600, no external deps, print-ready via `@media print`)
- Score calibrated for SMB environments: 13 CRITICAL pillars = score 0

---

## ⚙️ Requirements

- Python 3.7+
- No additional dependencies — stdlib only

---

## 🚀 Usage

```bash
# Run all auditors first, then:
python3 tools/exec_summary.py --input-dir . --output exec_summary.html

# Specify a directory containing report JSON files
python3 tools/exec_summary.py --input-dir /path/to/reports/

# Custom output path
python3 tools/exec_summary.py --input-dir . --output /tmp/my_summary.html
```

---

## 📊 Scoring Algorithm

Deductions are **per pillar** (not per finding) to avoid inflating the penalty for auditors that emit many findings per service:

| Pillar Risk Level | Deduction |
|------------------|-----------|
| CRITICAL pillar | −8 points |
| HIGH pillar | −3 points |
| MEDIUM pillar | −1 point |
| LOW pillar | 0 points |

Starting from 100, score is clamped to [0, 100]. A typical first-time SMB assessment with 5–8 CRITICAL pillars scores 36–60.

| Score | Grade | Interpretation |
|-------|-------|---------------|
| ≥ 85 | A | Strong posture, minor gaps only |
| ≥ 70 | B | Good posture with some issues to address |
| ≥ 55 | C | Notable gaps requiring attention |
| ≥ 40 | D | Significant security debt |
| < 40 | F | Critical issues requiring immediate action |

### Grade hard-caps

- Any CRITICAL pillar present → grade capped at B
- 2+ CRITICAL pillars → grade capped at C
- Firewall pillar CRITICAL (no firewall detected) → grade floored at D
- Any UNKNOWN pillar (SSH without sudo) → grade capped at B

Grade logic lives in [`scoring.py`](../scoring.py) and is unit-tested in [`tests/test_scoring.py`](../tests/test_scoring.py).

---

## 📋 Supported Report Files

The tool auto-discovers any of these filenames in the input directory:

**AWS (15):** `s3_report.json`, `sg_report.json`, `cloudtrail_report.json`, `root_report.json`, `iam_report.json`, `ec2_report.json`, `rds_report.json`, `guardduty_report.json`, `vpcflowlogs_report.json`, `lambda_report.json`, `securityhub_report.json`, `kms_report.json`, `elb_report.json`, `config_report.json`, `backup_report.json`

**Azure (11):** `keyvault_report.json`, `storage_report.json`, `nsg_report.json`, `activitylog_report.json`, `subscription_report.json`, `entra_report.json`, `entrapwd_report.json`, `hybrid_report.json`, `defender_report.json`, `policy_report.json`, `azbackup_report.json`

**M365 (5):** `m365_report.json`, `sharepoint_report.json`, `teams_report.json`, `intune_report.json`, `exchange_report.json`

**On-Premises — Windows (10):** `ad_report.json`, `localuser_report.json`, `winfirewall_report.json`, `smbsigning_report.json`, `auditpolicy_report.json`, `bitlocker_report.json`, `laps_report.json`, `winpatch_report.json`, `mde_report.json`, `netexpose_report.json`

**On-Premises — Linux (5):** `user_report.json`, `fw_report.json`, `sysctl_report.json`, `patch_report.json`, `ssh_report.json`

**Email:** `email_report.json`

**Network:** `ssl_report.json`, `http_headers_report.json`

---

## 🔧 Quick Wins

The quick wins table surfaces ℹ️-prefixed flags from HIGH or CRITICAL findings. These are low-effort configuration changes (e.g. enabling versioning, adding a DLQ, enabling X-Ray) that reduce risk quickly without requiring architectural changes.

---

## `add_auditor.py` — Scaffold a New Auditor

Generates a new auditor stub and wires it into `audit.py` and `exec_summary.py` automatically.

```bash
# Scaffold a new Linux auditor
python3 tools/add_auditor.py --name linux_disk

# Scaffold an AWS auditor with a custom output prefix
python3 tools/add_auditor.py --name aws_config --output-prefix config_report

# Supported categories: linux, aws, azure, windows, network, email
python3 tools/add_auditor.py --name linux_apparmor --category linux
```

Creates: auditor stub + `tests/` directory, inserts `AUDITOR_MAP` entry in `audit.py`, adds `*_report.json` to `KNOWN_PATTERNS` in `exec_summary.py`.

---

## Running Tests

```bash
# All 934 tests from repo root (pytest.ini handles --import-mode=importlib)
python3 -m pytest -q

# exec_summary + scoring + schema only
python3 -m pytest tools/tests/ tests/test_scoring.py tests/test_schema.py tests/test_html_escaping.py -v
```
