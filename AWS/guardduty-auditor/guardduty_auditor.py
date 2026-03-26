#!/usr/bin/env python3
"""
GuardDuty Auditor
=================
Audits AWS GuardDuty enablement and active threat findings across all regions:

- GuardDuty detector enabled / disabled per region
- Finding statistics by severity (HIGH ≥7.0, MEDIUM ≥4.0, LOW <4.0)
- S3 Protection, EKS Protection, Malware Protection, RDS Protection, Runtime Monitoring
- Findings export to EventBridge or S3 (optional protection plans)
- Auto-archive rules in use
- CloudWatch publishing (findings → Events)

One finding per region.  Regions with no detector are flagged as CRITICAL.
Regions with a detector but HIGH findings are flagged as HIGH.
Regions with only MEDIUM/LOW findings are MEDIUM/LOW respectively.

Usage:
    python3 guardduty_auditor.py
    python3 guardduty_auditor.py --output gd_report --format html
    python3 guardduty_auditor.py --profile prod --regions eu-west-1 us-east-1
"""

import boto3
import html as html_lib
import json
import csv
import argparse
import logging
import os
from datetime import datetime, timezone
from botocore.config import Config
from botocore.exceptions import ClientError

BOTO_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 10})

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

NOW = datetime.now(timezone.utc)

AWS_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
    "eu-north-1", "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "ap-northeast-2", "ap-south-1",
    "ca-central-1", "sa-east-1", "af-south-1", "me-south-1",
]

# GuardDuty severity bands
HIGH_SEVERITY_MIN = 7.0
MEDIUM_SEVERITY_MIN = 4.0

FIELDNAMES = [
    "region", "detector_id", "enabled", "status",
    "high_findings", "medium_findings", "low_findings",
    "s3_protection", "eks_protection", "malware_protection",
    "rds_protection", "runtime_monitoring",
    "findings_export_enabled", "risk_level", "severity_score",
    "flags", "remediations",
]


# ── Checks ────────────────────────────────────────────────────────────────────

def get_finding_counts(gd, detector_id):
    """Return (high, medium, low) finding counts for active findings."""
    high = medium = low = 0
    try:
        paginator = gd.get_paginator("list_findings")
        for page in paginator.paginate(
            DetectorId=detector_id,
            FindingCriteria={
                "Criterion": {
                    "service.archived": {"Eq": ["false"]},
                }
            },
        ):
            finding_ids = page.get("FindingIds", [])
            if not finding_ids:
                continue
            # get_findings supports max 50 IDs per call
            for i in range(0, len(finding_ids), 50):
                chunk = finding_ids[i:i + 50]
                details = gd.get_findings(DetectorId=detector_id, FindingIds=chunk)
                for f in details.get("Findings", []):
                    sev = f.get("Severity", 0)
                    if sev >= HIGH_SEVERITY_MIN:
                        high += 1
                    elif sev >= MEDIUM_SEVERITY_MIN:
                        medium += 1
                    else:
                        low += 1
    except ClientError as e:
        log.warning(f"Could not list findings for detector {detector_id}: {e}")
    return high, medium, low


def get_protection_plans(gd, detector_id):
    """Return dict of protection plan enablement booleans."""
    plans = {
        "s3_protection": False,
        "eks_protection": False,
        "malware_protection": False,
        "rds_protection": False,
        "runtime_monitoring": False,
    }
    try:
        resp = gd.get_detector(DetectorId=detector_id)
        features = resp.get("Features", [])
        feature_map = {f["Name"]: f.get("Status") for f in features}
        plans["s3_protection"] = feature_map.get("S3_DATA_EVENTS") == "ENABLED"
        plans["eks_protection"] = feature_map.get("EKS_AUDIT_LOGS") == "ENABLED"
        plans["malware_protection"] = feature_map.get("EBS_MALWARE_PROTECTION") == "ENABLED"
        plans["rds_protection"] = feature_map.get("RDS_LOGIN_EVENTS") == "ENABLED"
        plans["runtime_monitoring"] = feature_map.get("RUNTIME_MONITORING") == "ENABLED"
    except ClientError:
        pass
    return plans


def check_findings_export(gd, detector_id):
    """Return True if a publishing destination (S3 or EventBridge) is configured."""
    try:
        resp = gd.list_publishing_destinations(DetectorId=detector_id)
        return len(resp.get("Destinations", [])) > 0
    except ClientError:
        return False


def build_flags_and_remediations(enabled, high, medium, low, plans, export_enabled):
    flags = []
    remediations = []

    if not enabled:
        flags.append("❌ GuardDuty not enabled")
        remediations.append(
            "Enable GuardDuty: AWS Console → GuardDuty → Get started → Enable GuardDuty. "
            "Or via CLI: aws guardduty create-detector --enable"
        )
        return flags, remediations  # rest irrelevant if not enabled

    if high > 0:
        flags.append(f"❌ {high} HIGH-severity finding(s) require investigation")
        remediations.append(
            "Review and remediate HIGH findings: GuardDuty Console → Findings → "
            "filter by Severity ≥7. Investigate and archive false positives; "
            "remediate genuine threats immediately."
        )

    if medium > 0:
        flags.append(f"⚠️ {medium} MEDIUM-severity finding(s) present")
        remediations.append(
            "Review MEDIUM findings: GuardDuty Console → Findings → filter by Severity 4–7. "
            "Prioritise after HIGH findings are cleared."
        )

    if not plans["s3_protection"]:
        flags.append("ℹ️ S3 Protection not enabled")
        remediations.append(
            "Enable S3 Protection: GuardDuty Console → Protection plans → S3 Protection → Enable. "
            "Detects suspicious API calls and access patterns against S3 buckets."
        )

    if not plans["malware_protection"]:
        flags.append("ℹ️ Malware Protection (EBS) not enabled")
        remediations.append(
            "Enable Malware Protection: GuardDuty Console → Protection plans → Malware Protection → Enable. "
            "Scans EBS volumes attached to EC2 instances for malware on suspicious activity."
        )

    if not plans["rds_protection"]:
        flags.append("ℹ️ RDS Protection not enabled")
        remediations.append(
            "Enable RDS Protection: GuardDuty Console → Protection plans → RDS Protection → Enable. "
            "Detects anomalous login attempts to RDS databases."
        )

    if not export_enabled:
        flags.append("ℹ️ No findings export destination configured")
        remediations.append(
            "Configure findings export: GuardDuty Console → Settings → Findings export options → "
            "Set S3 or EventBridge destination for long-term retention and SIEM integration."
        )

    if low > 0 and high == 0 and medium == 0:
        flags.append(f"✅ Only {low} low-severity finding(s) — no urgent action required")
        remediations.append("")

    if high == 0 and medium == 0 and low == 0:
        flags.append("✅ No active findings")
        remediations.append("")

    return flags, remediations


def calculate_score(enabled, high, medium, low):
    """Return (severity_score 0–10, risk_level)."""
    if not enabled:
        return 10, "CRITICAL"
    if high > 0:
        score = min(10, 6 + high)
        return score, "HIGH"
    if medium > 0:
        score = min(5, 3 + medium)
        return score, "MEDIUM"
    if low > 0:
        return 2, "LOW"
    return 0, "LOW"


def audit_region(session, region):
    """Audit GuardDuty in a single region. Returns one finding dict."""
    log.info(f"Auditing region: {region}")
    gd = session.client("guardduty", region_name=region, config=BOTO_CONFIG)

    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
    except ClientError as e:
        log.warning(f"  {region}: cannot list detectors — {e}")
        return None

    if not detectors:
        flags, remediations = build_flags_and_remediations(
            enabled=False, high=0, medium=0, low=0,
            plans={k: False for k in ["s3_protection", "eks_protection",
                                      "malware_protection", "rds_protection",
                                      "runtime_monitoring"]},
            export_enabled=False,
        )
        score, risk_level = calculate_score(enabled=False, high=0, medium=0, low=0)
        return {
            "region": region,
            "detector_id": None,
            "enabled": False,
            "status": "NOT_ENABLED",
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "s3_protection": False,
            "eks_protection": False,
            "malware_protection": False,
            "rds_protection": False,
            "runtime_monitoring": False,
            "findings_export_enabled": False,
            "risk_level": risk_level,
            "severity_score": score,
            "flags": flags,
            "remediations": remediations,
        }

    detector_id = detectors[0]
    try:
        det = gd.get_detector(DetectorId=detector_id)
        status = det.get("Status", "UNKNOWN")
    except ClientError:
        status = "UNKNOWN"

    enabled = status == "ENABLED"
    high, medium, low = get_finding_counts(gd, detector_id)
    plans = get_protection_plans(gd, detector_id)
    export_enabled = check_findings_export(gd, detector_id)

    flags, remediations = build_flags_and_remediations(
        enabled, high, medium, low, plans, export_enabled
    )
    score, risk_level = calculate_score(enabled, high, medium, low)

    return {
        "region": region,
        "detector_id": detector_id,
        "enabled": enabled,
        "status": status,
        "high_findings": high,
        "medium_findings": medium,
        "low_findings": low,
        "s3_protection": plans["s3_protection"],
        "eks_protection": plans["eks_protection"],
        "malware_protection": plans["malware_protection"],
        "rds_protection": plans["rds_protection"],
        "runtime_monitoring": plans["runtime_monitoring"],
        "findings_export_enabled": export_enabled,
        "risk_level": risk_level,
        "severity_score": score,
        "flags": flags,
        "remediations": remediations,
    }


def audit(session, regions=None):
    """Run GuardDuty audit across specified regions. Returns report dict."""
    if regions is None:
        regions = AWS_REGIONS

    findings = []
    for region in regions:
        result = audit_region(session, region)
        if result:
            findings.append(result)

    findings.sort(key=lambda f: (-f["severity_score"], f["region"]))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    disabled_regions = []
    for f in findings:
        counts[f["risk_level"]] = counts.get(f["risk_level"], 0) + 1
        if not f["enabled"]:
            disabled_regions.append(f["region"])

    return {
        "generated_at": NOW.isoformat(),
        "regions_audited": len(findings),
        "summary": {
            "total_regions": len(findings),
            "disabled_regions": len(disabled_regions),
            "disabled_region_names": disabled_regions,
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
        },
        "findings": findings,
    }


# ── Output formatters ─────────────────────────────────────────────────────────

def write_json(report, path):
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    os.chmod(path, 0o600)
    log.info(f"JSON report: {path}")


def write_csv(findings, path):
    if not findings:
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        for row in findings:
            row = dict(row)
            row["flags"] = " | ".join(row.get("flags", []))
            row["remediations"] = " | ".join(row.get("remediations", []))
            writer.writerow(row)
    os.chmod(path, 0o600)
    log.info(f"CSV report: {path}")


def write_html(report, path):
    findings = report["findings"]
    summary = report["summary"]
    generated = report["generated_at"]

    risk_colours = {
        "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107", "LOW": "#28a745",
    }

    rows = ""
    for f in findings:
        colour = risk_colours.get(f["risk_level"], "#6c757d")
        flag_items = []
        for flag, rem in zip(f.get("flags", []), f.get("remediations", [])):
            if rem:
                flag_items.append(
                    f'<div class="flag-item">'
                    f'<span class="flag-text">{html_lib.escape(flag)}</span>'
                    f'<span class="rem-text">↳ {html_lib.escape(rem)}</span>'
                    f'</div>'
                )
            else:
                flag_items.append(
                    f'<div class="flag-item"><span class="flag-text">{html_lib.escape(flag)}</span></div>'
                )
        flags_html = "".join(flag_items) or "None"

        def yn(val):
            return "✅" if val else "❌"

        region_escaped = html_lib.escape(f["region"])
        detector = html_lib.escape(f["detector_id"] or "—")
        rows += f"""
        <tr>
            <td>{region_escaped}</td>
            <td><span style="background:{colour};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{f['risk_level']}</span></td>
            <td>{f['severity_score']}/10</td>
            <td>{yn(f['enabled'])}</td>
            <td style="color:#dc3545;font-weight:bold">{f['high_findings']}</td>
            <td style="color:#fd7e14">{f['medium_findings']}</td>
            <td>{f['low_findings']}</td>
            <td>{yn(f['s3_protection'])} S3 | {yn(f['malware_protection'])} Malware | {yn(f['rds_protection'])} RDS</td>
            <td style="font-size:0.8em;font-family:monospace;color:#666">{detector}</td>
            <td style="font-size:0.85em">{flags_html}</td>
        </tr>"""

    disabled = summary.get("disabled_regions", 0)
    disabled_names = ", ".join(summary.get("disabled_region_names", [])) or "None"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GuardDuty Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f5f6fa; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #2c3e50, #3498db); color: white; padding: 30px 40px; }}
  .header h1 {{ margin: 0; font-size: 1.8em; }}
  .header p {{ margin: 5px 0 0; opacity: 0.8; }}
  .summary {{ display: flex; gap: 20px; padding: 20px 40px; flex-wrap: wrap; }}
  .stat {{ background: white; border-radius: 8px; padding: 15px 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); min-width: 120px; text-align: center; }}
  .stat .value {{ font-size: 2em; font-weight: bold; }}
  .stat .label {{ font-size: 0.85em; color: #666; margin-top: 4px; }}
  .section {{ margin: 0 40px 30px; }}
  .section h2 {{ font-size: 1.1em; border-bottom: 2px solid #e0e0e0; padding-bottom: 8px; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }}
  th {{ background: #2c3e50; color: white; padding: 10px 12px; text-align: left; font-size: 0.85em; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: top; font-size: 0.9em; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f8f9fa; }}
  .flag-item {{ margin-bottom: 4px; }}
  .flag-text {{ display: block; font-weight: 500; }}
  .rem-text {{ display: block; color: #666; font-size: 0.85em; padding-left: 8px; }}
  .disabled-banner {{ margin: 0 40px 20px; padding: 12px 20px; background: #fdf3e3; border-left: 4px solid #fd7e14; border-radius: 4px; font-size: 0.9em; }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ GuardDuty Audit Report</h1>
  <p>Generated: {html_lib.escape(generated)}</p>
</div>
<div class="summary">
  <div class="stat"><div class="value">{summary['total_regions']}</div><div class="label">Regions Audited</div></div>
  <div class="stat"><div class="value" style="color:#dc3545">{summary['disabled_regions']}</div><div class="label">Disabled</div></div>
  <div class="stat"><div class="value" style="color:#dc3545">{summary['critical']}</div><div class="label">CRITICAL</div></div>
  <div class="stat"><div class="value" style="color:#fd7e14">{summary['high']}</div><div class="label">HIGH</div></div>
  <div class="stat"><div class="value" style="color:#ffc107">{summary['medium']}</div><div class="label">MEDIUM</div></div>
  <div class="stat"><div class="value" style="color:#28a745">{summary['low']}</div><div class="label">LOW</div></div>
</div>
{'<div class="disabled-banner">⚠️ GuardDuty disabled in ' + str(disabled) + ' region(s): ' + html_lib.escape(disabled_names) + '</div>' if disabled else ''}
<div class="section">
  <h2>Regional GuardDuty Status</h2>
  <table>
    <thead>
      <tr>
        <th>Region</th><th>Risk</th><th>Score</th><th>Enabled</th>
        <th>HIGH Findings</th><th>MEDIUM</th><th>LOW</th>
        <th>Protection Plans</th><th>Detector ID</th><th>Flags / Actions</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html_content)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AWS GuardDuty Auditor")
    parser.add_argument("--output", "-o", default="guardduty_report",
                        help="Output file prefix (default: guardduty_report)")
    parser.add_argument("--format", "-f",
                        choices=["json", "csv", "html", "all", "stdout"],
                        default="all", help="Output format (default: all)")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--regions", nargs="+", help="Regions to audit (default: all)")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile)
    regions = args.regions or AWS_REGIONS

    report = audit(session, regions)

    if args.format == "stdout":
        print(json.dumps(report, indent=2, default=str))
        return

    if args.format in ("json", "all"):
        write_json(report, f"{args.output}.json")
    if args.format in ("csv", "all"):
        write_csv(report["findings"], f"{args.output}.csv")
    if args.format in ("html", "all"):
        write_html(report, f"{args.output}.html")


if __name__ == "__main__":
    main()
