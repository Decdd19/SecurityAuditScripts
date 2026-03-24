#!/usr/bin/env python3
"""
Security Hub Auditor
====================
Audits AWS Security Hub enablement and findings across all regions:

- Security Hub enabled / disabled per region (not enabled → CRITICAL)
- Active finding counts by severity (CRITICAL, HIGH, MEDIUM, LOW)
- Enabled compliance standards (CIS, PCI DSS, FSBP) and control pass rates
- Standards with low pass rate (<50%) flagged MEDIUM

One finding per region. Regions with no Security Hub detector are CRITICAL.

Usage:
    python3 securityhub_auditor.py
    python3 securityhub_auditor.py --output sh_report --format html
    python3 securityhub_auditor.py --profile prod --regions eu-west-1 us-east-1
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

FIELDNAMES = [
    "region", "enabled", "critical_findings", "high_findings",
    "medium_findings", "low_findings", "standards_enabled",
    "standards_with_low_pass_rate", "risk_level", "severity_score",
    "flags", "remediations",
]


# ── Checks ────────────────────────────────────────────────────────────────────

def is_hub_enabled(sh):
    """Return True if Security Hub is enabled in this region."""
    try:
        sh.describe_hub()
        return True
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidAccessException", "AccessDeniedException"):
            return False
        raise


def get_finding_counts(sh):
    """Return dict with CRITICAL/HIGH/MEDIUM/LOW active finding counts."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFORMATIONAL": "LOW",
    }
    try:
        paginator = sh.get_paginator("get_findings")
        for page in paginator.paginate(
            Filters={
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"},
                                   {"Value": "NOTIFIED", "Comparison": "EQUALS"}],
            }
        ):
            for finding in page.get("Findings", []):
                sev = finding.get("Severity", {}).get("Label", "LOW")
                bucket = severity_map.get(sev, "LOW")
                counts[bucket] += 1
    except ClientError:
        pass
    return counts


def get_standards_info(sh):
    """Return list of dicts with standard name and pass rate."""
    standards = []
    try:
        resp = sh.get_enabled_standards()
        for sub in resp.get("StandardsSubscriptions", []):
            arn = sub["StandardsSubscriptionArn"]
            name = sub.get("StandardsArn", arn).split("/")[-1]
            passed = failed = 0
            try:
                paginator = sh.get_paginator("describe_standards_controls")
                for page in paginator.paginate(StandardsSubscriptionArn=arn):
                    for ctrl in page.get("Controls", []):
                        status = ctrl.get("ControlStatus", "")
                        if status == "PASSED":
                            passed += 1
                        elif status == "FAILED":
                            failed += 1
            except ClientError:
                pass
            total = passed + failed
            pass_rate = round(passed / total * 100, 1) if total > 0 else None
            standards.append({"name": name, "pass_rate": pass_rate,
                               "passed": passed, "failed": failed})
    except ClientError:
        pass
    return standards


# ── Scoring ───────────────────────────────────────────────────────────────────

def calculate_score(enabled, critical_findings, high_findings,
                    standards_enabled, standards_low_pass_rate):
    """Return (severity_score 0-10, risk_level str)."""
    if not enabled:
        return 9, "CRITICAL"

    score = 0
    if critical_findings > 0:
        score += min(critical_findings, 2) * 2   # +2 per critical, max +4
    if high_findings > 0:
        score += min(high_findings, 2)            # +1 per high, max +2
    if not standards_enabled:
        score += 2
    if standards_low_pass_rate > 0:
        score += min(standards_low_pass_rate, 2)  # +1 per low-pass standard, max +2

    score = min(score, 10)

    if score >= 8:
        risk = "CRITICAL"
    elif score >= 4:
        risk = "HIGH"
    elif score >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    return score, risk


def build_flags_and_remediations(finding):
    """Build parallel flags/remediations lists from finding dict."""
    flags = []
    rems = []

    if not finding["enabled"]:
        flags.append("❌ Security Hub not enabled in this region")
        rems.append(
            "Enable Security Hub: Console → Security Hub → Go to Security Hub → Enable. "
            "Or: aws securityhub enable-security-hub --enable-default-standards"
        )
        return flags, rems

    if finding["critical_findings"] > 0:
        flags.append(f"❌ {finding['critical_findings']} active CRITICAL finding(s)")
        rems.append(
            "Review and remediate CRITICAL findings in Security Hub Console → Findings. "
            "Filter by Severity: CRITICAL and Status: Active."
        )
    if finding["high_findings"] > 0:
        flags.append(f"⚠️ {finding['high_findings']} active HIGH finding(s)")
        rems.append(
            "Review HIGH findings in Security Hub Console → Findings. "
            "Prioritise those with a fix available."
        )
    if not finding["standards_enabled"]:
        flags.append("⚠️ No compliance standards enabled")
        rems.append(
            "Enable at least one standard: Security Hub → Standards → Enable CIS AWS Foundations "
            "or AWS Foundational Security Best Practices."
        )
    for std in finding.get("standards", []):
        if std["pass_rate"] is not None and std["pass_rate"] < 50:
            flags.append(f"ℹ️ {std['name']} pass rate {std['pass_rate']}% (below 50%)")
            rems.append(
                f"Review failed controls for {std['name']} in Security Hub → Standards → "
                "select standard → view controls. Enable auto-remediation where available."
            )

    if not flags:
        flags.append("✅ Security Hub enabled, no critical/high findings")
        rems.append("")

    return flags, rems


# ── Region audit ──────────────────────────────────────────────────────────────

def audit_region(session, region):
    """Audit a single region and return a finding dict."""
    log.info("Auditing region: %s", region)
    sh = session.client("securityhub", region_name=region, config=BOTO_CONFIG)

    enabled = is_hub_enabled(sh)

    if not enabled:
        finding = {
            "region": region,
            "enabled": False,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "standards_enabled": False,
            "standards_with_low_pass_rate": 0,
            "standards": [],
        }
    else:
        counts = get_finding_counts(sh)
        standards = get_standards_info(sh)
        low_pass = sum(
            1 for s in standards
            if s["pass_rate"] is not None and s["pass_rate"] < 50
        )
        finding = {
            "region": region,
            "enabled": True,
            "critical_findings": counts["CRITICAL"],
            "high_findings": counts["HIGH"],
            "medium_findings": counts["MEDIUM"],
            "low_findings": counts["LOW"],
            "standards_enabled": len(standards) > 0,
            "standards_with_low_pass_rate": low_pass,
            "standards": standards,
        }

    score, risk = calculate_score(
        finding["enabled"],
        finding["critical_findings"],
        finding["high_findings"],
        finding["standards_enabled"],
        finding["standards_with_low_pass_rate"],
    )
    finding["severity_score"] = score
    finding["risk_level"] = risk
    finding["flags"], finding["remediations"] = build_flags_and_remediations(finding)
    return finding


def audit(session, regions):
    """Audit Security Hub across given regions. Return report dict."""
    findings = [audit_region(session, r) for r in regions]

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        rl = f["risk_level"].lower()
        if rl in counts:
            counts[rl] += 1

    return {
        "generated_at": NOW.isoformat(),
        "summary": {
            "total_regions": len(findings),
            "not_enabled": sum(1 for f in findings if not f["enabled"]),
            **counts,
        },
        "findings": findings,
    }


# ── Output ────────────────────────────────────────────────────────────────────

def write_json(report, path):
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    os.chmod(path, 0o600)
    log.info("JSON written: %s", path)


def write_csv(findings, path):
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            row = dict(f)
            row["flags"] = " | ".join(f.get("flags", []))
            row["remediations"] = " | ".join(f.get("remediations", []))
            row["standards_enabled"] = str(f.get("standards_enabled", False))
            writer.writerow(row)
    os.chmod(path, 0o600)
    log.info("CSV written: %s", path)


def write_html(report, path):
    findings = report["findings"]
    summary = report["summary"]
    generated_at = report.get("generated_at", "")

    rows = ""
    for f in sorted(findings, key=lambda x: -x["severity_score"]):
        colour = {
            "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107", "LOW": "#28a745",
        }.get(f["risk_level"], "#6c757d")
        enabled_str = "✅ Yes" if f["enabled"] else "❌ No"
        flags_html = "<br>".join(html_lib.escape(fl) for fl in f.get("flags", []))
        rows += f"""
        <tr>
          <td>{html_lib.escape(f['region'])}</td>
          <td>{enabled_str}</td>
          <td>{f['critical_findings']}</td>
          <td>{f['high_findings']}</td>
          <td>{f['medium_findings']}</td>
          <td>{f['low_findings']}</td>
          <td style="color:{colour};font-weight:bold">{html_lib.escape(f['risk_level'])}</td>
          <td>{html_lib.escape(str(f['severity_score']))}</td>
          <td style="font-size:0.85em">{flags_html}</td>
        </tr>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Hub Audit Report</title>
<style>
  body{{font-family:Arial,sans-serif;margin:24px;background:#f8f9fa}}
  h1{{color:#212529}}
  .summary{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}}
  .card{{background:#fff;border-radius:8px;padding:16px 24px;box-shadow:0 1px 4px rgba(0,0,0,.1);min-width:130px}}
  .card .val{{font-size:2em;font-weight:bold}}
  table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.1)}}
  th{{background:#343a40;color:#fff;padding:10px 12px;text-align:left}}
  td{{padding:8px 12px;border-bottom:1px solid #dee2e6;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  .footer{{margin-top:16px;color:#6c757d;font-size:0.85em}}
</style>
</head>
<body>
<h1>🛡️ Security Hub Audit Report</h1>
<div class="summary">
  <div class="card"><div class="val">{summary['total_regions']}</div>Regions</div>
  <div class="card"><div class="val" style="color:#dc3545">{summary['not_enabled']}</div>Not Enabled</div>
  <div class="card"><div class="val" style="color:#dc3545">{summary['critical']}</div>CRITICAL</div>
  <div class="card"><div class="val" style="color:#fd7e14">{summary['high']}</div>HIGH</div>
  <div class="card"><div class="val" style="color:#ffc107">{summary['medium']}</div>MEDIUM</div>
  <div class="card"><div class="val" style="color:#28a745">{summary['low']}</div>LOW</div>
</div>
<table>
<tr>
  <th>Region</th><th>Enabled</th><th>CRIT Findings</th><th>HIGH Findings</th>
  <th>MED Findings</th><th>LOW Findings</th><th>Risk</th><th>Score</th><th>Flags</th>
</tr>
{rows}
</table>
<div class="footer">Generated: {html_lib.escape(generated_at)} | AWS Security Hub Auditor</div>
</body>
</html>"""

    with open(path, "w") as fh:
        fh.write(html_content)
    os.chmod(path, 0o600)
    log.info("HTML written: %s", path)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Audit AWS Security Hub across regions")
    parser.add_argument("--output", default="securityhub_report")
    parser.add_argument(
        "--format", choices=["json", "csv", "html", "all", "stdout"], default="all"
    )
    parser.add_argument("--profile")
    parser.add_argument("--regions", nargs="+")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    regions = args.regions or AWS_REGIONS

    report = audit(session, regions)

    fmt = args.format
    if fmt == "stdout":
        print(json.dumps(report, indent=2, default=str))
        return

    if fmt in ("json", "all"):
        write_json(report, f"{args.output}.json")
    if fmt in ("csv", "all"):
        write_csv(report["findings"], f"{args.output}.csv")
    if fmt in ("html", "all"):
        write_html(report, f"{args.output}.html")


if __name__ == "__main__":
    main()
