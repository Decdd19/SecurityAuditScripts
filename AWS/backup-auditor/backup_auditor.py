#!/usr/bin/env python3
"""
AWS Backup Auditor
==================
Audits AWS Backup configuration across regions for common security misconfigurations:
- Missing backup vaults (no backup strategy in region)
- Vault lock not configured (data can be deleted)
- No recent recovery points / stale backups (>30 days)
- Vault access policy allows public access

Usage:
    python3 backup_auditor.py
    python3 backup_auditor.py --output report --format html
    python3 backup_auditor.py --profile prod
    python3 backup_auditor.py --regions us-east-1 eu-west-1
"""

import boto3
import html as html_lib
import json
import csv
import argparse
import logging
import os
from datetime import datetime, timezone, timedelta
from botocore.config import Config
from botocore.exceptions import ClientError

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from report_utils import get_styles

BOTO_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 10})

# -- Logging -------------------------------------------------------------------
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

STALE_THRESHOLD_DAYS = 30


# -- Helpers -------------------------------------------------------------------

def _is_public_principal(principal):
    """Return True if a policy principal grants public (wildcard) access."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS", "")
        if aws == "*":
            return True
        if isinstance(aws, list) and "*" in aws:
            return True
    return False


def _has_condition(statement):
    """Return True if the statement has a non-empty Condition block."""
    cond = statement.get("Condition")
    return bool(cond) and isinstance(cond, dict) and len(cond) > 0


# -- Checks -------------------------------------------------------------------

def check_vault_lock(backup_client, vault_name):
    """Check if a backup vault has vault lock configured. Returns True if locked."""
    try:
        resp = backup_client.describe_backup_vault(BackupVaultName=vault_name)
        return resp.get("Locked", False)
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            log.warning(f"Access denied describing vault {vault_name}")
        else:
            log.warning(f"Error describing vault {vault_name}: {e}")
        return None


def check_recovery_points(backup_client, vault_name):
    """
    Check recovery points in a vault.
    Returns (has_recent: bool, most_recent_date: datetime|None, count: int).
    """
    try:
        resp = backup_client.list_recovery_points_by_backup_vault(
            BackupVaultName=vault_name
        )
        points = resp.get("RecoveryPoints", [])
        if not points:
            return False, None, 0

        dates = [p["CreationDate"] for p in points if "CreationDate" in p]
        if not dates:
            return False, None, 0

        most_recent = max(dates)
        age = NOW - most_recent
        has_recent = age <= timedelta(days=STALE_THRESHOLD_DAYS)
        return has_recent, most_recent, len(points)

    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            log.warning(f"Access denied listing recovery points for {vault_name}")
        else:
            log.warning(f"Error listing recovery points for {vault_name}: {e}")
        return None, None, 0


def check_vault_policy(backup_client, vault_name):
    """
    Check if vault policy allows public access.
    Returns (is_public: bool, policy_doc: dict|None).
    """
    try:
        resp = backup_client.get_backup_vault_access_policy(
            BackupVaultName=vault_name
        )
        policy_str = resp.get("Policy", "{}")
        doc = json.loads(policy_str)
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", "")
            if _is_public_principal(principal) and not _has_condition(stmt):
                return True, doc
        return False, doc
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            # No policy attached -- not a finding
            return False, None
        if code == "AccessDeniedException":
            log.warning(f"Access denied getting policy for vault {vault_name}")
            return False, None
        log.warning(f"Error getting policy for vault {vault_name}: {e}")
        return False, None


# -- Build findings -----------------------------------------------------------

def _make_finding(region, resource, check, status, severity, severity_score,
                  description, recommendation, cis_control, flags, remediations):
    """Create a standardised finding dict."""
    return {
        "region": region,
        "resource": resource,
        "check": check,
        "status": status,
        "severity": severity,
        "risk_level": severity,
        "severity_score": severity_score,
        "description": description,
        "recommendation": recommendation,
        "cis_control": cis_control,
        "remediation": recommendation,
        "flags": flags,
        "remediations": remediations,
    }


def audit_region(backup_client, region):
    """Audit a single region and return a list of findings."""
    findings = []

    try:
        resp = backup_client.list_backup_vaults()
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            log.warning(f"Access denied listing vaults in {region}")
            return findings
        log.warning(f"Error listing vaults in {region}: {e}")
        return findings

    vaults = resp.get("BackupVaultList", [])

    if not vaults:
        findings.append(_make_finding(
            region=region,
            resource=f"Region:{region}",
            check="no_backup_vaults",
            status="FAIL",
            severity="HIGH",
            severity_score=7,
            description="No AWS Backup vaults configured in region",
            recommendation="Create a backup vault and configure backup plans to protect critical resources.",
            cis_control="CIS 10.1",
            flags=["No backup vaults found in region"],
            remediations=["Create a backup vault: AWS Backup Console -> Backup vaults -> Create backup vault"],
        ))
        return findings

    for vault in vaults:
        vault_name = vault.get("BackupVaultName", "unknown")
        vault_arn = vault.get("BackupVaultArn", "")
        resource_id = vault_arn or vault_name

        # Check 1: Vault lock
        locked = check_vault_lock(backup_client, vault_name)
        if locked is False:
            findings.append(_make_finding(
                region=region,
                resource=resource_id,
                check="vault_lock_not_configured",
                status="FAIL",
                severity="MEDIUM",
                severity_score=5,
                description="Backup vault not locked -- data can be deleted",
                recommendation="Enable vault lock to prevent deletion of recovery points.",
                cis_control="CIS 10.1",
                flags=["Vault lock not enabled"],
                remediations=[
                    "Enable vault lock: AWS Backup Console -> Backup vaults -> "
                    "Select vault -> Manage vault lock -> Enable"
                ],
            ))
        elif locked is True:
            pass  # Good -- vault is locked

        # Check 2: Recovery points / staleness
        has_recent, most_recent_date, point_count = check_recovery_points(
            backup_client, vault_name
        )
        if has_recent is False:
            if point_count == 0:
                desc = "No recovery points in backup vault"
            else:
                age_str = most_recent_date.isoformat() if most_recent_date else "unknown"
                desc = f"No recent backups in vault (last backup >30 days ago, most recent: {age_str})"
            findings.append(_make_finding(
                region=region,
                resource=resource_id,
                check="no_recent_backups",
                status="FAIL",
                severity="HIGH",
                severity_score=7,
                description=desc,
                recommendation="Configure backup plans to ensure regular backups are created.",
                cis_control="CIS 10.1",
                flags=["No recent recovery points (>30 days or none)"],
                remediations=[
                    "Create a backup plan: AWS Backup Console -> Backup plans -> "
                    "Create backup plan -> Assign resources"
                ],
            ))

        # Check 3: Public vault policy
        is_public, _ = check_vault_policy(backup_client, vault_name)
        if is_public:
            findings.append(_make_finding(
                region=region,
                resource=resource_id,
                check="public_vault_policy",
                status="FAIL",
                severity="CRITICAL",
                severity_score=10,
                description="Backup vault policy allows public access",
                recommendation="Remove wildcard principal from vault access policy.",
                cis_control="CIS 10.1",
                flags=["Vault policy allows public/wildcard access"],
                remediations=[
                    "Restrict vault policy: AWS Backup Console -> Backup vaults -> "
                    "Select vault -> Access policy -> Remove statements with Principal: *"
                ],
            ))

    return findings


# -- Output formatters ---------------------------------------------------------

def write_json(report, path):
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    os.chmod(path, 0o600)
    log.info(f"JSON report: {path}")


def write_csv(findings, path):
    if not findings:
        return
    fieldnames = [
        "region", "resource", "check", "status", "severity",
        "risk_level", "severity_score", "description", "recommendation",
        "cis_control", "remediation", "flags", "remediations",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            row = finding.copy()
            for field in ["flags", "remediations"]:
                val = row.get(field, [])
                row[field] = "; ".join(val) if isinstance(val, list) else (val or "")
            writer.writerow(row)
    os.chmod(path, 0o600)
    log.info(f"CSV report: {path}")


def write_html(report, path):
    findings = report["findings"]
    summary = report["summary"]
    generated = report["generated_at"]

    risk_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#28a745",
    }

    rows = ""
    for f in findings:
        color = risk_colors.get(f["severity"], "#999")

        flag_items = []
        flags_list = f.get("flags", [])
        rems_list = f.get("remediations", [])
        for flag, rem in zip(flags_list, rems_list):
            flag_items.append(
                f'<div class="flag-item">'
                f'<span class="flag-text">{html_lib.escape(flag)}</span>'
                f'<span class="rem-text">-> {html_lib.escape(rem)}</span>'
                f'</div>'
            )
        for flag in flags_list[len(rems_list):]:
            flag_items.append(
                f'<div class="flag-item">'
                f'<span class="flag-text">{html_lib.escape(flag)}</span>'
                f'</div>'
            )
        flags_html = "".join(flag_items) or "None"

        resource_escaped = html_lib.escape(f["resource"])
        region_escaped = html_lib.escape(f["region"])
        check_escaped = html_lib.escape(f["check"])
        desc_escaped = html_lib.escape(f["description"])

        rows += f"""
        <tr>
            <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{f['severity']}</span></td>
            <td style="font-weight:bold">{f['severity_score']}/10</td>
            <td style="font-family:monospace;font-size:0.85em">{resource_escaped}</td>
            <td>{region_escaped}</td>
            <td>{check_escaped}</td>
            <td style="font-size:0.85em">{desc_escaped}</td>
            <td style="font-size:0.8em">{flags_html}</td>
        </tr>"""

    extra_css = (
        "  .flag-item { margin-bottom: 6px; }\n"
        "  .flag-text { display: block; font-size: 0.85em; }\n"
        "  .rem-text { display: block; font-size: 0.78em; color: #555; padding-left: 12px; font-style: italic; }\n"
    )
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AWS Backup Audit Report</title>
<style>
{get_styles(extra_css)}
</style>
</head>
<body>
<div class="header">
  <h1>AWS Backup Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; {summary['total_findings']} findings across {summary['regions_scanned']} regions</p>
</div>
<div class="summary">
  <div class="card total"><div class="num">{summary['total_findings']}</div><div class="label">Total Findings</div></div>
  <div class="card critical"><div class="num">{summary['critical']}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{summary['high']}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{summary['medium']}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{summary['low']}</div><div class="label">Low</div></div>
  <div class="card" style="border-left:4px solid #dc3545"><div class="num" style="color:#dc3545">{summary['public_policy']}</div><div class="label">Public Policy</div></div>
  <div class="card" style="border-left:4px solid #fd7e14"><div class="num" style="color:#fd7e14">{summary['no_vaults']}</div><div class="label">No Vaults</div></div>
  <div class="card" style="border-left:4px solid #ffc107"><div class="num" style="color:#ffc107">{summary['stale_backups']}</div><div class="label">Stale Backups</div></div>
</div>
<div class="table-wrap">
  <table>
    <thead>
      <tr><th>Risk</th><th>Score</th><th>Resource</th><th>Region</th><th>Check</th><th>Description</th><th>Flags &amp; Remediation</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">AWS Backup Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html_content)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")


# -- Main ---------------------------------------------------------------------

def run(output_prefix="backup_report", fmt="all", regions=None, profile=None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()

    account_id = None
    try:
        sts = session.client("sts", config=BOTO_CONFIG)
        account_id = sts.get_caller_identity()["Account"]
        log.info(f"Account ID: {account_id}")
    except ClientError:
        log.warning("Could not determine account ID")

    target_regions = regions if regions else AWS_REGIONS
    findings = []

    for region in target_regions:
        log.info(f"Scanning region: {region}")
        try:
            backup_client = session.client(
                "backup", region_name=region, config=BOTO_CONFIG
            )
            region_findings = audit_region(backup_client, region)
            findings.extend(region_findings)
        except ClientError as e:
            log.warning(f"Could not scan region {region}: {e}")
            continue

    findings.sort(key=lambda x: x["severity_score"], reverse=True)

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        risk_counts[f["severity"]] = risk_counts.get(f["severity"], 0) + 1

    report = {
        "generated_at": NOW.isoformat(),
        "account_id": account_id,
        "summary": {
            "total_findings": len(findings),
            "regions_scanned": len(target_regions),
            "critical": risk_counts.get("CRITICAL", 0),
            "high": risk_counts.get("HIGH", 0),
            "medium": risk_counts.get("MEDIUM", 0),
            "low": risk_counts.get("LOW", 0),
            "no_vaults": sum(1 for f in findings if f["check"] == "no_backup_vaults"),
            "stale_backups": sum(1 for f in findings if f["check"] == "no_recent_backups"),
            "public_policy": sum(1 for f in findings if f["check"] == "public_vault_policy"),
            "vault_lock_missing": sum(1 for f in findings if f["check"] == "vault_lock_not_configured"),
        },
        "findings": findings,
    }

    if fmt in ("json", "all"):
        write_json(report, f"{output_prefix}.json")
    if fmt in ("csv", "all"):
        write_csv(findings, f"{output_prefix}.csv")
    if fmt in ("html", "all"):
        write_html(report, f"{output_prefix}.html")
    if fmt == "stdout":
        print(json.dumps(report, indent=2, default=str))

    s = report["summary"]
    print(f"""
+==========================================+
|       AWS BACKUP AUDITOR -- SUMMARY      |
+==========================================+
|  Regions scanned:         {s['regions_scanned']:<15}|
|  Total findings:          {s['total_findings']:<15}|
|  CRITICAL:                {s['critical']:<15}|
|  HIGH:                    {s['high']:<15}|
|  MEDIUM:                  {s['medium']:<15}|
|  LOW:                     {s['low']:<15}|
|  No vaults:               {s['no_vaults']:<15}|
|  Stale backups:           {s['stale_backups']:<15}|
|  Public policy:           {s['public_policy']:<15}|
|  Vault lock missing:      {s['vault_lock_missing']:<15}|
+==========================================+
""")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWS Backup Auditor")
    parser.add_argument("--output", "-o", default="backup_report",
                        help="Output file prefix (default: backup_report)")
    parser.add_argument("--format", "-f",
                        choices=["json", "csv", "html", "all", "stdout"],
                        default="all", help="Output format (default: all)")
    parser.add_argument("--profile", default=None,
                        help="AWS CLI profile name to use")
    parser.add_argument("--regions", nargs="+", default=None,
                        help="AWS regions to scan (default: all supported regions)")
    args = parser.parse_args()
    run(output_prefix=args.output, fmt=args.format,
        profile=args.profile, regions=args.regions)
