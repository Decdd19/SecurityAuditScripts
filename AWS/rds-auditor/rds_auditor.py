#!/usr/bin/env python3
"""
RDS Instance Auditor
====================
Audits RDS DB instances for common security misconfigurations:
- Public accessibility
- Storage encryption (at rest)
- Automated backup retention (<7 days flagged)
- Deletion protection
- Default parameter group usage
- Auto minor version upgrade
- IAM database authentication
- Multi-AZ deployment
- Public snapshots

Usage:
    python3 rds_auditor.py
    python3 rds_auditor.py --output report --format html
    python3 rds_auditor.py --profile prod --regions eu-west-1
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

BACKUP_MIN_DAYS = 7

AWS_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
    "eu-north-1", "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "ap-northeast-2", "ap-south-1",
    "ca-central-1", "sa-east-1", "af-south-1", "me-south-1",
]

FIELDNAMES = [
    "db_identifier", "db_class", "engine", "engine_version", "status",
    "region", "vpc_id", "endpoint", "port", "publicly_accessible",
    "encrypted", "kms_key", "backup_retention_days", "deletion_protection",
    "iam_auth", "auto_minor_upgrade", "multi_az", "using_default_parameter_group",
    "public_snapshots", "severity_score", "risk_level", "flags", "remediations",
]


# ── Checks ────────────────────────────────────────────────────────────────────

def is_publicly_accessible(db):
    return db.get("PubliclyAccessible", False) is True


def check_encryption(db):
    return db.get("StorageEncrypted", False) is True


def check_backup_retention(db, min_days=BACKUP_MIN_DAYS):
    days = db.get("BackupRetentionPeriod", 0)
    if days is None:
        days = 0
    return days >= min_days, days


def check_deletion_protection(db):
    return db.get("DeletionProtection", False) is True


def check_iam_auth(db):
    return db.get("IAMDatabaseAuthenticationEnabled", False) is True


def check_multi_az(db):
    return db.get("MultiAZ", False) is True


def check_auto_minor_version_upgrade(db):
    return db.get("AutoMinorVersionUpgrade", False) is True


def check_public_snapshots(rds_client, db_identifier):
    """Return list of snapshot IDs that are publicly restorable."""
    public_snaps = []
    try:
        resp = rds_client.describe_db_snapshots(
            DBInstanceIdentifier=db_identifier,
            SnapshotType="manual",
        )
        for snap in resp.get("DBSnapshots", []):
            snap_id = snap["DBSnapshotIdentifier"]
            try:
                attr_resp = rds_client.describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=snap_id
                )
                attrs = attr_resp.get("DBSnapshotAttributesResult", {}).get(
                    "DBSnapshotAttributes", []
                )
                for attr in attrs:
                    if attr.get("AttributeName") == "restore" and "all" in attr.get(
                        "AttributeValues", []
                    ):
                        public_snaps.append(snap_id)
            except ClientError as e:
                log.warning(f"Could not describe snapshot attributes for {snap_id}: {e}")
    except ClientError as e:
        log.warning(f"Could not describe snapshots for {db_identifier}: {e}")
    return public_snaps


# ── Scoring ───────────────────────────────────────────────────────────────────

def calculate_score(publicly_accessible, not_encrypted, backup_insufficient,
                    no_deletion_protection, public_snapshots, no_iam_auth,
                    no_auto_minor_upgrade, no_multi_az):
    score = 0
    if publicly_accessible:
        score += 4
    if not_encrypted:
        score += 3
    if public_snapshots:
        score += 3
    if backup_insufficient:
        score += 2
    if no_deletion_protection:
        score += 1
    if no_iam_auth:
        score += 1
    if no_auto_minor_upgrade:
        score += 1
    if no_multi_az:
        score += 1
    score = min(score, 10)

    if score >= 8:
        risk_level = "CRITICAL"
    elif score >= 5:
        risk_level = "HIGH"
    elif score >= 2:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    return score, risk_level


# ── Analysis ──────────────────────────────────────────────────────────────────

def analyse_instance(rds_client, db, region=""):
    """Analyse a single RDS DB instance dict and return a findings dict."""
    db_id = db["DBInstanceIdentifier"]
    flags = []
    remediations = []

    # Public accessibility
    publicly_accessible = is_publicly_accessible(db)
    if publicly_accessible:
        flags.append("❌ DB instance is publicly accessible")
        remediations.append(
            "Disable public accessibility: RDS Console → DB instance → Modify → "
            "Connectivity → Publicly accessible → No → Apply immediately"
        )

    # Storage encryption
    encrypted = check_encryption(db)
    kms_key = db.get("KmsKeyId")
    if not encrypted:
        flags.append("❌ Storage not encrypted at rest")
        remediations.append(
            "Enable encryption: encryption cannot be added to an existing unencrypted instance. "
            "Take a snapshot, copy it with encryption enabled (choose a KMS CMK), "
            "then restore to a new encrypted instance."
        )

    # Backup retention
    backup_ok, backup_days = check_backup_retention(db)
    if not backup_ok:
        if backup_days == 0:
            flags.append("❌ Automated backups disabled (retention=0)")
            remediations.append(
                "Enable automated backups: RDS Console → DB instance → Modify → "
                "Backup → Backup retention period → 7 days (minimum) → Apply immediately"
            )
        else:
            flags.append(f"⚠️ Backup retention period is only {backup_days} day(s) (recommended: ≥7)")
            remediations.append(
                "Increase backup retention: RDS Console → DB instance → Modify → "
                "Backup → Backup retention period → 7 or more days → Apply immediately"
            )

    # Deletion protection
    deletion_protection = check_deletion_protection(db)
    if not deletion_protection:
        flags.append("⚠️ Deletion protection disabled")
        remediations.append(
            "Enable deletion protection: RDS Console → DB instance → Modify → "
            "Deletion protection → Enable deletion protection → Apply immediately"
        )

    # Default parameter group
    param_groups = db.get("DBParameterGroups", [])
    using_default_pg = any(
        pg["DBParameterGroupName"].startswith("default.")
        for pg in param_groups
    )
    if using_default_pg:
        flags.append("ℹ️ Using default parameter group (no custom hardening)")
        remediations.append(
            "Create a custom parameter group with hardened settings "
            "(e.g., enable audit logging, set require_secure_transport=ON for MySQL): "
            "RDS Console → Parameter groups → Create parameter group"
        )

    # Auto minor version upgrade
    auto_minor = check_auto_minor_version_upgrade(db)
    if not auto_minor:
        flags.append("ℹ️ Auto minor version upgrade disabled")
        remediations.append(
            "Enable auto minor version upgrades: RDS Console → DB instance → Modify → "
            "Maintenance → Enable auto minor version upgrade"
        )

    # IAM database authentication
    iam_auth = check_iam_auth(db)
    if not iam_auth:
        flags.append("ℹ️ IAM database authentication not enabled")
        remediations.append(
            "Enable IAM auth: RDS Console → DB instance → Modify → "
            "Database authentication → Password and IAM database authentication → Apply immediately"
        )

    # Multi-AZ
    multi_az = check_multi_az(db)
    if not multi_az:
        flags.append("ℹ️ Multi-AZ not enabled (single point of failure)")
        remediations.append(
            "Enable Multi-AZ for production workloads: RDS Console → DB instance → "
            "Modify → Availability & durability → Multi-AZ deployment → Apply"
        )

    # Public snapshots
    public_snaps = check_public_snapshots(rds_client, db_id)
    if public_snaps:
        flags.append(f"❌ Public snapshot(s): {', '.join(public_snaps[:3])}")
        remediations.append(
            "Make snapshots private: RDS Console → Snapshots → select snapshot → "
            "Actions → Share snapshot → Remove 'all' from public → Save"
        )

    # NOTE: ✅ flags appended last, no matching remediations.
    # The HTML renderer's fallback (flags_list[len(rems_list):]) depends on this ordering.
    if not publicly_accessible:
        flags.append("✅ Not publicly accessible")
    if encrypted:
        flags.append(f"✅ Storage encrypted{' (KMS)' if kms_key else ''}")
    if backup_ok:
        flags.append(f"✅ Automated backups enabled ({backup_days}d)")
    if deletion_protection:
        flags.append("✅ Deletion protection enabled")
    if multi_az:
        flags.append("✅ Multi-AZ enabled")

    score, risk_level = calculate_score(
        publicly_accessible=publicly_accessible,
        not_encrypted=not encrypted,
        backup_insufficient=not backup_ok,
        no_deletion_protection=not deletion_protection,
        public_snapshots=public_snaps,
        no_iam_auth=not iam_auth,
        no_auto_minor_upgrade=not auto_minor,
        no_multi_az=not multi_az,
    )

    return {
        "db_identifier": db_id,
        "db_class": db.get("DBInstanceClass", ""),
        "engine": db.get("Engine", ""),
        "engine_version": db.get("EngineVersion", ""),
        "status": db.get("DBInstanceStatus", ""),
        "region": region,
        "vpc_id": db.get("DBSubnetGroup", {}).get("VpcId", ""),
        "endpoint": db.get("Endpoint", {}).get("Address", ""),
        "port": db.get("Endpoint", {}).get("Port"),
        "publicly_accessible": publicly_accessible,
        "encrypted": encrypted,
        "kms_key": kms_key,
        "backup_retention_days": backup_days,
        "deletion_protection": deletion_protection,
        "iam_auth": iam_auth,
        "auto_minor_upgrade": auto_minor,
        "multi_az": multi_az,
        "public_snapshots": public_snaps,
        "using_default_parameter_group": using_default_pg,
        "severity_score": score,
        "risk_level": risk_level,
        "flags": flags,
        "remediations": remediations,
    }


# ── Output writers ────────────────────────────────────────────────────────────

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
        for finding in findings:
            row = dict(finding)
            row["flags"] = "; ".join(finding.get("flags", []))
            row["remediations"] = "; ".join(finding.get("remediations", []))
            row["public_snapshots"] = "; ".join(finding.get("public_snapshots", []))
            writer.writerow(row)
    os.chmod(path, 0o600)
    log.info(f"CSV report: {path}")


def write_html(report, path):
    findings = report.get("findings", [])
    summary = report.get("summary", {})
    generated = report.get("generated_at", "")

    rows = ""
    for f in findings:
        risk = f["risk_level"]
        colour = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14",
                  "MEDIUM": "#ffc107", "LOW": "#28a745"}.get(risk, "#6c757d")
        flags_list = f.get("flags", [])
        rems_list = f.get("remediations", [])
        flag_items = []
        for flag, rem in zip(flags_list, rems_list):
            flag_items.append(
                f'<div class="flag-item">'
                f'<span class="flag-text">{html_lib.escape(flag)}</span>'
                f'<span class="rem-text">↳ {html_lib.escape(rem)}</span>'
                f'</div>'
            )
        for flag in flags_list[len(rems_list):]:
            flag_items.append(
                f'<div class="flag-item">'
                f'<span class="flag-text">{html_lib.escape(flag)}</span>'
                f'</div>'
            )
        flags_html = "".join(flag_items)

        backup_cell = f"✅ {f.get('backup_retention_days','?')}d" if f.get("backup_retention_days", 0) >= BACKUP_MIN_DAYS else f"❌ {f.get('backup_retention_days',0)}d"

        rows += (
            f'<tr>'
            f'<td><span style="background:{colour};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em">{risk}</span></td>'
            f'<td>{f["severity_score"]}</td>'
            f'<td><code>{html_lib.escape(f["db_identifier"])}</code></td>'
            f'<td>{html_lib.escape(f.get("engine",""))} {html_lib.escape(f.get("engine_version",""))}</td>'
            f'<td>{html_lib.escape(f.get("db_class",""))}</td>'
            f'<td>{html_lib.escape(f.get("region",""))}</td>'
            f'<td>{"❌ Yes" if f.get("publicly_accessible") else "✅ No"}</td>'
            f'<td>{"✅" if f.get("encrypted") else "❌"}</td>'
            f'<td>{backup_cell}</td>'
            f'<td>{"✅" if f.get("multi_az") else "ℹ️"}</td>'
            f'<td>{flags_html}</td>'
            f'</tr>\n'
        )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>RDS Audit Report</title>
<style>
  body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; margin:0; background:#f5f6fa; color:#333; }}
  .header {{ background: linear-gradient(135deg,#232f3e,#1a73e8); color:#fff; padding:30px 40px; }}
  .header h1 {{ margin:0; font-size:1.8em; }}
  .summary {{ display:flex; flex-wrap:wrap; gap:16px; padding:24px 40px; background:#fff; border-bottom:1px solid #e0e0e0; }}
  .card {{ border-left:4px solid #ccc; padding:12px 20px; min-width:120px; }}
  .card .num {{ font-size:2em; font-weight:700; }}
  .card .label {{ font-size:0.8em; color:#666; text-transform:uppercase; }}
  .card.critical {{ border-left-color:#dc3545; }} .card.critical .num {{ color:#dc3545; }}
  .card.high {{ border-left-color:#fd7e14; }} .card.high .num {{ color:#fd7e14; }}
  .card.medium {{ border-left-color:#ffc107; }} .card.medium .num {{ color:#856404; }}
  .card.low {{ border-left-color:#28a745; }} .card.low .num {{ color:#28a745; }}
  .table-wrap {{ padding:24px 40px; overflow-x:auto; }}
  table {{ width:100%; border-collapse:collapse; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,.06); }}
  th {{ background:#232f3e; color:#fff; padding:10px 14px; text-align:left; font-size:0.85em; }}
  td {{ padding:10px 14px; border-bottom:1px solid #f0f0f0; font-size:0.88em; vertical-align:top; }}
  tr:hover td {{ background:#fafbff; }}
  .footer {{ text-align:center; padding:20px; color:#999; font-size:0.85em; }}
  .flag-item {{ margin-bottom:6px; }}
  .flag-text {{ display:block; font-size:0.85em; }}
  .rem-text {{ display:block; font-size:0.78em; color:#555; padding-left:12px; font-style:italic; }}
</style>
</head>
<body>
<div class="header">
  <h1>🗄️ RDS Database Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; {summary.get('total_instances',0)} instances analysed</p>
</div>
<div class="summary">
  <div class="card total"><div class="num">{summary.get('total_instances',0)}</div><div class="label">Total Instances</div></div>
  <div class="card critical"><div class="num">{summary.get('critical',0)}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{summary.get('high',0)}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{summary.get('medium',0)}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{summary.get('low',0)}</div><div class="label">Low</div></div>
  <div class="card" style="border-left:4px solid #dc3545"><div class="num" style="color:#dc3545">{summary.get('public_instances',0)}</div><div class="label">Public</div></div>
  <div class="card" style="border-left:4px solid #fd7e14"><div class="num" style="color:#fd7e14">{summary.get('unencrypted_instances',0)}</div><div class="label">Unencrypted</div></div>
  <div class="card" style="border-left:4px solid #ffc107"><div class="num" style="color:#ffc107">{summary.get('no_backups',0)}</div><div class="label">No Backups</div></div>
</div>
<div class="table-wrap">
  <table>
    <thead>
      <tr><th>Risk</th><th>Score</th><th>DB Identifier</th><th>Engine</th><th>Class</th><th>Region</th><th>Public</th><th>Encrypted</th><th>Backups</th><th>Multi-AZ</th><th>Flags</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">RDS Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html_content)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(output_prefix="rds_report", fmt="all", profile=None, regions=None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()

    account_id = None
    try:
        sts = session.client("sts", config=BOTO_CONFIG)
        account_id = sts.get_caller_identity()["Account"]
        log.info(f"Account ID: {account_id}")
    except ClientError:
        log.warning("Could not determine account ID")

    target_regions = regions or AWS_REGIONS
    all_findings = []

    for region in target_regions:
        log.info(f"Scanning region: {region}")
        try:
            rds_client = session.client("rds", region_name=region, config=BOTO_CONFIG)
            paginator = rds_client.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    finding = analyse_instance(rds_client, db, region=region)
                    all_findings.append(finding)
        except ClientError as e:
            log.warning(f"Skipping {region}: {e}")

    all_findings.sort(key=lambda x: x["severity_score"], reverse=True)

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        risk_counts[f["risk_level"]] = risk_counts.get(f["risk_level"], 0) + 1

    report = {
        "generated_at": NOW.isoformat(),
        "account_id": account_id,
        "summary": {
            "total_instances": len(all_findings),
            "critical": risk_counts.get("CRITICAL", 0),
            "high": risk_counts.get("HIGH", 0),
            "medium": risk_counts.get("MEDIUM", 0),
            "low": risk_counts.get("LOW", 0),
            "public_instances": sum(1 for f in all_findings if f["publicly_accessible"]),
            "unencrypted_instances": sum(1 for f in all_findings if not f["encrypted"]),
            "no_backups": sum(1 for f in all_findings if f["backup_retention_days"] == 0),
        },
        "findings": all_findings,
    }

    if fmt in ("json", "all"):
        write_json(report, f"{output_prefix}.json")
    if fmt in ("csv", "all"):
        write_csv(all_findings, f"{output_prefix}.csv")
    if fmt in ("html", "all"):
        write_html(report, f"{output_prefix}.html")

    log.info(
        f"Done. {len(all_findings)} DB instances. "
        f"CRITICAL={risk_counts['CRITICAL']} HIGH={risk_counts['HIGH']} "
        f"MEDIUM={risk_counts['MEDIUM']} LOW={risk_counts['LOW']}"
    )


def main():
    parser = argparse.ArgumentParser(description="RDS Database Security Auditor")
    parser.add_argument("--output", default="rds_report", help="Output file prefix")
    parser.add_argument(
        "--format", choices=["json", "csv", "html", "all"], default="all"
    )
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--regions", nargs="+", help="Specific regions to scan")
    args = parser.parse_args()
    run(output_prefix=args.output, fmt=args.format, profile=args.profile,
        regions=args.regions)


if __name__ == "__main__":
    main()
