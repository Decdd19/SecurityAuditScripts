#!/usr/bin/env python3
"""
VPC Flow Logs Auditor
=====================
Audits VPC flow log configuration across all regions:

- VPC has no flow logs enabled at all
- Flow logs enabled but logging only ACCEPT or REJECT (not ALL traffic)
- Flow log destination: S3 vs CloudWatch Logs vs Kinesis (S3 preferred for long-term retention)
- Flow log format: custom vs default (default misses some fields)
- Log retention < 90 days (CloudWatch destination only)

One finding per VPC.  VPCs with no flow logs = CRITICAL.
VPCs with partial coverage (ACCEPT or REJECT only) = HIGH.
VPCs with S3 destination but short retention not detectable at the VPC level
(S3 lifecycle must be checked separately in the S3 auditor).

Usage:
    python3 vpcflowlogs_auditor.py
    python3 vpcflowlogs_auditor.py --output vpc_report --format html
    python3 vpcflowlogs_auditor.py --profile prod --regions eu-west-1
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

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from report_utils import get_styles

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

CW_RETENTION_MIN_DAYS = 90

FIELDNAMES = [
    "vpc_id", "vpc_name", "region", "is_default", "flow_log_count",
    "has_all_traffic_log", "has_accept_only_log", "has_reject_only_log",
    "destinations", "uses_custom_format", "cw_short_retention",
    "risk_level", "severity_score", "flags", "remediations", "cis_control",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_vpc_name(vpc):
    for tag in vpc.get("Tags", []):
        if tag["Key"] == "Name":
            return tag["Value"]
    return ""


def check_cw_retention(logs_client, log_group_name):
    """Return retention days for a CloudWatch log group, or None if unlimited."""
    try:
        resp = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name, limit=1)
        groups = resp.get("logGroups", [])
        if groups and groups[0].get("logGroupName") == log_group_name:
            return groups[0].get("retentionInDays")  # None = unlimited
    except ClientError:
        pass
    return None


def analyse_vpc(ec2, logs_client, vpc, flow_logs):
    """Build one finding dict per VPC."""
    vpc_id = vpc["VpcId"]
    vpc_name = get_vpc_name(vpc)
    is_default = vpc.get("IsDefault", False)

    # Classify flow logs for this VPC
    vpc_logs = [fl for fl in flow_logs if fl.get("ResourceId") == vpc_id]
    active_logs = [fl for fl in vpc_logs if fl.get("FlowLogStatus") == "ACTIVE"]

    traffic_types = {fl.get("TrafficType", "").upper() for fl in active_logs}
    has_all = "ALL" in traffic_types
    has_accept = "ACCEPT" in traffic_types
    has_reject = "REJECT" in traffic_types

    destinations = list({fl.get("LogDestinationType", "cloud-watch-logs") for fl in active_logs})
    uses_custom_format = any(
        fl.get("LogFormat") and fl["LogFormat"] != "${version} ${account-id} ${interface-id} "
        "${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} "
        "${bytes} ${start} ${end} ${action} ${log-status}"
        for fl in active_logs
    )

    # Check CloudWatch log group retention
    cw_short_retention = False
    for fl in active_logs:
        if fl.get("LogDestinationType") in (None, "cloud-watch-logs"):
            log_group = fl.get("LogGroupName", "")
            if log_group:
                ret = check_cw_retention(logs_client, log_group)
                if ret is not None and ret < CW_RETENTION_MIN_DAYS:
                    cw_short_retention = True

    flags, remediations = build_flags_and_remediations(
        vpc_id=vpc_id,
        has_any_logs=len(active_logs) > 0,
        has_all=has_all,
        has_accept=has_accept,
        has_reject=has_reject,
        uses_custom_format=uses_custom_format,
        cw_short_retention=cw_short_retention,
        is_default=is_default,
    )
    score, risk_level = calculate_score(
        has_any_logs=len(active_logs) > 0,
        has_all=has_all,
    )

    return {
        "vpc_id": vpc_id,
        "vpc_name": vpc_name,
        "region": vpc.get("_region", ""),
        "is_default": is_default,
        "flow_log_count": len(active_logs),
        "has_all_traffic_log": has_all,
        "has_accept_only_log": has_accept and not has_all,
        "has_reject_only_log": has_reject and not has_all,
        "destinations": destinations,
        "uses_custom_format": uses_custom_format,
        "cw_short_retention": cw_short_retention,
        "risk_level": risk_level,
        "severity_score": score,
        "flags": flags,
        "remediations": remediations,
        "cis_control": "CIS 8",
    }


def build_flags_and_remediations(vpc_id, has_any_logs, has_all, has_accept,
                                  has_reject, uses_custom_format,
                                  cw_short_retention, is_default):
    flags = []
    remediations = []

    if not has_any_logs:
        flags.append("❌ No flow logs enabled")
        remediations.append(
            f"Enable VPC flow logs: AWS Console → VPC → Your VPCs → select {vpc_id} → "
            "Flow Logs tab → Create flow log → Traffic type: All → Destination: S3 or CloudWatch Logs → Create. "
            "CLI: aws ec2 create-flow-logs --resource-type VPC --resource-ids "
            f"{vpc_id} --traffic-type ALL --log-destination-type s3 --log-destination arn:aws:s3:::your-flow-log-bucket"
        )
        return flags, remediations

    if not has_all:
        if has_accept and not has_reject:
            flags.append("⚠️ Flow logs capture ACCEPT traffic only — REJECT traffic not logged")
            remediations.append(
                f"Add a flow log for REJECT or ALL traffic: VPC Console → {vpc_id} → Flow Logs → "
                "Create flow log → Traffic type: All (replaces ACCEPT-only log)."
            )
        elif has_reject and not has_accept:
            flags.append("⚠️ Flow logs capture REJECT traffic only — ACCEPT traffic not logged")
            remediations.append(
                f"Add a flow log for ALL traffic: VPC Console → {vpc_id} → Flow Logs → "
                "Create flow log → Traffic type: All."
            )
        else:
            flags.append("⚠️ Flow logs active but not capturing ALL traffic types")
            remediations.append(
                f"Create a flow log with Traffic type: All for VPC {vpc_id}."
            )

    if not uses_custom_format:
        flags.append("ℹ️ Using default flow log format — missing useful fields (e.g. vpc-id, subnet-id, pkt-src-aws-service)")
        remediations.append(
            "Use a custom log format that includes additional fields: when creating a flow log, "
            "select 'Custom format' and add fields such as vpc-id, subnet-id, instance-id, "
            "pkt-src-aws-service, pkt-dst-aws-service, flow-direction, traffic-path."
        )

    if cw_short_retention:
        flags.append(f"ℹ️ CloudWatch log group retention is less than {CW_RETENTION_MIN_DAYS} days")
        remediations.append(
            f"Increase CloudWatch log group retention to ≥{CW_RETENTION_MIN_DAYS} days: "
            "CloudWatch Console → Log groups → select the flow log group → Actions → Edit retention setting."
        )

    if has_all:
        flags.append("✅ ALL traffic flow logs active")
        remediations.append("")

    return flags, remediations


def calculate_score(has_any_logs, has_all):
    if not has_any_logs:
        return 8, "CRITICAL"
    if not has_all:
        return 5, "HIGH"
    return 1, "LOW"


def audit_region(session, region):
    """Audit VPC flow log coverage in a single region. Returns list of finding dicts."""
    log.info(f"Auditing region: {region}")
    ec2 = session.client("ec2", region_name=region, config=BOTO_CONFIG)
    logs_client = session.client("logs", region_name=region, config=BOTO_CONFIG)

    try:
        vpcs = ec2.describe_vpcs()["Vpcs"]
    except ClientError as e:
        log.warning(f"  {region}: cannot describe VPCs — {e}")
        return []

    if not vpcs:
        return []

    # Fetch all flow logs for this region in one call
    try:
        flow_logs = []
        paginator = ec2.get_paginator("describe_flow_logs")
        for page in paginator.paginate(
            Filter=[{"Name": "resource-type", "Values": ["VPC"]}]
        ):
            flow_logs.extend(page.get("FlowLogs", []))
    except ClientError as e:
        log.warning(f"  {region}: cannot describe flow logs — {e}")
        flow_logs = []

    findings = []
    for vpc in vpcs:
        vpc["_region"] = region
        finding = analyse_vpc(ec2, logs_client, vpc, flow_logs)
        findings.append(finding)

    return findings


def audit(session, regions=None):
    """Run VPC flow log audit across specified regions. Returns report dict."""
    if regions is None:
        regions = AWS_REGIONS

    all_findings = []
    for region in regions:
        all_findings.extend(audit_region(session, region))

    all_findings.sort(key=lambda f: (-f["severity_score"], f["region"], f["vpc_id"]))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        counts[f["risk_level"]] = counts.get(f["risk_level"], 0) + 1

    no_logs_count = sum(1 for f in all_findings if not f["has_all_traffic_log"] and f["flow_log_count"] == 0)

    return {
        "generated_at": NOW.isoformat(),
        "summary": {
            "total_vpcs": len(all_findings),
            "vpcs_without_flow_logs": no_logs_count,
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
        },
        "findings": all_findings,
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
            row["destinations"] = ", ".join(row.get("destinations", []))
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
        dests = ", ".join(f.get("destinations", [])) or "—"
        vpc_name = html_lib.escape(f.get("vpc_name") or "—")

        rows += f"""
        <tr>
            <td>{html_lib.escape(f['vpc_id'])}</td>
            <td>{vpc_name}</td>
            <td>{html_lib.escape(f['region'])}</td>
            <td>{'✅ Default' if f['is_default'] else ''}</td>
            <td><span style="background:{colour};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{f['risk_level']}</span></td>
            <td>{f['severity_score']}/10</td>
            <td>{f['flow_log_count']}</td>
            <td>{html_lib.escape(dests)}</td>
            <td style="font-size:0.85em">{flags_html}</td>
        </tr>"""

    extra_css = (
        "  .stat { background: white; border-radius: 8px; padding: 15px 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); min-width: 120px; text-align: center; }\n"
        "  .stat .value { font-size: 2em; font-weight: bold; }\n"
        "  .stat .label { font-size: 0.85em; color: #666; margin-top: 4px; }\n"
        "  .section { margin: 0 40px 30px; }\n"
        "  .section h2 { font-size: 1.1em; border-bottom: 2px solid #e0e0e0; padding-bottom: 8px; }\n"
        "  .flag-item { margin-bottom: 4px; }\n"
        "  .flag-text { display: block; font-weight: 500; }\n"
        "  .rem-text { display: block; color: #666; font-size: 0.85em; padding-left: 8px; }\n"
    )
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VPC Flow Logs Audit Report</title>
<style>
{get_styles(extra_css)}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 VPC Flow Logs Audit Report</h1>
  <p>Generated: {html_lib.escape(generated)}</p>
</div>
<div class="summary">
  <div class="stat"><div class="value">{summary['total_vpcs']}</div><div class="label">VPCs Audited</div></div>
  <div class="stat"><div class="value" style="color:#dc3545">{summary['vpcs_without_flow_logs']}</div><div class="label">No Flow Logs</div></div>
  <div class="stat"><div class="value" style="color:#dc3545">{summary['critical']}</div><div class="label">CRITICAL</div></div>
  <div class="stat"><div class="value" style="color:#fd7e14">{summary['high']}</div><div class="label">HIGH</div></div>
  <div class="stat"><div class="value" style="color:#ffc107">{summary['medium']}</div><div class="label">MEDIUM</div></div>
  <div class="stat"><div class="value" style="color:#28a745">{summary['low']}</div><div class="label">LOW</div></div>
</div>
<div class="section">
  <h2>VPC Flow Log Coverage</h2>
  <table>
    <thead>
      <tr>
        <th>VPC ID</th><th>Name</th><th>Region</th><th>Default</th>
        <th>Risk</th><th>Score</th><th>Active Logs</th><th>Destination(s)</th><th>Flags / Actions</th>
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
    parser = argparse.ArgumentParser(description="AWS VPC Flow Logs Auditor")
    parser.add_argument("--output", "-o", default="vpcflowlogs_report",
                        help="Output file prefix (default: vpcflowlogs_report)")
    parser.add_argument("--format", "-f",
                        choices=["json", "csv", "html", "all", "stdout"],
                        default="all")
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
