"""
CloudTrail Auditor
==================
Audits AWS CloudTrail configuration across all regions for:
- Trails enabled and logging
- Multi-region coverage
- Log file validation
- CloudWatch Logs integration
- S3 bucket security for trail logs
- Log encryption (KMS)
- Management vs data event coverage

Usage:
    python3 cloudtrail_auditor.py
    python3 cloudtrail_auditor.py --output report --format all
    python3 cloudtrail_auditor.py --format csv
    python3 cloudtrail_auditor.py --profile prod
"""

import boto3
import json
import csv
import argparse
import logging
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

NOW = datetime.now(timezone.utc)

ALL_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
    "eu-north-1", "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "ap-northeast-2", "ap-south-1",
    "ca-central-1", "sa-east-1", "af-south-1", "me-south-1",
]


# ── Scoring ───────────────────────────────────────────────────────────────────

def calculate_score(not_logging, no_validation, no_cloudwatch, no_kms,
                    not_multi_region, no_global_events, s3_public):
    score = 0
    if not_logging:
        score += 5
    if s3_public:
        score += 3
    if no_kms:
        score += 2
    if no_cloudwatch:
        score += 2
    if no_validation:
        score += 1
    if not_multi_region:
        score += 1
    if no_global_events:
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


# ── Trail checks ──────────────────────────────────────────────────────────────

def check_trail_logging(ct, trail_arn):
    try:
        status = ct.get_trail_status(Name=trail_arn)
        return status.get("IsLogging", False), status.get("LatestDeliveryTime"), status.get("LatestDeliveryError")
    except ClientError:
        return False, None, None


def check_event_selectors(ct, trail_arn):
    try:
        resp = ct.get_event_selectors(TrailName=trail_arn)
        selectors = resp.get("EventSelectors", [])
        has_management = any(
            s.get("IncludeManagementEvents", False) for s in selectors
        )
        has_data = any(
            len(s.get("DataResources", [])) > 0 for s in selectors
        )
        read_write = selectors[0].get("ReadWriteType", "Unknown") if selectors else "Unknown"
        return has_management, has_data, read_write
    except ClientError:
        return False, False, "Unknown"


def check_s3_bucket_public(s3, bucket_name):
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        config = resp["PublicAccessBlockConfiguration"]
        all_blocked = all([
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False),
        ])
        return not all_blocked
    except ClientError:
        return False


# ── Analyse trail ─────────────────────────────────────────────────────────────

def analyse_trail(ct, s3, trail):
    name = trail["Name"]
    arn = trail["TrailARN"]
    home_region = trail.get("HomeRegion", "Unknown")
    log.info(f"  Trail: {name} ({home_region})")

    is_logging, last_delivery, delivery_error = check_trail_logging(ct, arn)
    is_multi_region = trail.get("IsMultiRegionTrail", False)
    include_global = trail.get("IncludeGlobalServiceEvents", False)
    log_validation = trail.get("LogFileValidationEnabled", False)
    has_kms = bool(trail.get("KMSKeyId"))
    kms_key = trail.get("KMSKeyId")
    has_cloudwatch = bool(trail.get("CloudWatchLogsLogGroupArn"))
    cloudwatch_group = trail.get("CloudWatchLogsLogGroupArn")
    s3_bucket = trail.get("S3BucketName", "")
    has_sns = bool(trail.get("SnsTopicARN"))

    has_management, has_data, read_write = check_event_selectors(ct, arn)

    s3_public = False
    if s3_bucket:
        s3_public = check_s3_bucket_public(s3, s3_bucket)

    flags = []
    if not is_logging:
        flags.append("❌ Trail is NOT actively logging")
    if delivery_error:
        flags.append(f"⚠️ Last delivery error: {delivery_error}")
    if not log_validation:
        flags.append("⚠️ Log file validation disabled")
    if not has_cloudwatch:
        flags.append("⚠️ No CloudWatch Logs integration")
    if not has_kms:
        flags.append("⚠️ Log files not KMS encrypted")
    if not is_multi_region:
        flags.append("⚠️ Single-region trail only")
    if not include_global:
        flags.append("⚠️ Global service events not captured")
    if s3_public:
        flags.append("❌ Trail S3 bucket is publicly accessible!")
    if not has_management:
        flags.append("⚠️ Management events not captured")
    if not has_data:
        flags.append("ℹ️ Data events not captured (S3/Lambda activity)")
    if read_write == "ReadOnly":
        flags.append("⚠️ Only capturing read events (not writes)")
    if has_sns:
        flags.append("✅ SNS notifications enabled")
    if has_kms:
        flags.append("✅ KMS encryption enabled")
    if log_validation:
        flags.append("✅ Log file validation enabled")
    if has_cloudwatch:
        flags.append("✅ CloudWatch Logs integrated")

    score, risk_level = calculate_score(
        not is_logging, not log_validation, not has_cloudwatch,
        not has_kms, not is_multi_region, not include_global, s3_public
    )

    last_delivery_str = last_delivery.isoformat() if last_delivery else "Never"

    return {
        "name": name,
        "arn": arn,
        "home_region": home_region,
        "risk_level": risk_level,
        "severity_score": score,
        "is_logging": is_logging,
        "is_multi_region": is_multi_region,
        "include_global_events": include_global,
        "log_file_validation": log_validation,
        "kms_encrypted": has_kms,
        "kms_key": kms_key,
        "cloudwatch_logs": has_cloudwatch,
        "cloudwatch_group": cloudwatch_group,
        "s3_bucket": s3_bucket,
        "s3_bucket_public": s3_public,
        "sns_enabled": has_sns,
        "management_events": has_management,
        "data_events": has_data,
        "read_write_type": read_write,
        "last_delivery": last_delivery_str,
        "delivery_error": delivery_error,
        "flags": flags,
    }


def check_region_coverage(session):
    """Check which regions have no CloudTrail trails at all."""
    uncovered = []
    for region in ALL_REGIONS:
        try:
            ct = session.client("cloudtrail", region_name=region)
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
            if not trails:
                uncovered.append(region)
        except ClientError:
            uncovered.append(region)
    return uncovered


# ── Output formatters ─────────────────────────────────────────────────────────

def write_json(report, path):
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    log.info(f"JSON report: {path}")


def write_csv(findings, path):
    if not findings:
        return
    fieldnames = [
        "name", "arn", "home_region", "risk_level", "severity_score",
        "is_logging", "is_multi_region", "include_global_events",
        "log_file_validation", "kms_encrypted", "kms_key",
        "cloudwatch_logs", "cloudwatch_group", "s3_bucket", "s3_bucket_public",
        "sns_enabled", "management_events", "data_events", "read_write_type",
        "last_delivery", "delivery_error", "flags",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            row = finding.copy()
            row["flags"] = "; ".join(row.get("flags", []))
            writer.writerow(row)
    log.info(f"CSV report: {path}")


def write_html(report, path):
    findings = report["findings"]
    summary = report["summary"]
    generated = report["generated_at"]
    uncovered = report.get("uncovered_regions", [])

    risk_colors = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "LOW": "#27ae60"}

    rows = ""
    for f in findings:
        color = risk_colors.get(f["risk_level"], "#999")
        flags_html = "<br>".join(f.get("flags", [])) or "None"
        rows += f"""
        <tr>
            <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{f['risk_level']}</span></td>
            <td style="font-weight:bold">{f['severity_score']}/10</td>
            <td>{f['name']}</td>
            <td>{f['home_region']}</td>
            <td>{'✅ Active' if f['is_logging'] else '❌ Inactive'}</td>
            <td>{'✅' if f['is_multi_region'] else '❌'}</td>
            <td>{'✅' if f['kms_encrypted'] else '❌'}</td>
            <td>{'✅' if f['cloudwatch_logs'] else '❌'}</td>
            <td>{'✅' if f['log_file_validation'] else '❌'}</td>
            <td style="font-size:0.8em">{flags_html}</td>
        </tr>"""

    uncovered_html = ""
    if uncovered:
        uncovered_html = f"""
        <div style="margin: 0 40px 20px; padding: 15px 20px; background: #fdf3e3; border-left: 4px solid #e67e22; border-radius: 4px;">
            <strong>⚠️ Regions with no CloudTrail coverage ({len(uncovered)}):</strong><br>
            <span style="font-size:0.9em">{', '.join(uncovered)}</span>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CloudTrail Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f5f6fa; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #2c3e50, #8e44ad); color: white; padding: 30px 40px; }}
  .header h1 {{ margin: 0; font-size: 1.8em; }}
  .header p {{ margin: 5px 0 0; opacity: 0.8; }}
  .summary {{ display: flex; gap: 20px; padding: 20px 40px; flex-wrap: wrap; }}
  .card {{ background: white; border-radius: 8px; padding: 20px 30px; flex: 1; min-width: 140px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }}
  .card .num {{ font-size: 2.5em; font-weight: bold; }}
  .card .label {{ color: #666; font-size: 0.9em; margin-top: 4px; }}
  .critical .num {{ color: #c0392b; }} .high .num {{ color: #e67e22; }}
  .medium .num {{ color: #f39c12; }} .low .num {{ color: #27ae60; }}
  .total .num {{ color: #3498db; }}
  .table-wrap {{ padding: 0 40px 40px; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  th {{ background: #2c3e50; color: white; padding: 12px 15px; text-align: left; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }}
  td {{ padding: 10px 15px; border-bottom: 1px solid #ecf0f1; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f8f9ff; }}
  .footer {{ text-align: center; padding: 20px; color: #999; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 CloudTrail Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; {summary['total_trails']} trails analysed across {summary['regions_checked']} regions</p>
</div>
<div class="summary">
  <div class="card total"><div class="num">{summary['total_trails']}</div><div class="label">Total Trails</div></div>
  <div class="card critical"><div class="num">{summary['critical']}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{summary['high']}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{summary['medium']}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{summary['low']}</div><div class="label">Low</div></div>
  <div class="card" style="border-left:4px solid #c0392b"><div class="num" style="color:#c0392b">{summary['trails_not_logging']}</div><div class="label">Not Logging</div></div>
  <div class="card" style="border-left:4px solid #e67e22"><div class="num" style="color:#e67e22">{summary['uncovered_regions']}</div><div class="label">Uncovered Regions</div></div>
  <div class="card" style="border-left:4px solid #f39c12"><div class="num" style="color:#f39c12">{summary['no_kms']}</div><div class="label">No KMS</div></div>
  <div class="card" style="border-left:4px solid #95a5a6"><div class="num" style="color:#95a5a6">{summary['no_cloudwatch']}</div><div class="label">No CloudWatch</div></div>
</div>
{uncovered_html}
<div class="table-wrap">
  <table>
    <thead>
      <tr><th>Risk</th><th>Score</th><th>Trail Name</th><th>Region</th><th>Logging</th><th>Multi-Region</th><th>KMS</th><th>CloudWatch</th><th>Log Validation</th><th>Flags</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">CloudTrail Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    log.info(f"HTML report: {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(output_prefix="cloudtrail_report", fmt="all", profile=None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    ct = session.client("cloudtrail")
    s3 = session.client("s3")

    account_id = None
    try:
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        log.info(f"Account ID: {account_id}")
    except ClientError:
        log.warning("Could not determine account ID")

    log.info("Fetching CloudTrail trails...")
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    except ClientError as e:
        log.error(f"Could not list trails: {e}")
        return

    log.info(f"Found {len(trails)} trails — checking region coverage...")
    uncovered = check_region_coverage(session)

    findings = []
    for trail in trails:
        home_region = trail.get("HomeRegion", "us-east-1")
        regional_ct = session.client("cloudtrail", region_name=home_region)
        findings.append(analyse_trail(regional_ct, s3, trail))

    findings.sort(key=lambda x: x["severity_score"], reverse=True)

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        risk_counts[f["risk_level"]] = risk_counts.get(f["risk_level"], 0) + 1

    report = {
        "generated_at": NOW.isoformat(),
        "account_id": account_id,
        "uncovered_regions": uncovered,
        "summary": {
            "total_trails": len(findings),
            "critical": risk_counts.get("CRITICAL", 0),
            "high": risk_counts.get("HIGH", 0),
            "medium": risk_counts.get("MEDIUM", 0),
            "low": risk_counts.get("LOW", 0),
            "trails_not_logging": sum(1 for f in findings if not f["is_logging"]),
            "uncovered_regions": len(uncovered),
            "no_kms": sum(1 for f in findings if not f["kms_encrypted"]),
            "no_cloudwatch": sum(1 for f in findings if not f["cloudwatch_logs"]),
            "no_validation": sum(1 for f in findings if not f["log_file_validation"]),
            "regions_checked": len(ALL_REGIONS),
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
╔══════════════════════════════════════════╗
║      CLOUDTRAIL AUDITOR — SUMMARY        ║
╠══════════════════════════════════════════╣
║  Total trails:        {s['total_trails']:<20}║
║  CRITICAL:            {s['critical']:<20}║
║  HIGH:                {s['high']:<20}║
║  MEDIUM:              {s['medium']:<20}║
║  LOW:                 {s['low']:<20}║
║  Not logging:         {s['trails_not_logging']:<20}║
║  Uncovered regions:   {s['uncovered_regions']:<20}║
║  No KMS encryption:   {s['no_kms']:<20}║
║  No CloudWatch:       {s['no_cloudwatch']:<20}║
╚══════════════════════════════════════════╝
""")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CloudTrail Auditor")
    parser.add_argument("--output", "-o", default="cloudtrail_report", help="Output file prefix (default: cloudtrail_report)")
    parser.add_argument("--format", "-f", choices=["json", "csv", "html", "all", "stdout"], default="all", help="Output format (default: all)")
    parser.add_argument("--profile", default=None, help="AWS CLI profile name to use")
    args = parser.parse_args()
    run(output_prefix=args.output, fmt=args.format, profile=args.profile)
