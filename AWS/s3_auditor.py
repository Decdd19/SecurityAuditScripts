"""
S3 Bucket Auditor
=================
Audits all S3 buckets in your AWS account for common security misconfigurations:
- Public access (ACLs, bucket policies, block public access settings)
- Encryption at rest (SSE enabled, KMS vs AES256)
- Versioning status
- Access logging enabled
- Lifecycle policies
- Bucket policy analysis

Usage:
    python3 s3_auditor.py
    python3 s3_auditor.py --output report --format all
    python3 s3_auditor.py --format csv
    python3 s3_auditor.py --profile prod
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


# ── Scoring ───────────────────────────────────────────────────────────────────

def calculate_score(is_public, no_encryption, no_versioning, no_logging,
                    public_policy, no_block_public_access):
    score = 0
    if is_public:
        score += 5
    if public_policy:
        score += 3
    if no_block_public_access:
        score += 2
    if no_encryption:
        score += 2
    if no_versioning:
        score += 1
    if no_logging:
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


# ── Bucket checks ─────────────────────────────────────────────────────────────

def check_public_access_block(s3, bucket):
    try:
        resp = s3.get_public_access_block(Bucket=bucket)
        config = resp["PublicAccessBlockConfiguration"]
        all_blocked = all([
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False),
        ])
        return config, all_blocked
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return {}, False
        return {}, False


def check_acl(s3, bucket):
    try:
        acl = s3.get_bucket_acl(Bucket=bucket)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                return True, uri
        return False, None
    except ClientError:
        return False, None


def check_bucket_policy(s3, bucket):
    try:
        policy = s3.get_bucket_policy(Bucket=bucket)
        doc = json.loads(policy["Policy"])
        is_public = False
        findings = []
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", "")
            if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                findings.append(f"Public allow: {', '.join(actions)}")
                is_public = True
        return is_public, findings, doc
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchBucketPolicy", "AccessDenied"):
            return False, [], {}
        return False, [], {}


def check_encryption(s3, bucket):
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket)
        rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
        for rule in rules:
            sse = rule.get("ApplyServerSideEncryptionByDefault", {})
            algo = sse.get("SSEAlgorithm", "Unknown")
            kms_key = sse.get("KMSMasterKeyID", None)
            return True, algo, kms_key
        return False, None, None
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return False, None, None
        return False, None, None


def check_versioning(s3, bucket):
    try:
        resp = s3.get_bucket_versioning(Bucket=bucket)
        status = resp.get("Status", "Disabled")
        mfa_delete = resp.get("MFADelete", "Disabled")
        return status == "Enabled", status, mfa_delete
    except ClientError:
        return False, "Unknown", "Unknown"


def check_logging(s3, bucket):
    try:
        resp = s3.get_bucket_logging(Bucket=bucket)
        logging_enabled = "LoggingEnabled" in resp
        target = resp.get("LoggingEnabled", {}).get("TargetBucket", None)
        return logging_enabled, target
    except ClientError:
        return False, None


def check_lifecycle(s3, bucket):
    try:
        resp = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
        rules = resp.get("Rules", [])
        return len(rules) > 0, len(rules)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
            return False, 0
        return False, 0


def get_bucket_location(s3, bucket):
    try:
        resp = s3.get_bucket_location(Bucket=bucket)
        region = resp.get("LocationConstraint") or "us-east-1"
        return region
    except ClientError:
        return "Unknown"


def get_bucket_size(s3, bucket, region):
    """Approximate object count via listing (capped at 1 for speed)."""
    try:
        regional_s3 = boto3.client("s3", region_name=region)
        resp = regional_s3.list_objects_v2(Bucket=bucket, MaxKeys=1)
        return resp.get("KeyCount", 0), resp.get("IsTruncated", False)
    except ClientError:
        return 0, False


# ── Analyse bucket ────────────────────────────────────────────────────────────

def analyse_bucket(s3, bucket_name):
    log.info(f"  Bucket: {bucket_name}")

    region = get_bucket_location(s3, bucket_name)

    block_config, all_blocked = check_public_access_block(s3, bucket_name)
    acl_public, acl_uri = check_acl(s3, bucket_name)
    policy_public, policy_findings, _ = check_bucket_policy(s3, bucket_name)
    encrypted, enc_algo, kms_key = check_encryption(s3, bucket_name)
    versioned, version_status, mfa_delete = check_versioning(s3, bucket_name)
    logging_on, log_target = check_logging(s3, bucket_name)
    has_lifecycle, lifecycle_count = check_lifecycle(s3, bucket_name)

    is_public = acl_public or policy_public or not all_blocked

    flags = []
    if acl_public:
        flags.append(f"⚠️ Public ACL ({acl_uri})")
    if policy_public:
        flags.append("⚠️ Public bucket policy")
    if not all_blocked:
        flags.append("⚠️ Block Public Access not fully enabled")
    if not encrypted:
        flags.append("⚠️ No encryption at rest")
    if not versioned:
        flags.append("⚠️ Versioning disabled")
    if not logging_on:
        flags.append("⚠️ Access logging disabled")
    if encrypted and enc_algo == "AES256":
        flags.append("ℹ️ SSE-S3 (consider KMS for stronger control)")
    if encrypted and kms_key:
        flags.append("✅ KMS encryption")
    if mfa_delete == "Enabled":
        flags.append("✅ MFA Delete enabled")

    score, risk_level = calculate_score(
        is_public, not encrypted, not versioned,
        not logging_on, policy_public, not all_blocked
    )

    return {
        "name": bucket_name,
        "region": region,
        "risk_level": risk_level,
        "severity_score": score,
        "is_public": is_public,
        "public_acl": acl_public,
        "public_policy": policy_public,
        "block_public_access_enabled": all_blocked,
        "block_public_access_config": block_config,
        "encryption_enabled": encrypted,
        "encryption_algorithm": enc_algo,
        "kms_key": kms_key,
        "versioning_status": version_status,
        "mfa_delete": mfa_delete,
        "logging_enabled": logging_on,
        "log_target_bucket": log_target,
        "lifecycle_rules": lifecycle_count,
        "policy_findings": policy_findings,
        "flags": flags,
    }


# ── Output formatters ─────────────────────────────────────────────────────────

def write_json(report, path):
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    log.info(f"JSON report: {path}")


def write_csv(findings, path):
    if not findings:
        return
    fieldnames = [
        "name", "region", "risk_level", "severity_score",
        "is_public", "public_acl", "public_policy",
        "block_public_access_enabled", "encryption_enabled",
        "encryption_algorithm", "kms_key", "versioning_status",
        "mfa_delete", "logging_enabled", "log_target_bucket",
        "lifecycle_rules", "policy_findings", "flags",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            row = finding.copy()
            for field in ["policy_findings", "flags"]:
                val = row.get(field, [])
                row[field] = "; ".join(val) if isinstance(val, list) else (val or "")
            row.pop("block_public_access_config", None)
            writer.writerow(row)
    log.info(f"CSV report: {path}")


def write_html(report, path):
    findings = report["findings"]
    summary = report["summary"]
    generated = report["generated_at"]

    risk_colors = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "LOW": "#27ae60"}

    rows = ""
    for f in findings:
        color = risk_colors.get(f["risk_level"], "#999")
        flags_html = "<br>".join(f.get("flags", [])) or "None"
        policy_html = "<br>".join(f.get("policy_findings", [])) or "None"
        public_badge = '<span style="background:#c0392b;color:white;padding:1px 6px;border-radius:3px">PUBLIC</span>' if f["is_public"] else '<span style="background:#27ae60;color:white;padding:1px 6px;border-radius:3px">PRIVATE</span>'
        enc = f.get("encryption_algorithm") or "❌ None"
        rows += f"""
        <tr>
            <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{f['risk_level']}</span></td>
            <td style="font-weight:bold">{f['severity_score']}/10</td>
            <td>{f['name']}</td>
            <td>{f['region']}</td>
            <td>{public_badge}</td>
            <td>{enc}</td>
            <td>{'✅' if f['versioning_status'] == 'Enabled' else '❌'} {f['versioning_status']}</td>
            <td>{'✅' if f['logging_enabled'] else '❌'}</td>
            <td style="font-size:0.8em">{flags_html}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>S3 Bucket Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f5f6fa; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #2c3e50, #27ae60); color: white; padding: 30px 40px; }}
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
  <h1>🪣 S3 Bucket Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; {summary['total_buckets']} buckets analysed</p>
</div>
<div class="summary">
  <div class="card total"><div class="num">{summary['total_buckets']}</div><div class="label">Total Buckets</div></div>
  <div class="card critical"><div class="num">{summary['critical']}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{summary['high']}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{summary['medium']}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{summary['low']}</div><div class="label">Low</div></div>
  <div class="card" style="border-left:4px solid #c0392b"><div class="num" style="color:#c0392b">{summary['public_buckets']}</div><div class="label">Public Buckets</div></div>
  <div class="card" style="border-left:4px solid #e67e22"><div class="num" style="color:#e67e22">{summary['unencrypted_buckets']}</div><div class="label">No Encryption</div></div>
  <div class="card" style="border-left:4px solid #f39c12"><div class="num" style="color:#f39c12">{summary['no_versioning']}</div><div class="label">No Versioning</div></div>
  <div class="card" style="border-left:4px solid #95a5a6"><div class="num" style="color:#95a5a6">{summary['no_logging']}</div><div class="label">No Logging</div></div>
</div>
<div class="table-wrap">
  <table>
    <thead>
      <tr><th>Risk</th><th>Score</th><th>Bucket Name</th><th>Region</th><th>Visibility</th><th>Encryption</th><th>Versioning</th><th>Logging</th><th>Flags</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">S3 Bucket Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    log.info(f"HTML report: {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(output_prefix="s3_report", fmt="all", profile=None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    s3 = session.client("s3")

    account_id = None
    try:
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        log.info(f"Account ID: {account_id}")
    except ClientError:
        log.warning("Could not determine account ID")

    log.info("Listing S3 buckets...")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        log.error(f"Could not list buckets: {e}")
        return

    log.info(f"Found {len(buckets)} buckets")
    findings = []
    for b in buckets:
        findings.append(analyse_bucket(s3, b["Name"]))

    findings.sort(key=lambda x: x["severity_score"], reverse=True)

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        risk_counts[f["risk_level"]] = risk_counts.get(f["risk_level"], 0) + 1

    report = {
        "generated_at": NOW.isoformat(),
        "account_id": account_id,
        "summary": {
            "total_buckets": len(findings),
            "critical": risk_counts.get("CRITICAL", 0),
            "high": risk_counts.get("HIGH", 0),
            "medium": risk_counts.get("MEDIUM", 0),
            "low": risk_counts.get("LOW", 0),
            "public_buckets": sum(1 for f in findings if f["is_public"]),
            "unencrypted_buckets": sum(1 for f in findings if not f["encryption_enabled"]),
            "no_versioning": sum(1 for f in findings if f["versioning_status"] != "Enabled"),
            "no_logging": sum(1 for f in findings if not f["logging_enabled"]),
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
║         S3 AUDITOR — SUMMARY             ║
╠══════════════════════════════════════════╣
║  Total buckets:       {s['total_buckets']:<20}║
║  CRITICAL:            {s['critical']:<20}║
║  HIGH:                {s['high']:<20}║
║  MEDIUM:              {s['medium']:<20}║
║  LOW:                 {s['low']:<20}║
║  Public buckets:      {s['public_buckets']:<20}║
║  No encryption:       {s['unencrypted_buckets']:<20}║
║  No versioning:       {s['no_versioning']:<20}║
║  No logging:          {s['no_logging']:<20}║
╚══════════════════════════════════════════╝
""")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="S3 Bucket Auditor")
    parser.add_argument("--output", "-o", default="s3_report", help="Output file prefix (default: s3_report)")
    parser.add_argument("--format", "-f", choices=["json", "csv", "html", "all", "stdout"], default="all", help="Output format (default: all)")
    parser.add_argument("--profile", default=None, help="AWS CLI profile name to use")
    args = parser.parse_args()
    run(output_prefix=args.output, fmt=args.format, profile=args.profile)
