#!/usr/bin/env python3
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
import html
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
            # No block config set — treat as not blocked (security risk)
            return {}, False
        # Unexpected API error — return None to signal unknown state
        log.warning(f"Could not check Block Public Access for {bucket}: {e}")
        return None, False


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


def _is_public_principal(principal):
    """Return True if a policy principal grants public access."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS", "")
        if aws == "*":
            return True
        if isinstance(aws, list) and "*" in aws:
            return True
    return False


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
            if _is_public_principal(principal):
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

    block_check_failed = block_config is None
    is_public = acl_public or policy_public or not all_blocked

    flags = []
    remediations = []
    if block_check_failed:
        flags.append("⚠️ Could not verify Block Public Access configuration (API error)")
        remediations.append("Check IAM permissions allow s3:GetBucketPublicAccessBlock")
    if acl_public:
        flags.append(f"⚠️ Public ACL ({acl_uri})")
        remediations.append("Remove public grants: S3 Console → Permissions → ACL → revoke AllUsers/AuthenticatedUsers grants")
    if policy_public:
        flags.append("⚠️ Public bucket policy")
        remediations.append('Remove public access: S3 Console → Permissions → Bucket policy → remove or deny "Principal": "*" Allow statements')
    if not block_check_failed and not all_blocked:
        flags.append("⚠️ Block Public Access not fully enabled")
        remediations.append("Enable all 4 Block Public Access settings: S3 Console → Permissions → Block public access → Edit → enable all")
    if not encrypted:
        flags.append("⚠️ No encryption at rest")
        remediations.append("Enable default encryption: S3 Console → Properties → Default encryption → SSE-S3 or SSE-KMS")
    if not versioned:
        flags.append("⚠️ Versioning disabled")
        remediations.append("Enable versioning: S3 Console → Properties → Bucket Versioning → Enable")
    if not logging_on:
        flags.append("⚠️ Access logging disabled")
        remediations.append("Enable server access logging: S3 Console → Properties → Server access logging → Enable")
    if encrypted and enc_algo == "AES256":
        flags.append("ℹ️ SSE-S3 (consider KMS for stronger control)")
        remediations.append("Upgrade to SSE-KMS: S3 Console → Properties → Default encryption → SSE-KMS → choose a CMK for stronger key control")
    # NOTE: ✅ (positive) flags are appended last with no matching remediations.
    # The HTML renderer's fallback (flags_list[len(rems_list):]) depends on this ordering.
    # If adding a new ✅ flag, always append it after all ⚠️/ℹ️/❌ flags.
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
        "remediations": remediations,
        "cis_control": "CIS 3",
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
    fieldnames = [
        "name", "region", "risk_level", "severity_score",
        "is_public", "public_acl", "public_policy",
        "block_public_access_enabled", "encryption_enabled",
        "encryption_algorithm", "kms_key", "versioning_status",
        "mfa_delete", "logging_enabled", "log_target_bucket",
        "lifecycle_rules", "policy_findings", "flags", "remediations",
        "cis_control",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            row = finding.copy()
            for field in ["policy_findings", "flags", "remediations"]:
                val = row.get(field, [])
                row[field] = "; ".join(val) if isinstance(val, list) else (val or "")
            row.pop("block_public_access_config", None)
            writer.writerow(row)
    os.chmod(path, 0o600)
    log.info(f"CSV report: {path}")


def write_html(report, path):
    findings = report["findings"]
    summary = report["summary"]
    generated = report["generated_at"]

    risk_colors = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#28a745"}

    rows = ""
    for f in findings:
        color = risk_colors.get(f["risk_level"], "#999")
        flag_items = []
        for flag, rem in zip(f.get("flags", []), f.get("remediations", [])):
            flag_items.append(
                f'<div class="flag-item">'
                f'<span class="flag-text">{html.escape(flag)}</span>'
                f'<span class="rem-text">↳ {html.escape(rem)}</span>'
                f'</div>'
            )
        # Also render any flags that have no paired remediation (e.g. ✅ flags)
        flags_list = f.get("flags", [])
        rems_list = f.get("remediations", [])
        for flag in flags_list[len(rems_list):]:
            flag_items.append(f'<div class="flag-item"><span class="flag-text">{html.escape(flag)}</span></div>')
        flags_html = "".join(flag_items) or "None"
        policy_html = "<br>".join(html.escape(pf) for pf in f.get("policy_findings", [])) or "None"
        public_badge = '<span style="background:#dc3545;color:white;padding:1px 6px;border-radius:3px">PUBLIC</span>' if f["is_public"] else '<span style="background:#28a745;color:white;padding:1px 6px;border-radius:3px">PRIVATE</span>'
        _enc_raw = f.get("encryption_algorithm") or ""
        enc = html.escape(_enc_raw) if _enc_raw else "❌ None"
        name_escaped = html.escape(f["name"])
        region_escaped = html.escape(str(f["region"]))
        versioning_escaped = html.escape(str(f["versioning_status"]))
        rows += f"""
        <tr>
            <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{f['risk_level']}</span></td>
            <td style="font-weight:bold">{f['severity_score']}/10</td>
            <td>{name_escaped}</td>
            <td>{region_escaped}</td>
            <td>{public_badge}</td>
            <td>{enc}</td>
            <td>{'✅' if f['versioning_status'] == 'Enabled' else '❌'} {versioning_escaped}</td>
            <td>{'✅' if f['logging_enabled'] else '❌'}</td>
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
<title>S3 Bucket Audit Report</title>
<style>
{get_styles(extra_css)}
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
  <div class="card" style="border-left:4px solid #dc3545"><div class="num" style="color:#dc3545">{summary['public_buckets']}</div><div class="label">Public Buckets</div></div>
  <div class="card" style="border-left:4px solid #fd7e14"><div class="num" style="color:#fd7e14">{summary['unencrypted_buckets']}</div><div class="label">No Encryption</div></div>
  <div class="card" style="border-left:4px solid #ffc107"><div class="num" style="color:#ffc107">{summary['no_versioning']}</div><div class="label">No Versioning</div></div>
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
        f.write(html_content)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(output_prefix="s3_report", fmt="all", profile=None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    s3 = session.client("s3", config=BOTO_CONFIG)

    account_id = None
    try:
        sts = session.client("sts", config=BOTO_CONFIG)
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
