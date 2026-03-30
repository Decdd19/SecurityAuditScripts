#!/usr/bin/env python3
"""
KMS Key Auditor
===============
Audits all customer-managed KMS keys across AWS regions for common security misconfigurations:
- Key rotation enabled (symmetric keys only)
- Key state (enabled vs disabled/pending_deletion/pending_import)
- Key policy — public or cross-account wildcard access
- Key alias presence (unaliased keys are harder to manage)
- Key spec (SYMMETRIC_DEFAULT, RSA_*, ECC_*, HMAC_*)

Usage:
    python3 kms_auditor.py
    python3 kms_auditor.py --output report --format html
    python3 kms_auditor.py --profile prod
    python3 kms_auditor.py --regions us-east-1 eu-west-1
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

# ── Logging ───────────────────────────────────────────────────────────────────
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


# ── Scoring ───────────────────────────────────────────────────────────────────

def calculate_score(public_policy, no_rotation, not_enabled):
    score = 0
    if public_policy:
        score += 5   # CRITICAL
    if not_enabled:
        score += 3   # HIGH
    if no_rotation:
        score += 2   # MEDIUM
    score = min(score, 10)

    if score >= 8:
        risk = "CRITICAL"
    elif score >= 5:
        risk = "HIGH"
    elif score >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return score, risk


# ── Key checks ────────────────────────────────────────────────────────────────

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


def check_key_policy(kms, key_id):
    """
    Parse the default key policy for wildcard/public Allow statements.
    Returns (public_policy: bool, policy_doc: dict).
    """
    try:
        resp = kms.get_key_policy(KeyId=key_id, PolicyName="default")
        doc = json.loads(resp["Policy"])
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", "")
            if _is_public_principal(principal):
                return True, doc
        return False, doc
    except ClientError as e:
        log.warning(f"Could not retrieve key policy for {key_id}: {e}")
        return False, {}


def get_key_aliases(kms, key_id):
    """Return list of alias names for the given key."""
    try:
        resp = kms.list_aliases(KeyId=key_id)
        return [a["AliasName"] for a in resp.get("Aliases", [])]
    except ClientError as e:
        log.warning(f"Could not list aliases for {key_id}: {e}")
        return []


def get_rotation_status(kms, key_id, key_spec):
    """
    Return (rotation_enabled: bool|None, rotation_applicable: bool).
    Asymmetric and HMAC keys cannot have rotation; returns (None, False).
    """
    # Only SYMMETRIC_DEFAULT keys support automatic rotation
    if key_spec != "SYMMETRIC_DEFAULT":
        return None, False
    try:
        resp = kms.get_key_rotation_status(KeyId=key_id)
        return resp.get("KeyRotationEnabled", False), True
    except ClientError as e:
        log.warning(f"Could not get rotation status for {key_id}: {e}")
        return None, False


# ── Build flags/remediations ──────────────────────────────────────────────────

def build_flags(key_enabled, key_state, rotation_enabled, rotation_applicable,
                public_policy, aliases):
    """
    Return (flags: list[str], remediations: list[str]).
    Positive ✅ flags are appended last, with no paired remediations.
    """
    flags = []
    remediations = []

    if public_policy:
        flags.append("❌ Key policy allows public/wildcard principal")
        remediations.append(
            "Remove wildcard principal: KMS Console → Key policy → Edit → "
            "remove or restrict statements with Principal: * or AWS: *"
        )

    if not key_enabled:
        flags.append(f"⚠️ Key state is {key_state} (not Enabled)")
        remediations.append(
            f"Re-enable or delete key: KMS Console → Customer managed keys → "
            f"select key → Key actions → Enable (or schedule deletion if unused)"
        )

    if rotation_applicable and rotation_enabled is False:
        flags.append("⚠️ Automatic key rotation is disabled")
        remediations.append(
            "Enable rotation: KMS Console → Customer managed keys → select key → "
            "Key rotation → Enable automatic key rotation"
        )

    if not aliases:
        flags.append("ℹ️ Key has no alias (harder to identify and manage)")
        remediations.append(
            "Add a descriptive alias: aws kms create-alias "
            "--alias-name alias/my-key --target-key-id <key-id>"
        )

    # NOTE: ✅ (positive) flags are appended last with no matching remediations.
    # The HTML renderer's fallback (flags_list[len(rems_list):]) depends on this ordering.
    if key_enabled:
        flags.append("✅ Key is enabled")
    if rotation_applicable and rotation_enabled:
        flags.append("✅ Automatic key rotation enabled")
    if not rotation_applicable:
        flags.append("ℹ️ Key rotation not applicable (asymmetric/HMAC key)")

    return flags, remediations


# ── Analyse key ───────────────────────────────────────────────────────────────

def analyse_key(kms, key_id, key_arn, region):
    """Audit a single customer-managed KMS key and return a finding dict."""
    log.info(f"  Key: {key_id} ({region})")

    try:
        meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    except ClientError as e:
        log.warning(f"Could not describe key {key_id}: {e}")
        return None

    # Skip AWS-managed keys (should already be filtered, but guard here too)
    if meta.get("KeyManager") == "AWS":
        return None

    key_state = meta.get("KeyState", "Unknown")
    key_enabled = key_state == "Enabled"
    key_spec = meta.get("KeySpec", "SYMMETRIC_DEFAULT")
    multi_region = meta.get("MultiRegion", False)
    creation_date = meta.get("CreationDate", None)
    creation_iso = creation_date.isoformat() if creation_date else ""

    aliases = get_key_aliases(kms, key_id)
    rotation_enabled, rotation_applicable = get_rotation_status(kms, key_id, key_spec)
    public_policy, _ = check_key_policy(kms, key_id)

    no_rotation = rotation_applicable and not rotation_enabled
    not_enabled = not key_enabled

    score, risk_level = calculate_score(public_policy, no_rotation, not_enabled)
    flags, remediations = build_flags(
        key_enabled, key_state, rotation_enabled, rotation_applicable,
        public_policy, aliases
    )

    return {
        "key_id": key_id,
        "key_arn": key_arn,
        "aliases": aliases,
        "key_state": key_state,
        "key_enabled": key_enabled,
        "key_spec": key_spec,
        "key_manager": meta.get("KeyManager", "CUSTOMER"),
        "multi_region": multi_region,
        "rotation_enabled": rotation_enabled,
        "rotation_applicable": rotation_applicable,
        "public_policy": public_policy,
        "creation_date": creation_iso,
        "region": region,
        "severity_score": score,
        "risk_level": risk_level,
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
        "key_id", "key_arn", "aliases", "key_state", "key_enabled",
        "key_spec", "key_manager", "multi_region", "rotation_enabled",
        "rotation_applicable", "public_policy", "creation_date", "region",
        "severity_score", "risk_level", "flags", "remediations", "cis_control",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            row = finding.copy()
            for field in ["aliases", "flags", "remediations"]:
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
        color = risk_colors.get(f["risk_level"], "#999")

        flag_items = []
        for flag, rem in zip(f.get("flags", []), f.get("remediations", [])):
            flag_items.append(
                f'<div class="flag-item">'
                f'<span class="flag-text">{html_lib.escape(flag)}</span>'
                f'<span class="rem-text">↳ {html_lib.escape(rem)}</span>'
                f'</div>'
            )
        # Also render any flags that have no paired remediation (e.g. ✅ flags)
        flags_list = f.get("flags", [])
        rems_list = f.get("remediations", [])
        for flag in flags_list[len(rems_list):]:
            flag_items.append(
                f'<div class="flag-item">'
                f'<span class="flag-text">{html_lib.escape(flag)}</span>'
                f'</div>'
            )
        flags_html = "".join(flag_items) or "None"

        aliases_display = html_lib.escape(", ".join(f.get("aliases", [])) or "(none)")
        key_id_escaped = html_lib.escape(f["key_id"])
        region_escaped = html_lib.escape(f["region"])
        state_escaped = html_lib.escape(f["key_state"])
        spec_escaped = html_lib.escape(f["key_spec"])

        if f["rotation_applicable"]:
            rotation_display = "✅ Yes" if f["rotation_enabled"] else "❌ No"
        else:
            rotation_display = "N/A"

        rows += f"""
        <tr>
            <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{f['risk_level']}</span></td>
            <td style="font-weight:bold">{f['severity_score']}/10</td>
            <td style="font-family:monospace;font-size:0.85em">{key_id_escaped}</td>
            <td style="font-size:0.85em">{aliases_display}</td>
            <td>{region_escaped}</td>
            <td>{'✅' if f['key_enabled'] else '❌'} {state_escaped}</td>
            <td>{rotation_display}</td>
            <td>{spec_escaped}</td>
            <td style="font-size:0.8em">{flags_html}</td>
        </tr>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>KMS Key Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f5f6fa; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #232f3e, #ff9900); color: white; padding: 30px 40px; }}
  .header h1 {{ margin: 0; font-size: 1.8em; }}
  .header p {{ margin: 5px 0 0; opacity: 0.8; }}
  .summary {{ display: flex; gap: 20px; padding: 20px 40px; flex-wrap: wrap; }}
  .card {{ background: white; border-radius: 8px; padding: 20px 30px; flex: 1; min-width: 140px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }}
  .card .num {{ font-size: 2.5em; font-weight: bold; }}
  .card .label {{ color: #666; font-size: 0.9em; margin-top: 4px; }}
  .critical .num {{ color: #dc3545; }} .high .num {{ color: #fd7e14; }}
  .medium .num {{ color: #ffc107; }} .low .num {{ color: #28a745; }}
  .total .num {{ color: #3498db; }}
  .table-wrap {{ padding: 0 40px 40px; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  th {{ background: #232f3e; color: white; padding: 12px 15px; text-align: left; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }}
  td {{ padding: 10px 15px; border-bottom: 1px solid #ecf0f1; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f8f9ff; }}
  .footer {{ text-align: center; padding: 20px; color: #999; font-size: 0.85em; }}
  .flag-item {{ margin-bottom: 6px; }}
  .flag-text {{ display: block; font-size: 0.85em; }}
  .rem-text {{ display: block; font-size: 0.78em; color: #555; padding-left: 12px; font-style: italic; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔑 KMS Key Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; {summary['total_keys']} customer-managed keys analysed</p>
</div>
<div class="summary">
  <div class="card total"><div class="num">{summary['total_keys']}</div><div class="label">Total CMKs</div></div>
  <div class="card critical"><div class="num">{summary['critical']}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{summary['high']}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{summary['medium']}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{summary['low']}</div><div class="label">Low</div></div>
  <div class="card" style="border-left:4px solid #dc3545"><div class="num" style="color:#dc3545">{summary['public_policy']}</div><div class="label">Public Policy</div></div>
  <div class="card" style="border-left:4px solid #fd7e14"><div class="num" style="color:#fd7e14">{summary['no_rotation']}</div><div class="label">No Rotation</div></div>
  <div class="card" style="border-left:4px solid #ffc107"><div class="num" style="color:#ffc107">{summary['not_enabled']}</div><div class="label">Not Enabled</div></div>
</div>
<div class="table-wrap">
  <table>
    <thead>
      <tr><th>Risk</th><th>Score</th><th>Key ID</th><th>Aliases</th><th>Region</th><th>State</th><th>Rotation</th><th>Spec</th><th>Flags</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">KMS Key Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html_content)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(output_prefix="kms_report", fmt="all", profile=None, regions=None):
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
            kms = session.client("kms", region_name=region, config=BOTO_CONFIG)
            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for key_entry in page.get("Keys", []):
                    key_id = key_entry["KeyId"]
                    key_arn = key_entry["KeyArn"]

                    # Quick pre-check: skip AWS-managed keys by describing first
                    try:
                        meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    except ClientError as e:
                        log.warning(f"Could not describe key {key_id}: {e}")
                        continue

                    if meta.get("KeyManager") == "AWS":
                        log.info(f"  Skipping AWS-managed key: {key_id}")
                        continue

                    finding = analyse_key(kms, key_id, key_arn, region)
                    if finding:
                        findings.append(finding)

        except ClientError as e:
            log.warning(f"Could not scan region {region}: {e}")
            continue

    findings.sort(key=lambda x: x["severity_score"], reverse=True)

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        risk_counts[f["risk_level"]] = risk_counts.get(f["risk_level"], 0) + 1

    report = {
        "generated_at": NOW.isoformat(),
        "account_id": account_id,
        "summary": {
            "total_keys": len(findings),
            "critical": risk_counts.get("CRITICAL", 0),
            "high": risk_counts.get("HIGH", 0),
            "medium": risk_counts.get("MEDIUM", 0),
            "low": risk_counts.get("LOW", 0),
            "no_rotation": sum(1 for f in findings if f["rotation_enabled"] is False),
            "public_policy": sum(1 for f in findings if f["public_policy"]),
            "not_enabled": sum(1 for f in findings if not f["key_enabled"]),
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
║         KMS AUDITOR — SUMMARY            ║
╠══════════════════════════════════════════╣
║  Customer-managed keys:   {s['total_keys']:<20}║
║  CRITICAL:                {s['critical']:<20}║
║  HIGH:                    {s['high']:<20}║
║  MEDIUM:                  {s['medium']:<20}║
║  LOW:                     {s['low']:<20}║
║  No rotation:             {s['no_rotation']:<20}║
║  Public policy:           {s['public_policy']:<20}║
║  Not enabled:             {s['not_enabled']:<20}║
╚══════════════════════════════════════════╝
""")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KMS Key Auditor")
    parser.add_argument("--output", "-o", default="kms_report",
                        help="Output file prefix (default: kms_report)")
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
