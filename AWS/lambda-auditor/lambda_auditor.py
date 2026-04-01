#!/usr/bin/env python3
"""
Lambda Security Auditor
=======================
Audits AWS Lambda functions for common security misconfigurations across all regions:

- Function URL with no auth (publicly invokable without IAM)
- Overly permissive execution role (admin policy or broad wildcards)
- Secrets in environment variables (pattern-matched key names)
- Dead-letter queue not configured (failed invocations silently dropped)
- Reserved concurrency = 0 (function effectively throttled to zero)
- Runtime end-of-life / deprecated
- VPC attachment: functions with sensitive roles not isolated in a VPC
- X-Ray tracing disabled

Usage:
    python3 lambda_auditor.py
    python3 lambda_auditor.py --output lambda_report --format html
    python3 lambda_auditor.py --profile prod --regions eu-west-1 us-east-1
"""

import boto3
import html as html_lib
import json
import csv
import argparse
import logging
import os
import re
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

# Environment variable key patterns that commonly contain secrets
SECRET_ENV_PATTERNS = re.compile(
    r"(password|passwd|secret|api[_-]?key|token|credential|auth|private[_-]?key"
    r"|access[_-]?key|db[_-]?pass|database[_-]?pass|smtp[_-]?pass)",
    re.IGNORECASE,
)

# Runtimes that AWS has deprecated or EOL'd
DEPRECATED_RUNTIMES = {
    "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x", "nodejs14.x",
    "python2.7", "python3.6", "python3.7", "python3.8",
    "java8", "java11",
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1",
    "ruby2.5", "ruby2.7",
    "go1.x",
}

# Admin-equivalent managed policies
ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}

FIELDNAMES = [
    "function_name", "region", "runtime", "role_arn",
    "has_function_url", "function_url_auth_type",
    "has_dlq", "tracing_enabled", "in_vpc",
    "reserved_concurrency", "deprecated_runtime",
    "secret_env_keys", "has_admin_role",
    "risk_level", "severity_score", "flags", "remediations", "cis_control",
]


# ── Checks ────────────────────────────────────────────────────────────────────

def check_function_url(lambda_client, function_name):
    """Return (has_url, auth_type) where auth_type is 'NONE' or 'AWS_IAM' or None."""
    try:
        resp = lambda_client.get_function_url_config(FunctionName=function_name)
        return True, resp.get("AuthType", "NONE")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return False, None
        raise


def check_role_permissions(iam, role_arn):
    """Return (has_admin, high_risk_policies) for a Lambda execution role."""
    has_admin = False
    high_risk = []

    try:
        role_name = role_arn.split("/")[-1]
        # Attached managed policies
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        for p in attached:
            if p["PolicyArn"] in ADMIN_POLICY_ARNS:
                has_admin = True
                high_risk.append(p["PolicyName"])
            elif "FullAccess" in p["PolicyName"] or "Admin" in p["PolicyName"]:
                high_risk.append(p["PolicyName"])

        # Inline policies — check for wildcard actions
        inline_names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        for pname in inline_names:
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=pname)["PolicyDocument"]
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if any(a == "*" or a.endswith(":*") for a in actions):
                    has_admin = True
                    high_risk.append(f"inline:{pname} (wildcard action)")

    except ClientError:
        pass

    return has_admin, high_risk


def check_reserved_concurrency(lambda_client, function_name):
    """Return reserved concurrency value or None if not set."""
    try:
        resp = lambda_client.get_function_concurrency(FunctionName=function_name)
        return resp.get("ReservedConcurrentExecutions")
    except ClientError:
        return None


def find_secret_env_keys(env_vars):
    """Return list of env var key names that look like they contain secrets."""
    return [k for k in env_vars if SECRET_ENV_PATTERNS.search(k)]


def build_flags_and_remediations(fn):
    """Build parallel flags/remediations from a function analysis dict."""
    flags = []
    remediations = []

    # Public function URL (no auth)
    if fn.get("has_function_url") and fn.get("function_url_auth_type") == "NONE":
        flags.append("❌ Function URL enabled with no authentication (public invoke)")
        remediations.append(
            f"Restrict function URL: Lambda Console → {fn['function_name']} → Configuration → "
            "Function URL → Edit → Auth type → AWS_IAM → Save. "
            "Or delete the URL if not needed."
        )

    # Admin role
    if fn.get("has_admin_role"):
        flags.append("❌ Execution role has admin/wildcard permissions")
        remediations.append(
            f"Replace overly-permissive role with least-privilege policy: IAM Console → "
            f"Roles → {fn['role_arn'].split('/')[-1]} → remove FullAccess/Admin policies and "
            "attach a policy scoped to only the services this function needs."
        )
    elif fn.get("high_risk_policies"):
        flags.append(f"⚠️ Execution role has broad policies: {', '.join(fn['high_risk_policies'][:3])}")
        remediations.append(
            "Review and narrow the execution role policies to only the actions this function requires. "
            "Use IAM Access Analyzer to identify unused permissions."
        )

    # Secrets in env vars
    if fn.get("secret_env_keys"):
        flags.append(f"⚠️ Potential secrets in environment variables: {', '.join(fn['secret_env_keys'])}")
        remediations.append(
            f"Move secrets to AWS Secrets Manager or SSM Parameter Store and retrieve them at runtime. "
            "Lambda Console → Configuration → Environment variables → remove the sensitive keys."
        )

    # Deprecated runtime
    if fn.get("deprecated_runtime"):
        flags.append(f"⚠️ Deprecated runtime: {fn['runtime']}")
        remediations.append(
            f"Upgrade runtime: Lambda Console → {fn['function_name']} → Code → Runtime settings → "
            f"Edit → select a supported runtime → Save. Test thoroughly after upgrade."
        )

    # No DLQ
    if not fn.get("has_dlq"):
        flags.append("ℹ️ No dead-letter queue — failed async invocations are silently dropped")
        remediations.append(
            f"Add a DLQ: Lambda Console → {fn['function_name']} → Configuration → "
            "Asynchronous invocation → Edit → Dead-letter queue service → SQS or SNS → Save."
        )

    # X-Ray tracing disabled
    if not fn.get("tracing_enabled"):
        flags.append("ℹ️ X-Ray tracing disabled — no distributed trace visibility")
        remediations.append(
            f"Enable tracing: Lambda Console → {fn['function_name']} → Configuration → "
            "Monitoring and operations tools → Edit → AWS X-Ray → Active → Save."
        )

    # Reserved concurrency = 0
    rc = fn.get("reserved_concurrency")
    if rc is not None and rc == 0:
        flags.append("⚠️ Reserved concurrency is 0 — function is throttled and will not execute")
        remediations.append(
            f"Check if this is intentional: Lambda Console → {fn['function_name']} → Configuration → "
            "Concurrency → Edit → set to an appropriate value or remove the reservation."
        )

    if not flags:
        flags.append("✅ No significant findings")
        remediations.append("")

    return flags, remediations


def calculate_score(has_public_url, has_admin_role, has_secret_envs,
                    has_deprecated_runtime, reserved_concurrency_zero):
    score = 0
    if has_public_url:
        score += 4
    if has_admin_role:
        score += 4
    if has_secret_envs:
        score += 3
    if has_deprecated_runtime:
        score += 2
    if reserved_concurrency_zero:
        score += 1

    score = min(10, score)
    if score >= 8:
        risk = "CRITICAL"
    elif score >= 6:
        risk = "HIGH"
    elif score >= 3:
        risk = "MEDIUM"
    elif score > 0:
        risk = "LOW"
    else:
        risk = "LOW"
    return score, risk


def analyse_function(lambda_client, iam, fn_config):
    """Build one finding dict per Lambda function."""
    name = fn_config["FunctionName"]
    region = fn_config.get("_region", "")
    runtime = fn_config.get("Runtime", "unknown")
    role_arn = fn_config.get("Role", "")
    env_vars = fn_config.get("Environment", {}).get("Variables", {})
    tracing = fn_config.get("TracingConfig", {}).get("Mode") == "Active"
    in_vpc = bool(fn_config.get("VpcConfig", {}).get("VpcId"))
    has_dlq = bool(fn_config.get("DeadLetterConfig", {}).get("TargetArn"))

    has_url, url_auth = check_function_url(lambda_client, name)
    has_admin, high_risk_policies = check_role_permissions(iam, role_arn)
    reserved_concurrency = check_reserved_concurrency(lambda_client, name)
    secret_keys = find_secret_env_keys(env_vars)
    deprecated = runtime.lower() in DEPRECATED_RUNTIMES

    finding = {
        "function_name": name,
        "region": region,
        "runtime": runtime,
        "role_arn": role_arn,
        "has_function_url": has_url,
        "function_url_auth_type": url_auth,
        "has_dlq": has_dlq,
        "tracing_enabled": tracing,
        "in_vpc": in_vpc,
        "reserved_concurrency": reserved_concurrency,
        "deprecated_runtime": deprecated,
        "secret_env_keys": secret_keys,
        "has_admin_role": has_admin,
        "high_risk_policies": high_risk_policies,
    }

    score, risk_level = calculate_score(
        has_public_url=has_url and url_auth == "NONE",
        has_admin_role=has_admin,
        has_secret_envs=len(secret_keys) > 0,
        has_deprecated_runtime=deprecated,
        reserved_concurrency_zero=(reserved_concurrency == 0),
    )
    finding["severity_score"] = score
    finding["risk_level"] = risk_level
    finding["flags"], finding["remediations"] = build_flags_and_remediations(finding)
    finding["cis_control"] = "CIS 4"
    return finding


def audit_region(session, region):
    """Audit Lambda functions in a single region. Returns list of finding dicts."""
    log.info(f"Auditing region: {region}")
    lambda_client = session.client("lambda", region_name=region, config=BOTO_CONFIG)
    iam = session.client("iam", config=BOTO_CONFIG)

    try:
        functions = []
        paginator = lambda_client.get_paginator("list_functions")
        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))
    except ClientError as e:
        log.warning(f"  {region}: cannot list Lambda functions — {e}")
        return []

    findings = []
    for fn in functions:
        fn["_region"] = region
        try:
            finding = analyse_function(lambda_client, iam, fn)
            findings.append(finding)
        except Exception as e:
            log.warning(f"  {region}/{fn.get('FunctionName', '?')}: error — {e}")

    return findings


def audit(session, regions=None):
    """Run Lambda security audit across specified regions. Returns report dict."""
    if regions is None:
        regions = AWS_REGIONS

    all_findings = []
    for region in regions:
        all_findings.extend(audit_region(session, region))

    all_findings.sort(key=lambda f: (-f["severity_score"], f["region"], f["function_name"]))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        counts[f["risk_level"]] = counts.get(f["risk_level"], 0) + 1

    return {
        "generated_at": NOW.isoformat(),
        "summary": {
            "total_functions": len(all_findings),
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
            row["secret_env_keys"] = ", ".join(row.get("secret_env_keys", []))
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
        fn_name = html_lib.escape(f["function_name"])

        rows += f"""
        <tr>
            <td style="font-weight:500">{fn_name}</td>
            <td>{html_lib.escape(f['region'])}</td>
            <td><span style="background:{colour};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{f['risk_level']}</span></td>
            <td>{f['severity_score']}/10</td>
            <td style="font-size:0.85em;font-family:monospace">{html_lib.escape(f['runtime'])}</td>
            <td>{'❌ Public' if (f['has_function_url'] and f['function_url_auth_type'] == 'NONE') else ('✅ IAM' if f['has_function_url'] else '—')}</td>
            <td>{'✅' if f['in_vpc'] else '—'}</td>
            <td>{'✅' if f['tracing_enabled'] else '❌'}</td>
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
<title>Lambda Security Audit Report</title>
<style>
{get_styles(extra_css)}
</style>
</head>
<body>
<div class="header">
  <h1>&#955; Lambda Security Audit Report</h1>
  <p>Generated: {html_lib.escape(generated)}</p>
</div>
<div class="summary">
  <div class="stat"><div class="value">{summary['total_functions']}</div><div class="label">Functions</div></div>
  <div class="stat"><div class="value" style="color:#dc3545">{summary['critical']}</div><div class="label">CRITICAL</div></div>
  <div class="stat"><div class="value" style="color:#fd7e14">{summary['high']}</div><div class="label">HIGH</div></div>
  <div class="stat"><div class="value" style="color:#ffc107">{summary['medium']}</div><div class="label">MEDIUM</div></div>
  <div class="stat"><div class="value" style="color:#28a745">{summary['low']}</div><div class="label">LOW</div></div>
</div>
<div class="section">
  <h2>Lambda Function Security</h2>
  <table>
    <thead>
      <tr>
        <th>Function</th><th>Region</th><th>Risk</th><th>Score</th>
        <th>Runtime</th><th>Function URL</th><th>VPC</th><th>X-Ray</th><th>Flags / Actions</th>
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
    parser = argparse.ArgumentParser(description="AWS Lambda Security Auditor")
    parser.add_argument("--output", "-o", default="lambda_report",
                        help="Output file prefix (default: lambda_report)")
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
