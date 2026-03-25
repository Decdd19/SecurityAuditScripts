#!/usr/bin/env python3
"""
ELB (Elastic Load Balancer) Auditor
=====================================
Audits Application Load Balancers (ALB) and Network Load Balancers (NLB)
for common security misconfigurations:
- Access logging to S3 enabled
- Deletion protection enabled
- HTTP→HTTPS redirect configured (ALB only)
- SSL/TLS policy up to date (ALB HTTPS / NLB TLS listeners)
- WAF WebACL association (ALB only)
- Internet-facing vs internal scheme (informational)

Usage:
    python3 elb_auditor.py
    python3 elb_auditor.py --output report --format all
    python3 elb_auditor.py --format html
    python3 elb_auditor.py --profile prod --regions eu-west-1 us-east-1
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

OUTDATED_SSL_POLICIES = {
    "ELBSecurityPolicy-2016-08",
    "ELBSecurityPolicy-TLS-1-0-2015-04",
    "ELBSecurityPolicy-TLS-1-1-2017-01",
}

RECOMMENDED_SSL_POLICY = "ELBSecurityPolicy-TLS13-1-2-2021-06"

FIELDNAMES = [
    "lb_name", "lb_arn", "lb_type", "scheme", "region", "vpc_id", "state",
    "access_logs_enabled", "deletion_protection", "http_redirect_to_https",
    "has_http_listener", "outdated_ssl_policy", "ssl_policies_found",
    "waf_associated", "severity_score", "risk_level", "flags", "remediations",
]


# ── Scoring ───────────────────────────────────────────────────────────────────

def calculate_score(no_access_logs, no_deletion_protection, http_no_redirect,
                    outdated_ssl_policy, no_waf, lb_type):
    score = 0
    if http_no_redirect and lb_type == "application":
        score += 3   # HIGH — cleartext traffic
    if outdated_ssl_policy:
        score += 3   # HIGH — weak TLS
    if no_access_logs:
        score += 2   # MEDIUM
    if no_waf and lb_type == "application":
        score += 2   # MEDIUM
    if no_deletion_protection:
        score += 1   # LOW
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


# ── Per-LB checks ─────────────────────────────────────────────────────────────

def check_access_logs(attributes):
    """Return True if S3 access logging is enabled."""
    attr_map = {a["Key"]: a["Value"] for a in attributes}
    return attr_map.get("access_logs.s3.enabled", "false").lower() == "true"


def check_deletion_protection(attributes):
    """Return True if deletion protection is enabled."""
    attr_map = {a["Key"]: a["Value"] for a in attributes}
    return attr_map.get("deletion_protection.enabled", "false").lower() == "true"


def check_http_redirect(listeners):
    """
    For ALB: check if a port-80 listener exists and redirects to HTTPS.
    Returns (has_http_listener: bool, redirects_to_https: bool).
    """
    http_listeners = [ln for ln in listeners if ln.get("Port") == 80]
    if not http_listeners:
        return False, None  # No HTTP listener — not applicable
    for listener in http_listeners:
        actions = listener.get("DefaultActions", [])
        for action in actions:
            if action.get("Type") == "redirect":
                redirect_cfg = action.get("RedirectConfig", {})
                if redirect_cfg.get("Protocol", "").upper() == "HTTPS":
                    return True, True  # Has HTTP listener and it redirects
        # HTTP listener exists but no HTTPS redirect found
        return True, False
    return True, False


def check_ssl_policy(listeners, lb_type):
    """
    Check SSL/TLS policies on HTTPS (ALB) or TLS (NLB) listeners.
    Returns (has_outdated: bool, policies_found: list[str]).
    """
    relevant_protocols = {"HTTPS"} if lb_type == "application" else {"TLS"}
    policies_found = []
    has_outdated = False
    for listener in listeners:
        protocol = listener.get("Protocol", "").upper()
        if protocol in relevant_protocols:
            policy = listener.get("SslPolicy", "")
            if policy:
                policies_found.append(policy)
                if policy in OUTDATED_SSL_POLICIES:
                    has_outdated = True
    return has_outdated, policies_found


def check_waf_association(wafv2_client, lb_arn):
    """Return True if the ALB has a WAF WebACL associated."""
    try:
        acls = wafv2_client.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
        for acl in acls:
            try:
                resources = wafv2_client.list_resources_by_web_acl(
                    WebACLArn=acl["ARN"],
                    ResourceType="APPLICATION_LOAD_BALANCER"
                ).get("ResourceArns", [])
                if lb_arn in resources:
                    return True
            except ClientError:
                continue
        return False
    except ClientError:
        return False  # If WAFv2 not available, treat as no WAF (informational)


# ── Analyse LB ────────────────────────────────────────────────────────────────

def analyse_lb(elbv2_client, wafv2_client, lb, region):
    """Analyse a single load balancer and return a findings dict."""
    lb_arn = lb["LoadBalancerArn"]
    lb_name = lb["LoadBalancerName"]
    lb_type = lb["Type"]  # "application" | "network" | "gateway"
    scheme = lb.get("Scheme", "")
    state = lb.get("State", {}).get("Code", "unknown")
    vpc_id = lb.get("VpcId", "")

    log.info(f"  LB: {lb_name} ({lb_type}, {scheme})")

    # Fetch listeners
    try:
        listeners_resp = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)
        listeners = listeners_resp.get("Listeners", [])
    except ClientError as e:
        log.warning(f"Could not describe listeners for {lb_name}: {e}")
        listeners = []

    # Fetch attributes
    try:
        attrs_resp = elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
        attributes = attrs_resp.get("Attributes", [])
    except ClientError as e:
        log.warning(f"Could not describe attributes for {lb_name}: {e}")
        attributes = []

    access_logs_enabled = check_access_logs(attributes)
    deletion_protection = check_deletion_protection(attributes)

    # HTTP redirect check (ALB only)
    if lb_type == "application":
        has_http_listener, http_redirect_to_https = check_http_redirect(listeners)
    else:
        has_http_listener = False
        http_redirect_to_https = None  # Not applicable for NLB

    # SSL policy check
    outdated_ssl_policy, ssl_policies_found = check_ssl_policy(listeners, lb_type)

    # WAF check (ALB only)
    if lb_type == "application":
        waf_associated = check_waf_association(wafv2_client, lb_arn)
    else:
        waf_associated = None  # Not applicable for NLB

    # Build flags and remediations
    flags = []
    remediations = []

    if not access_logs_enabled:
        flags.append("⚠️ Access logging to S3 is not enabled")
        remediations.append(
            "Enable access logging: ELB Console → Load Balancer → Attributes → "
            "Access logs → Enable → specify an S3 bucket with appropriate bucket policy"
        )

    if lb_type == "application" and has_http_listener and http_redirect_to_https is False:
        flags.append("❌ HTTP listener (port 80) does not redirect to HTTPS")
        remediations.append(
            "Add HTTPS redirect: ELB Console → Listeners → port 80 → Edit → "
            "Default action → Redirect → HTTPS 443 → Save. "
            "Alternatively add a redirect rule via the AWS CLI: "
            "aws elbv2 modify-listener --default-actions Type=redirect,RedirectConfig={Protocol=HTTPS,Port=443,StatusCode=HTTP_301}"
        )

    if outdated_ssl_policy:
        policies_str = ", ".join(ssl_policies_found)
        flags.append(f"❌ Outdated SSL/TLS security policy in use: {policies_str}")
        remediations.append(
            f"Update SSL policy: ELB Console → Listeners → HTTPS/TLS listener → Edit → "
            f"Security policy → {RECOMMENDED_SSL_POLICY} (or ELBSecurityPolicy-FS-1-2-Res-2020-10). "
            "Apply to all HTTPS/TLS listeners."
        )

    if lb_type == "application" and not waf_associated:
        flags.append("⚠️ No WAF WebACL associated with this ALB")
        remediations.append(
            "Associate a WAF WebACL: AWS WAF Console → Web ACLs → select or create ACL → "
            "Associated AWS resources → Add → select this load balancer. "
            "Alternatively: aws wafv2 associate-web-acl --web-acl-arn <arn> --resource-arn <lb-arn>"
        )

    if not deletion_protection:
        flags.append("⚠️ Deletion protection is not enabled")
        remediations.append(
            "Enable deletion protection: ELB Console → Load Balancer → Attributes → "
            "Deletion protection → Enable → Save changes"
        )

    if scheme == "internet-facing":
        flags.append("ℹ️ Load balancer is internet-facing (verify this is intentional)")
        remediations.append(
            "Confirm that internet-facing exposure is required. "
            "If only internal consumers are needed, recreate as an internal LB. "
            "Ensure security groups (ALB) or NACLs restrict inbound traffic to expected sources."
        )

    # NOTE: ✅ (positive) flags appended last, no matching remediations.
    # The HTML renderer's fallback (flags_list[len(rems_list):]) depends on this ordering.
    if access_logs_enabled:
        flags.append("✅ Access logging enabled")
    if deletion_protection:
        flags.append("✅ Deletion protection enabled")
    if lb_type == "application" and waf_associated:
        flags.append("✅ WAF WebACL associated")
    if lb_type == "application" and has_http_listener and http_redirect_to_https:
        flags.append("✅ HTTP→HTTPS redirect configured")
    if lb_type == "application" and not has_http_listener:
        flags.append("✅ No unprotected HTTP listener on port 80")
    if ssl_policies_found and not outdated_ssl_policy:
        flags.append("✅ SSL/TLS policy is up to date")

    # Scoring
    http_no_redirect = lb_type == "application" and has_http_listener and http_redirect_to_https is False
    no_waf = lb_type == "application" and not waf_associated

    score, risk_level = calculate_score(
        no_access_logs=not access_logs_enabled,
        no_deletion_protection=not deletion_protection,
        http_no_redirect=http_no_redirect,
        outdated_ssl_policy=outdated_ssl_policy,
        no_waf=no_waf,
        lb_type=lb_type,
    )

    return {
        "lb_name": lb_name,
        "lb_arn": lb_arn,
        "lb_type": lb_type,
        "scheme": scheme,
        "region": region,
        "vpc_id": vpc_id,
        "state": state,
        "access_logs_enabled": access_logs_enabled,
        "deletion_protection": deletion_protection,
        "http_redirect_to_https": http_redirect_to_https,
        "has_http_listener": has_http_listener,
        "outdated_ssl_policy": outdated_ssl_policy,
        "ssl_policies_found": ssl_policies_found,
        "waf_associated": waf_associated,
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
            row["ssl_policies_found"] = "; ".join(finding.get("ssl_policies_found", []))
            writer.writerow(row)
    os.chmod(path, 0o600)
    log.info(f"CSV report: {path}")


def write_html(report, path):
    findings = report.get("findings", [])
    summary = report.get("summary", {})
    generated = report.get("generated_at", "")

    risk_colors = {
        "CRITICAL": "#c0392b",
        "HIGH": "#e67e22",
        "MEDIUM": "#f39c12",
        "LOW": "#27ae60",
    }

    rows = ""
    for f in findings:
        risk = f["risk_level"]
        colour = risk_colors.get(risk, "#6c757d")
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
        flags_html = "".join(flag_items) or "None"

        lb_type = f.get("lb_type", "")
        scheme = f.get("scheme", "")
        scheme_badge = (
            '<span style="background:#c0392b;color:white;padding:1px 6px;border-radius:3px">internet-facing</span>'
            if scheme == "internet-facing"
            else '<span style="background:#27ae60;color:white;padding:1px 6px;border-radius:3px">internal</span>'
        )
        tls_cell = "✅" if (f.get("ssl_policies_found") and not f.get("outdated_ssl_policy")) else ("❌" if f.get("outdated_ssl_policy") else "—")
        redirect_val = f.get("http_redirect_to_https")
        if redirect_val is None:
            redirect_cell = "—"
        elif redirect_val:
            redirect_cell = "✅"
        else:
            redirect_cell = "❌"
        waf_val = f.get("waf_associated")
        if waf_val is None:
            waf_cell = "—"
        elif waf_val:
            waf_cell = "✅"
        else:
            waf_cell = "❌"

        rows += (
            f'<tr>'
            f'<td><span style="background:{colour};color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:0.8em">{risk}</span></td>'
            f'<td style="font-weight:bold">{f["severity_score"]}/10</td>'
            f'<td><code>{html_lib.escape(f["lb_name"])}</code></td>'
            f'<td>{html_lib.escape(lb_type)}</td>'
            f'<td>{html_lib.escape(f.get("region",""))}</td>'
            f'<td>{scheme_badge}</td>'
            f'<td>{"✅" if f.get("access_logs_enabled") else "❌"}</td>'
            f'<td>{tls_cell}</td>'
            f'<td>{redirect_cell}</td>'
            f'<td>{waf_cell}</td>'
            f'<td style="font-size:0.8em">{flags_html}</td>'
            f'</tr>\n'
        )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Load Balancer Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f5f6fa; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #232f3e, #ff9900); color: white; padding: 30px 40px; }}
  .header h1 {{ margin: 0; font-size: 1.8em; }}
  .header p {{ margin: 5px 0 0; opacity: 0.8; }}
  .summary {{ display: flex; gap: 20px; padding: 20px 40px; flex-wrap: wrap; background: white; border-bottom: 1px solid #e0e0e0; }}
  .card {{ border-left: 4px solid #ccc; padding: 12px 20px; min-width: 120px; }}
  .card .num {{ font-size: 2em; font-weight: 700; }}
  .card .label {{ font-size: 0.8em; color: #666; text-transform: uppercase; }}
  .card.critical {{ border-left-color: #c0392b; }} .card.critical .num {{ color: #c0392b; }}
  .card.high {{ border-left-color: #e67e22; }} .card.high .num {{ color: #e67e22; }}
  .card.medium {{ border-left-color: #f39c12; }} .card.medium .num {{ color: #856404; }}
  .card.low {{ border-left-color: #27ae60; }} .card.low .num {{ color: #27ae60; }}
  .table-wrap {{ padding: 24px 40px 40px; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,.06); }}
  th {{ background: #232f3e; color: white; padding: 10px 14px; text-align: left; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }}
  td {{ padding: 10px 14px; border-bottom: 1px solid #f0f0f0; font-size: 0.88em; vertical-align: top; }}
  tr:hover td {{ background: #fafbff; }}
  .footer {{ text-align: center; padding: 20px; color: #999; font-size: 0.85em; }}
  .flag-item {{ margin-bottom: 6px; }}
  .flag-text {{ display: block; font-size: 0.85em; }}
  .rem-text {{ display: block; font-size: 0.78em; color: #555; padding-left: 12px; font-style: italic; }}
</style>
</head>
<body>
<div class="header">
  <h1>&#x2696;&#xFE0F; Load Balancer Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; {summary.get('total_load_balancers', 0)} load balancers analysed</p>
</div>
<div class="summary">
  <div class="card" style="border-left-color:#3498db"><div class="num" style="color:#3498db">{summary.get('total_load_balancers', 0)}</div><div class="label">Total LBs</div></div>
  <div class="card critical"><div class="num">{summary.get('critical', 0)}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{summary.get('high', 0)}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{summary.get('medium', 0)}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{summary.get('low', 0)}</div><div class="label">Low</div></div>
  <div class="card" style="border-left-color:#c0392b"><div class="num" style="color:#c0392b">{summary.get('no_access_logs', 0)}</div><div class="label">No Access Logs</div></div>
  <div class="card" style="border-left-color:#e74c3c"><div class="num" style="color:#e74c3c">{summary.get('http_no_redirect', 0)}</div><div class="label">HTTP No Redirect</div></div>
  <div class="card" style="border-left-color:#e67e22"><div class="num" style="color:#e67e22">{summary.get('outdated_ssl_policy', 0)}</div><div class="label">Outdated TLS</div></div>
  <div class="card" style="border-left-color:#f39c12"><div class="num" style="color:#f39c12">{summary.get('no_waf', 0)}</div><div class="label">No WAF</div></div>
</div>
<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Risk</th><th>Score</th><th>Name</th><th>Type</th><th>Region</th>
        <th>Scheme</th><th>Access Logs</th><th>TLS</th><th>HTTP&#x2192;HTTPS</th><th>WAF</th><th>Flags</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">ELB Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html_content)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(output_prefix="elb_report", fmt="all", profile=None, regions=None):
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
            elbv2_client = session.client("elbv2", region_name=region, config=BOTO_CONFIG)
            wafv2_client = session.client("wafv2", region_name=region, config=BOTO_CONFIG)
            paginator = elbv2_client.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    lb_type = lb.get("Type", "")
                    if lb_type == "gateway":
                        log.info(f"  Skipping gateway LB: {lb.get('LoadBalancerName')}")
                        continue
                    finding = analyse_lb(elbv2_client, wafv2_client, lb, region)
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
            "total_load_balancers": len(all_findings),
            "critical": risk_counts.get("CRITICAL", 0),
            "high": risk_counts.get("HIGH", 0),
            "medium": risk_counts.get("MEDIUM", 0),
            "low": risk_counts.get("LOW", 0),
            "no_access_logs": sum(1 for f in all_findings if not f["access_logs_enabled"]),
            "http_no_redirect": sum(
                1 for f in all_findings
                if f["lb_type"] == "application" and f["has_http_listener"]
                and f["http_redirect_to_https"] is False
            ),
            "outdated_ssl_policy": sum(1 for f in all_findings if f["outdated_ssl_policy"]),
            "no_waf": sum(
                1 for f in all_findings
                if f["lb_type"] == "application" and not f["waf_associated"]
            ),
        },
        "findings": all_findings,
    }

    if fmt in ("json", "all"):
        write_json(report, f"{output_prefix}.json")
    if fmt in ("csv", "all"):
        write_csv(all_findings, f"{output_prefix}.csv")
    if fmt in ("html", "all"):
        write_html(report, f"{output_prefix}.html")
    if fmt == "stdout":
        print(json.dumps(report, indent=2, default=str))

    s = report["summary"]
    print(f"""
╔══════════════════════════════════════════╗
║       ELB AUDITOR — SUMMARY              ║
╠══════════════════════════════════════════╣
║  Total load balancers:    {s['total_load_balancers']:<20}║
║  CRITICAL:                {s['critical']:<20}║
║  HIGH:                    {s['high']:<20}║
║  MEDIUM:                  {s['medium']:<20}║
║  LOW:                     {s['low']:<20}║
║  No access logs:          {s['no_access_logs']:<20}║
║  HTTP without redirect:   {s['http_no_redirect']:<20}║
║  Outdated SSL policy:     {s['outdated_ssl_policy']:<20}║
║  No WAF:                  {s['no_waf']:<20}║
╚══════════════════════════════════════════╝
""")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ELB (ALB/NLB) Security Auditor")
    parser.add_argument("--output", "-o", default="elb_report",
                        help="Output file prefix (default: elb_report)")
    parser.add_argument("--format", "-f",
                        choices=["json", "csv", "html", "all", "stdout"],
                        default="all",
                        help="Output format (default: all)")
    parser.add_argument("--profile", default=None,
                        help="AWS CLI profile name to use")
    parser.add_argument("--regions", nargs="+", default=None,
                        help="Specific regions to scan (default: all supported regions)")
    args = parser.parse_args()
    run(output_prefix=args.output, fmt=args.format,
        profile=args.profile, regions=args.regions)
