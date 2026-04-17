#!/usr/bin/env python3
"""
AWS Config Auditor
==================
Audits AWS Config service across regions for common security misconfigurations:
- Config recorder enabled and recording
- Delivery channel configured
- Config recorder status (recording state and last status)
- Managed rules presence
- Non-compliant resources

Usage:
    python3 config_auditor.py
    python3 config_auditor.py --output report --format html
    python3 config_auditor.py --profile prod
    python3 config_auditor.py --regions us-east-1 eu-west-1
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


# -- Checks -------------------------------------------------------------------

def check_recorder(config_client, region):
    """Check if AWS Config recorder is enabled and recording all resources."""
    findings = []
    try:
        resp = config_client.describe_configuration_recorders()
        recorders = resp.get("ConfigurationRecorders", [])
        if not recorders:
            findings.append({
                "region": region,
                "resource": f"config-recorder/{region}",
                "check": "Config Recorder Enabled",
                "status": "FAIL",
                "severity": "CRITICAL",
                "risk_level": "CRITICAL",
                "severity_score": 9,
                "description": "AWS Config recorder not enabled in this region",
                "recommendation": "Enable AWS Config recorder to track resource configurations and changes",
                "cis_control": "CIS 3.5",
                "remediation": "Enable AWS Config recorder to track resource configurations and changes",
                "flags": ["No Config recorder configured"],
                "remediations": ["AWS Console -> Config -> Get started -> Enable recording"],
            })
        else:
            for rec in recorders:
                rg = rec.get("recordingGroup", {})
                all_supported = rg.get("allSupported", False)
                if not all_supported:
                    findings.append({
                        "region": region,
                        "resource": f"config-recorder/{rec.get('name', 'default')}",
                        "check": "Config Recorder Enabled",
                        "status": "FAIL",
                        "severity": "CRITICAL",
                        "risk_level": "CRITICAL",
                        "severity_score": 9,
                        "description": "AWS Config recorder not recording all supported resource types",
                        "recommendation": "Configure recorder to record all supported resource types",
                        "cis_control": "CIS 3.5",
                        "remediation": "Configure recorder to record all supported resource types",
                        "flags": ["Recorder not recording all resource types"],
                        "remediations": ["AWS Console -> Config -> Settings -> Edit -> Record all resources"],
                    })
                else:
                    findings.append({
                        "region": region,
                        "resource": f"config-recorder/{rec.get('name', 'default')}",
                        "check": "Config Recorder Enabled",
                        "status": "PASS",
                        "severity": "LOW",
                        "risk_level": "LOW",
                        "severity_score": 0,
                        "description": "AWS Config recorder is enabled and recording all resource types",
                        "recommendation": "No action required",
                        "cis_control": "CIS 3.5",
                        "remediation": "No action required",
                        "flags": ["Config recorder enabled and recording"],
                        "remediations": [],
                    })
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            log.warning(f"Access denied for describe_configuration_recorders in {region}")
            raise
        raise
    return findings


def check_delivery_channel(config_client, region):
    """Check if a Config delivery channel is configured."""
    findings = []
    try:
        resp = config_client.describe_delivery_channels()
        channels = resp.get("DeliveryChannels", [])
        if not channels:
            findings.append({
                "region": region,
                "resource": f"config-delivery-channel/{region}",
                "check": "Config Delivery Channel",
                "status": "FAIL",
                "severity": "HIGH",
                "risk_level": "HIGH",
                "severity_score": 7,
                "description": "No Config delivery channel configured",
                "recommendation": "Configure a delivery channel with an S3 bucket to store configuration snapshots",
                "cis_control": "CIS 3.5",
                "remediation": "Configure a delivery channel with an S3 bucket to store configuration snapshots",
                "flags": ["No delivery channel configured"],
                "remediations": ["AWS Console -> Config -> Settings -> Edit -> Set S3 bucket for delivery"],
            })
        else:
            findings.append({
                "region": region,
                "resource": f"config-delivery-channel/{channels[0].get('name', 'default')}",
                "check": "Config Delivery Channel",
                "status": "PASS",
                "severity": "LOW",
                "risk_level": "LOW",
                "severity_score": 0,
                "description": "Config delivery channel is configured",
                "recommendation": "No action required",
                "cis_control": "CIS 3.5",
                "remediation": "No action required",
                "flags": ["Delivery channel configured"],
                "remediations": [],
            })
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            log.warning(f"Access denied for describe_delivery_channels in {region}")
            raise
        raise
    return findings


def check_recorder_status(config_client, region):
    """Check if the Config recorder is actively recording and not in failure state."""
    findings = []
    try:
        resp = config_client.describe_configuration_recorder_status()
        statuses = resp.get("ConfigurationRecordersStatus", [])
        for status in statuses:
            recording = status.get("recording", False)
            last_status = status.get("lastStatus", "")
            recorder_name = status.get("name", "default")
            if not recording or last_status == "Failure":
                desc_parts = []
                if not recording:
                    desc_parts.append("recorder is not actively recording")
                if last_status == "Failure":
                    desc_parts.append(f"last status is {last_status}")
                findings.append({
                    "region": region,
                    "resource": f"config-recorder-status/{recorder_name}",
                    "check": "Config Recorder Status",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "risk_level": "HIGH",
                    "severity_score": 7,
                    "description": f"Config recorder issue: {'; '.join(desc_parts)}",
                    "recommendation": "Start the Config recorder and investigate delivery failures",
                    "cis_control": "CIS 3.5",
                    "remediation": "Start the Config recorder and investigate delivery failures",
                    "flags": [f"Recorder {recorder_name}: recording={recording}, lastStatus={last_status}"],
                    "remediations": ["AWS Console -> Config -> Settings -> Turn on recording"],
                })
            else:
                findings.append({
                    "region": region,
                    "resource": f"config-recorder-status/{recorder_name}",
                    "check": "Config Recorder Status",
                    "status": "PASS",
                    "severity": "LOW",
                    "risk_level": "LOW",
                    "severity_score": 0,
                    "description": "Config recorder is actively recording with no failures",
                    "recommendation": "No action required",
                    "cis_control": "CIS 3.5",
                    "remediation": "No action required",
                    "flags": ["Recorder actively recording"],
                    "remediations": [],
                })
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            log.warning(f"Access denied for describe_configuration_recorder_status in {region}")
            raise
        raise
    return findings


def check_config_rules(config_client, region):
    """Check if any Config rules are configured."""
    findings = []
    try:
        resp = config_client.describe_config_rules()
        rules = resp.get("ConfigRules", [])
        if len(rules) == 0:
            findings.append({
                "region": region,
                "resource": f"config-rules/{region}",
                "check": "Config Rules",
                "status": "FAIL",
                "severity": "HIGH",
                "risk_level": "HIGH",
                "severity_score": 6,
                "description": "No Config rules configured",
                "recommendation": "Add AWS Config managed rules or custom rules to evaluate resource compliance",
                "cis_control": "CIS 3.5",
                "remediation": "Add AWS Config managed rules or custom rules to evaluate resource compliance",
                "flags": ["No Config rules configured"],
                "remediations": ["AWS Console -> Config -> Rules -> Add rule"],
            })
        else:
            findings.append({
                "region": region,
                "resource": f"config-rules/{region}",
                "check": "Config Rules",
                "status": "PASS",
                "severity": "LOW",
                "risk_level": "LOW",
                "severity_score": 0,
                "description": f"{len(rules)} Config rule(s) configured",
                "recommendation": "No action required",
                "cis_control": "CIS 3.5",
                "remediation": "No action required",
                "flags": [f"{len(rules)} Config rule(s) active"],
                "remediations": [],
            })
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            log.warning(f"Access denied for describe_config_rules in {region}")
            raise
        raise
    return findings


def check_compliance(config_client, region):
    """Check for non-compliant Config rules."""
    findings = []
    try:
        resp = config_client.describe_compliance_by_config_rule(
            ComplianceTypes=["NON_COMPLIANT"]
        )
        non_compliant = resp.get("ComplianceByConfigRules", [])
        if non_compliant:
            count = len(non_compliant)
            rule_names = [r.get("ConfigRuleName", "unknown") for r in non_compliant[:5]]
            findings.append({
                "region": region,
                "resource": f"config-compliance/{region}",
                "check": "Config Rule Compliance",
                "status": "FAIL",
                "severity": "MEDIUM",
                "risk_level": "MEDIUM",
                "severity_score": 5,
                "description": f"{count} Config rule(s) have non-compliant resources",
                "recommendation": "Review and remediate non-compliant resources for each failing rule",
                "cis_control": "CIS 3.5",
                "remediation": "Review and remediate non-compliant resources for each failing rule",
                "flags": [f"{count} non-compliant rule(s): {', '.join(rule_names)}"],
                "remediations": ["AWS Console -> Config -> Rules -> Review non-compliant rules"],
            })
        else:
            findings.append({
                "region": region,
                "resource": f"config-compliance/{region}",
                "check": "Config Rule Compliance",
                "status": "PASS",
                "severity": "LOW",
                "risk_level": "LOW",
                "severity_score": 0,
                "description": "All Config rules are compliant",
                "recommendation": "No action required",
                "cis_control": "CIS 3.5",
                "remediation": "No action required",
                "flags": ["All rules compliant"],
                "remediations": [],
            })
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            log.warning(f"Access denied for describe_compliance_by_config_rule in {region}")
            raise
        # NoSuchConfigRuleException means no rules exist, skip gracefully
        if e.response["Error"]["Code"] == "NoSuchConfigRuleException":
            return findings
        raise
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
        color = risk_colors.get(f["risk_level"], "#999")

        flag_items = []
        for flag, rem in zip(f.get("flags", []), f.get("remediations", [])):
            flag_items.append(
                f'<div class="flag-item">'
                f'<span class="flag-text">{html_lib.escape(flag)}</span>'
                f'<span class="rem-text">{html_lib.escape(rem)}</span>'
                f'</div>'
            )
        flags_list = f.get("flags", [])
        rems_list = f.get("remediations", [])
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
            <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{f['risk_level']}</span></td>
            <td style="font-weight:bold">{f['severity_score']}/10</td>
            <td>{check_escaped}</td>
            <td style="font-family:monospace;font-size:0.85em">{resource_escaped}</td>
            <td>{region_escaped}</td>
            <td>{'PASS' if f['status'] == 'PASS' else 'FAIL'}</td>
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
<title>AWS Config Audit Report</title>
<style>
{get_styles(extra_css)}
</style>
</head>
<body>
<div class="header">
  <h1>AWS Config Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; {summary['total_findings']} findings across {summary['regions_scanned']} region(s)</p>
</div>
<div class="summary">
  <div class="card total"><div class="num">{summary['total_findings']}</div><div class="label">Total Findings</div></div>
  <div class="card critical"><div class="num">{summary['critical']}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{summary['high']}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{summary['medium']}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{summary['low']}</div><div class="label">Low</div></div>
  <div class="card" style="border-left:4px solid #28a745"><div class="num" style="color:#28a745">{summary['pass_count']}</div><div class="label">Passed</div></div>
  <div class="card" style="border-left:4px solid #dc3545"><div class="num" style="color:#dc3545">{summary['fail_count']}</div><div class="label">Failed</div></div>
</div>
<div class="table-wrap">
  <table>
    <thead>
      <tr><th>Risk</th><th>Score</th><th>Check</th><th>Resource</th><th>Region</th><th>Status</th><th>Description</th><th>Flags / Remediation</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">AWS Config Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html_content)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")


# -- Main ---------------------------------------------------------------------

def run(output_prefix="config_report", fmt="all", regions=None, profile=None):
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
            config_client = session.client("config", region_name=region, config=BOTO_CONFIG)

            findings.extend(check_recorder(config_client, region))
            findings.extend(check_delivery_channel(config_client, region))
            findings.extend(check_recorder_status(config_client, region))
            findings.extend(check_config_rules(config_client, region))
            findings.extend(check_compliance(config_client, region))

        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AccessDeniedException":
                log.warning(f"Access denied in region {region}, skipping")
                continue
            if code in ("ThrottlingException", "RequestLimitExceeded"):
                log.warning(f"Throttled in region {region} — partial scan; retry later")
                findings.append({
                    "region": region,
                    "resource": f"config/{region}",
                    "check": "Config Scan (throttled)",
                    "status": "UNKNOWN",
                    "severity": "MEDIUM",
                    "risk_level": "MEDIUM",
                    "severity_score": 3,
                    "description": f"AWS Config scan throttled in {region}; results may be incomplete",
                    "recommendation": "Re-run audit in this region after a brief delay",
                    "cis_control": "CIS 3.5",
                    "remediation": "Re-run audit — transient throttle, not a configuration issue",
                    "flags": [f"⚠️ Throttled scanning {region} — partial results"],
                    "remediations": ["Re-run audit after a brief delay to get complete results"],
                })
                continue
            log.warning(f"Could not scan region {region}: {e}")
            continue

    findings.sort(key=lambda x: x["severity_score"], reverse=True)

    fail_findings = [f for f in findings if f["status"] == "FAIL"]
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in fail_findings:
        risk_counts[f["risk_level"]] = risk_counts.get(f["risk_level"], 0) + 1

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
            "pass_count": sum(1 for f in findings if f["status"] == "PASS"),
            "fail_count": sum(1 for f in findings if f["status"] == "FAIL"),
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
|       CONFIG AUDITOR -- SUMMARY          |
+==========================================+
|  Regions scanned:     {s['regions_scanned']:<20}|
|  Total findings:      {s['total_findings']:<20}|
|  CRITICAL:            {s['critical']:<20}|
|  HIGH:                {s['high']:<20}|
|  MEDIUM:              {s['medium']:<20}|
|  LOW:                 {s['low']:<20}|
|  Passed:              {s['pass_count']:<20}|
|  Failed:              {s['fail_count']:<20}|
+==========================================+
""")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWS Config Auditor")
    parser.add_argument("--output", "-o", default="config_report",
                        help="Output file prefix (default: config_report)")
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
