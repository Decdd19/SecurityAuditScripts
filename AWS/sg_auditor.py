"""
Security Group Auditor
======================
Audits all EC2 security groups across all AWS regions for:
- Open ingress to the world (0.0.0.0/0 or ::/0)
- Unrestricted SSH (port 22) and RDP (port 3389)
- Dangerous port exposure (databases, admin interfaces)
- Overly permissive egress rules
- Unused security groups
- Default security group misuse

Usage:
    python3 sg_auditor.py
    python3 sg_auditor.py --output report --format all
    python3 sg_auditor.py --region eu-west-1
    python3 sg_auditor.py --format csv --profile prod
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

# Ports considered high risk if open to the world
HIGH_RISK_PORTS = {
    22:    "SSH",
    3389:  "RDP",
    23:    "Telnet",
    21:    "FTP",
    1433:  "MSSQL",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    27017: "MongoDB",
    6379:  "Redis",
    9200:  "Elasticsearch",
    2375:  "Docker (unencrypted)",
    2379:  "etcd",
    8080:  "HTTP Alt",
    8443:  "HTTPS Alt",
    445:   "SMB",
    135:   "RPC",
    5900:  "VNC",
}

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


# ── Scoring ───────────────────────────────────────────────────────────────────

def calculate_score(open_ssh, open_rdp, all_traffic_open, high_risk_ports,
                    is_default, unrestricted_egress, open_port_count):
    score = 0
    if all_traffic_open:
        score += 6
    elif open_ssh or open_rdp:
        score += 4
    elif high_risk_ports:
        score += min(len(high_risk_ports), 3)
    if is_default and open_port_count > 0:
        score += 2
    if unrestricted_egress:
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


# ── Rule analysis ─────────────────────────────────────────────────────────────

def is_open_to_world(rule):
    """Return True if this rule allows traffic from 0.0.0.0/0 or ::/0."""
    for cidr in rule.get("IpRanges", []):
        if cidr.get("CidrIp") in OPEN_CIDRS:
            return True
    for cidr in rule.get("Ipv6Ranges", []):
        if cidr.get("CidrIpv6") in OPEN_CIDRS:
            return True
    return False


def port_in_range(port, from_port, to_port):
    """Check if a port falls within a rule's port range."""
    if from_port == -1 and to_port == -1:
        return True  # All traffic
    return from_port <= port <= to_port


def analyse_rules(rules):
    """Analyse ingress rules and return findings."""
    open_ports = []
    high_risk_open = []
    all_traffic = False
    open_ssh = False
    open_rdp = False

    for rule in rules:
        if not is_open_to_world(rule):
            continue

        protocol = rule.get("IpProtocol", "")
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)

        if protocol == "-1":
            all_traffic = True
            open_ports.append("All traffic (0.0.0.0/0)")
            high_risk_open = list(HIGH_RISK_PORTS.values())
            break

        for port, service in HIGH_RISK_PORTS.items():
            if port_in_range(port, from_port, to_port):
                high_risk_open.append(f"{port}/{service}")
                if port == 22:
                    open_ssh = True
                if port == 3389:
                    open_rdp = True

        if not (from_port == to_port and from_port in HIGH_RISK_PORTS):
            if from_port != to_port:
                open_ports.append(f"Port range {from_port}-{to_port} open to world")
            else:
                open_ports.append(f"Port {from_port} open to world")

    return open_ports, high_risk_open, all_traffic, open_ssh, open_rdp


def check_egress(rules):
    for rule in rules:
        if is_open_to_world(rule) and rule.get("IpProtocol") == "-1":
            return True
    return False


# ── Analyse security group ────────────────────────────────────────────────────

def analyse_sg(ec2, sg, region, attached_resources):
    sg_id = sg["GroupId"]
    sg_name = sg["GroupName"]
    vpc_id = sg.get("VpcId", "EC2-Classic")
    is_default = sg_name == "default"
    description = sg.get("Description", "")

    ingress = sg.get("IpPermissions", [])
    egress = sg.get("IpPermissionsEgress", [])

    open_ports, high_risk_open, all_traffic, open_ssh, open_rdp = analyse_rules(ingress)
    unrestricted_egress = check_egress(egress)
    is_attached = sg_id in attached_resources

    flags = []
    if all_traffic:
        flags.append("❌ All inbound traffic open to 0.0.0.0/0")
    if open_ssh:
        flags.append("❌ SSH (22) open to the world")
    if open_rdp:
        flags.append("❌ RDP (3389) open to the world")
    for p in high_risk_open:
        if p not in ["SSH", "RDP"]:
            flags.append(f"⚠️ {p} open to the world")
    if is_default and open_ports:
        flags.append("⚠️ Default security group has open rules (best practice: keep default empty)")
    if unrestricted_egress:
        flags.append("ℹ️ Unrestricted outbound traffic (0.0.0.0/0) — consider restricting")
    if not is_attached:
        flags.append("ℹ️ Security group is not attached to any resource")
    if not flags:
        flags.append("✅ No world-open ingress rules detected")

    score, risk_level = calculate_score(
        open_ssh, open_rdp, all_traffic, high_risk_open,
        is_default, unrestricted_egress, len(open_ports)
    )

    return {
        "group_id": sg_id,
        "group_name": sg_name,
        "vpc_id": vpc_id,
        "region": region,
        "description": description,
        "risk_level": risk_level,
        "severity_score": score,
        "is_default": is_default,
        "is_attached": is_attached,
        "all_traffic_open": all_traffic,
        "open_ssh": open_ssh,
        "open_rdp": open_rdp,
        "high_risk_ports_open": high_risk_open,
        "open_port_findings": open_ports,
        "unrestricted_egress": unrestricted_egress,
        "ingress_rule_count": len(ingress),
        "egress_rule_count": len(egress),
        "flags": flags,
    }


def get_attached_resources(ec2):
    """Get set of security group IDs that are actually attached to something."""
    attached = set()
    try:
        paginator = ec2.get_paginator("describe_network_interfaces")
        for page in paginator.paginate():
            for eni in page["NetworkInterfaces"]:
                for group in eni.get("Groups", []):
                    attached.add(group["GroupId"])
    except ClientError:
        pass
    return attached


# ── Output formatters ─────────────────────────────────────────────────────────

def write_json(report, path):
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    log.info(f"JSON report: {path}")


def write_csv(findings, path):
    if not findings:
        return
    fieldnames = [
        "group_id", "group_name", "vpc_id", "region", "description",
        "risk_level", "severity_score", "is_default", "is_attached",
        "all_traffic_open", "open_ssh", "open_rdp",
        "high_risk_ports_open", "open_port_findings",
        "unrestricted_egress", "ingress_rule_count", "egress_rule_count", "flags",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            row = finding.copy()
            for field in ["high_risk_ports_open", "open_port_findings", "flags"]:
                val = row.get(field, [])
                row[field] = "; ".join(val) if isinstance(val, list) else (val or "")
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
        ports_html = "<br>".join(f.get("high_risk_ports_open", [])) or "None"
        rows += f"""
        <tr>
            <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{f['risk_level']}</span></td>
            <td style="font-weight:bold">{f['severity_score']}/10</td>
            <td><code>{f['group_id']}</code></td>
            <td>{f['group_name']}</td>
            <td>{f['vpc_id']}</td>
            <td>{f['region']}</td>
            <td>{'⚠️ Default' if f['is_default'] else '—'}</td>
            <td>{'✅' if f['is_attached'] else '❌ Unused'}</td>
            <td>{'❌ YES' if f['all_traffic_open'] else ('⚠️ SSH' if f['open_ssh'] else ('⚠️ RDP' if f['open_rdp'] else '✅'))}</td>
            <td style="font-size:0.8em;color:#c0392b">{ports_html}</td>
            <td style="font-size:0.8em">{flags_html}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Group Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f5f6fa; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #2c3e50, #e74c3c); color: white; padding: 30px 40px; }}
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
  code {{ background: #ecf0f1; padding: 2px 5px; border-radius: 3px; font-size: 0.85em; }}
  .footer {{ text-align: center; padding: 20px; color: #999; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ Security Group Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; {summary['total_groups']} security groups analysed across {summary['regions_scanned']} regions</p>
</div>
<div class="summary">
  <div class="card total"><div class="num">{summary['total_groups']}</div><div class="label">Total Groups</div></div>
  <div class="card critical"><div class="num">{summary['critical']}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{summary['high']}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{summary['medium']}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{summary['low']}</div><div class="label">Low</div></div>
  <div class="card" style="border-left:4px solid #c0392b"><div class="num" style="color:#c0392b">{summary['open_ssh']}</div><div class="label">SSH Open to World</div></div>
  <div class="card" style="border-left:4px solid #e74c3c"><div class="num" style="color:#e74c3c">{summary['open_rdp']}</div><div class="label">RDP Open to World</div></div>
  <div class="card" style="border-left:4px solid #e67e22"><div class="num" style="color:#e67e22">{summary['all_traffic_open']}</div><div class="label">All Traffic Open</div></div>
  <div class="card" style="border-left:4px solid #95a5a6"><div class="num" style="color:#95a5a6">{summary['unused_groups']}</div><div class="label">Unused Groups</div></div>
</div>
<div class="table-wrap">
  <table>
    <thead>
      <tr><th>Risk</th><th>Score</th><th>ID</th><th>Name</th><th>VPC</th><th>Region</th><th>Default</th><th>Attached</th><th>World Open</th><th>High-Risk Ports</th><th>Flags</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">Security Group Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    log.info(f"HTML report: {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(output_prefix="sg_report", fmt="all", profile=None, region=None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()

    account_id = None
    try:
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        log.info(f"Account ID: {account_id}")
    except ClientError:
        log.warning("Could not determine account ID")

    # Determine regions to scan
    if region:
        regions = [region]
    else:
        try:
            ec2_base = session.client("ec2", region_name="us-east-1")
            regions = [r["RegionName"] for r in ec2_base.describe_regions()["Regions"]]
        except ClientError:
            regions = ["us-east-1"]
        log.info(f"Scanning {len(regions)} regions...")

    findings = []
    for r in regions:
        log.info(f"Region: {r}")
        try:
            ec2 = session.client("ec2", region_name=r)
            attached = get_attached_resources(ec2)
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    findings.append(analyse_sg(ec2, sg, r, attached))
        except ClientError as e:
            log.warning(f"Skipping region {r}: {e}")

    findings.sort(key=lambda x: x["severity_score"], reverse=True)

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        risk_counts[f["risk_level"]] = risk_counts.get(f["risk_level"], 0) + 1

    report = {
        "generated_at": NOW.isoformat(),
        "account_id": account_id,
        "summary": {
            "total_groups": len(findings),
            "critical": risk_counts.get("CRITICAL", 0),
            "high": risk_counts.get("HIGH", 0),
            "medium": risk_counts.get("MEDIUM", 0),
            "low": risk_counts.get("LOW", 0),
            "open_ssh": sum(1 for f in findings if f["open_ssh"]),
            "open_rdp": sum(1 for f in findings if f["open_rdp"]),
            "all_traffic_open": sum(1 for f in findings if f["all_traffic_open"]),
            "unused_groups": sum(1 for f in findings if not f["is_attached"]),
            "default_with_rules": sum(1 for f in findings if f["is_default"] and f["ingress_rule_count"] > 0),
            "regions_scanned": len(regions),
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
║      SECURITY GROUP AUDITOR — SUMMARY    ║
╠══════════════════════════════════════════╣
║  Total groups:        {s['total_groups']:<20}║
║  CRITICAL:            {s['critical']:<20}║
║  HIGH:                {s['high']:<20}║
║  MEDIUM:              {s['medium']:<20}║
║  LOW:                 {s['low']:<20}║
║  SSH open to world:   {s['open_ssh']:<20}║
║  RDP open to world:   {s['open_rdp']:<20}║
║  All traffic open:    {s['all_traffic_open']:<20}║
║  Unused groups:       {s['unused_groups']:<20}║
╚══════════════════════════════════════════╝
""")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Group Auditor")
    parser.add_argument("--output", "-o", default="sg_report", help="Output file prefix (default: sg_report)")
    parser.add_argument("--format", "-f", choices=["json", "csv", "html", "all", "stdout"], default="all", help="Output format (default: all)")
    parser.add_argument("--region", "-r", default=None, help="Limit scan to a specific region")
    parser.add_argument("--profile", default=None, help="AWS CLI profile name to use")
    args = parser.parse_args()
    run(output_prefix=args.output, fmt=args.format, profile=args.profile, region=args.region)
