#!/usr/bin/env python3
"""
EC2 Instance Auditor
====================
Audits EC2 instances for common security misconfigurations:
- IMDSv2 enforcement and hop limit
- Public IP addresses
- Unencrypted EBS volumes
- Missing IAM instance profile
- Default VPC placement
- Public snapshots

Usage:
    python3 ec2_auditor.py
    python3 ec2_auditor.py --output report --format html
    python3 ec2_auditor.py --profile prod --regions eu-west-1 us-east-1
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

FIELDNAMES = [
    "instance_id", "name", "instance_type", "region", "vpc_id", "state",
    "launch_time", "image_id", "platform", "has_public_ip", "public_ip",
    "private_ip", "imds_v2_required", "imds_hop_limit", "has_instance_profile",
    "in_default_vpc", "unencrypted_volumes", "public_snapshots",
    "severity_score", "risk_level", "flags", "remediations",
    "cis_control",
]


# ── Checks ────────────────────────────────────────────────────────────────────

def check_imds(metadata_options):
    """Return (imds_v2_required: bool, hop_limit: int)."""
    if metadata_options.get("HttpEndpoint") == "disabled":
        return False, metadata_options.get("HttpPutResponseHopLimit", 1)
    v2_required = metadata_options.get("HttpTokens") == "required"
    hop_limit = metadata_options.get("HttpPutResponseHopLimit", 1)
    return v2_required, hop_limit


def check_ebs_encryption(ec2_client, block_device_mappings):
    """Return list of unencrypted volume IDs attached to this instance."""
    unencrypted = []
    vol_ids = [
        m["Ebs"]["VolumeId"]
        for m in block_device_mappings
        if "Ebs" in m
    ]
    if not vol_ids:
        return []
    try:
        resp = ec2_client.describe_volumes(VolumeIds=vol_ids)
        for vol in resp.get("Volumes", []):
            if not vol.get("Encrypted", False):
                unencrypted.append(vol["VolumeId"])
    except ClientError as e:
        log.warning(f"Could not describe volumes {vol_ids}: {e}")
    return unencrypted


def check_public_snapshots(ec2_client):
    """Return list of public snapshot IDs owned by this account (account-level check)."""
    public_snaps = []
    try:
        resp = ec2_client.describe_snapshots(
            Filters=[{"Name": "status", "Values": ["completed"]}],
            OwnerIds=["self"],
        )
        for snap in resp.get("Snapshots", []):
            perms = snap.get("CreateVolumePermissions", [])
            if any(p.get("Group") == "all" for p in perms):
                public_snaps.append(snap["SnapshotId"])
    except ClientError as e:
        log.warning(f"Could not describe snapshots: {e}")
    return public_snaps


# ── Scoring ───────────────────────────────────────────────────────────────────

def calculate_score(no_imds_v2, public_ip, unencrypted_volumes,
                    no_instance_profile, hop_limit_high, in_default_vpc,
                    public_snapshots):
    score = 0
    if no_imds_v2:
        score += 3
    if public_ip:
        score += 2
    if unencrypted_volumes:
        score += 2
    if public_snapshots:
        score += 3
    if hop_limit_high:
        score += 1
    if no_instance_profile:
        score += 1
    if in_default_vpc:
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

def analyse_instance(ec2_client, instance, default_vpc_id=None, account_public_snapshots=None):
    """Analyse a single EC2 instance dict and return a findings dict."""
    instance_id = instance["InstanceId"]
    flags = []
    remediations = []

    # IMDSv2
    meta_opts = instance.get("MetadataOptions", {})
    imds_v2_required, hop_limit = check_imds(meta_opts)
    hop_limit_high = hop_limit > 1

    if not imds_v2_required:
        flags.append("⚠️ IMDSv2 not enforced (HttpTokens=optional)")
        remediations.append(
            "Enforce IMDSv2: EC2 Console → Instances → select → Actions → "
            "Modify instance metadata options → IMDSv2 → Required"
        )
    if hop_limit_high:
        flags.append(f"ℹ️ IMDS hop limit is {hop_limit} (container escape risk if >1)")
        remediations.append(
            "Reduce IMDS hop limit to 1: EC2 Console → Instances → Actions → "
            "Modify instance metadata options → Metadata response hop limit → 1"
        )

    # Public IP
    has_public_ip = bool(instance.get("PublicIpAddress"))
    if has_public_ip:
        flags.append(f"⚠️ Instance has a public IP ({instance['PublicIpAddress']})")
        remediations.append(
            "Move instance behind a load balancer or NAT Gateway; disable public IP "
            "on subnet: VPC Console → Subnets → subnet → Modify auto-assign public IP → Disable"
        )

    # EBS encryption
    bdm = instance.get("BlockDeviceMappings", [])
    unencrypted_vols = check_ebs_encryption(ec2_client, bdm)
    if unencrypted_vols:
        flags.append(f"❌ Unencrypted EBS volume(s): {', '.join(unencrypted_vols)}")
        remediations.append(
            "Encrypt EBS volumes: create an encrypted snapshot of each volume, "
            "restore to new encrypted volume, swap attachment. "
            "Enable EBS encryption by default: EC2 Console → Settings → EBS encryption → Enable"
        )

    # IAM instance profile
    has_instance_profile = bool(instance.get("IamInstanceProfile"))
    no_instance_profile = not has_instance_profile
    if no_instance_profile:
        flags.append("ℹ️ No IAM instance profile attached")
        remediations.append(
            "Attach an IAM instance profile with least-privilege permissions: "
            "EC2 Console → Instances → Actions → Security → Modify IAM role → attach role"
        )

    # Default VPC
    vpc_id = instance.get("VpcId", "")
    in_default_vpc = (default_vpc_id is not None and vpc_id == default_vpc_id)
    if in_default_vpc:
        flags.append("ℹ️ Instance running in the default VPC")
        remediations.append(
            "Migrate instance to a purpose-built VPC with private subnets, NACLs, "
            "and flow logs. Default VPC lacks network segmentation controls."
        )

    # Public snapshots (account-level; pre-fetched by run() for efficiency)
    public_snaps = account_public_snapshots if account_public_snapshots is not None else check_public_snapshots(ec2_client)
    if public_snaps:
        flags.append(f"❌ Public snapshot(s) exist: {', '.join(public_snaps[:3])}")
        remediations.append(
            "Make snapshots private: EC2 Console → Snapshots → select → Actions → "
            "Modify permissions → Private"
        )

    # NOTE: ✅ (positive) flags are appended last with no matching remediations.
    # The HTML renderer's fallback (flags_list[len(rems_list):]) depends on this ordering.
    if imds_v2_required:
        flags.append("✅ IMDSv2 enforced")
    if not has_public_ip:
        flags.append("✅ No public IP")
    if not unencrypted_vols:
        flags.append("✅ All EBS volumes encrypted")
    if has_instance_profile:
        flags.append("✅ IAM instance profile attached")

    score, risk_level = calculate_score(
        no_imds_v2=not imds_v2_required,
        public_ip=has_public_ip,
        unencrypted_volumes=unencrypted_vols,
        no_instance_profile=no_instance_profile,
        hop_limit_high=hop_limit_high,
        in_default_vpc=in_default_vpc,
        public_snapshots=public_snaps,
    )

    name = next(
        (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"), ""
    )

    return {
        "instance_id": instance_id,
        "name": name,
        "instance_type": instance.get("InstanceType", ""),
        "region": instance.get("_region", ""),
        "vpc_id": vpc_id,
        "state": instance.get("State", {}).get("Name", ""),
        "launch_time": str(instance.get("LaunchTime", "")),
        "image_id": instance.get("ImageId", ""),
        "platform": instance.get("PlatformDetails", ""),
        "has_public_ip": has_public_ip,
        "public_ip": instance.get("PublicIpAddress"),
        "private_ip": instance.get("PrivateIpAddress"),
        "imds_v2_required": imds_v2_required,
        "imds_hop_limit": hop_limit,
        "has_instance_profile": has_instance_profile,
        "in_default_vpc": in_default_vpc,
        "unencrypted_volumes": unencrypted_vols,
        "public_snapshots": public_snaps,
        "severity_score": score,
        "risk_level": risk_level,
        "flags": flags,
        "remediations": remediations,
        "cis_control": "CIS 4",
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
            row["unencrypted_volumes"] = "; ".join(finding.get("unencrypted_volumes", []))
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

        rows += (
            f'<tr>'
            f'<td><span style="background:{colour};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em">{risk}</span></td>'
            f'<td>{f["severity_score"]}</td>'
            f'<td><code>{html_lib.escape(f["instance_id"])}</code></td>'
            f'<td>{html_lib.escape(f.get("name",""))}</td>'
            f'<td>{html_lib.escape(f.get("instance_type",""))}</td>'
            f'<td>{html_lib.escape(f.get("region",""))}</td>'
            f'<td>{html_lib.escape(f.get("state",""))}</td>'
            f'<td>{"✅" if not f.get("has_public_ip") else "❌ " + html_lib.escape(str(f.get("public_ip","")))}</td>'
            f'<td>{"✅" if f.get("imds_v2_required") else "❌"}</td>'
            f'<td>{"✅" if not f.get("unencrypted_volumes") else "❌"}</td>'
            f'<td>{"✅" if f.get("has_instance_profile") else "ℹ️"}</td>'
            f'<td>{flags_html}</td>'
            f'</tr>\n'
        )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>EC2 Audit Report</title>
<style>
  body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; margin:0; background:#f5f6fa; color:#333; }}
  .header {{ background: linear-gradient(135deg,#232f3e,#ff9900); color:#fff; padding:30px 40px; }}
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
  <h1>🖥️ EC2 Instance Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; {summary.get('total_instances',0)} instances analysed</p>
</div>
<div class="summary">
  <div class="card total"><div class="num">{summary.get('total_instances',0)}</div><div class="label">Total Instances</div></div>
  <div class="card critical"><div class="num">{summary.get('critical',0)}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{summary.get('high',0)}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{summary.get('medium',0)}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{summary.get('low',0)}</div><div class="label">Low</div></div>
  <div class="card" style="border-left:4px solid #dc3545"><div class="num" style="color:#dc3545">{summary.get('no_imds_v2',0)}</div><div class="label">No IMDSv2</div></div>
  <div class="card" style="border-left:4px solid #fd7e14"><div class="num" style="color:#fd7e14">{summary.get('public_instances',0)}</div><div class="label">Public IP</div></div>
  <div class="card" style="border-left:4px solid #ffc107"><div class="num" style="color:#ffc107">{summary.get('unencrypted_ebs',0)}</div><div class="label">Unencrypted EBS</div></div>
</div>
<div class="table-wrap">
  <table>
    <thead>
      <tr><th>Risk</th><th>Score</th><th>Instance ID</th><th>Name</th><th>Type</th><th>Region</th><th>State</th><th>Public IP</th><th>IMDSv2</th><th>EBS Enc.</th><th>IAM Profile</th><th>Flags</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">EC2 Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html_content)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def get_default_vpc(ec2_client):
    """Return the default VPC ID for this region, or None."""
    try:
        resp = ec2_client.describe_vpcs(
            Filters=[{"Name": "isDefault", "Values": ["true"]}]
        )
        vpcs = resp.get("Vpcs", [])
        return vpcs[0]["VpcId"] if vpcs else None
    except ClientError:
        return None


def run(output_prefix="ec2_report", fmt="all", profile=None, regions=None):
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
            ec2_client = session.client("ec2", region_name=region, config=BOTO_CONFIG)
            default_vpc = get_default_vpc(ec2_client)
            # Fetch account-level public snapshots once per region (not per instance)
            public_snaps_in_region = check_public_snapshots(ec2_client)
            paginator = ec2_client.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
            ):
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        inst["_region"] = region
                        finding = analyse_instance(ec2_client, inst, default_vpc_id=default_vpc, account_public_snapshots=public_snaps_in_region)
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
            "no_imds_v2": sum(1 for f in all_findings if not f["imds_v2_required"]),
            "public_instances": sum(1 for f in all_findings if f["has_public_ip"]),
            "unencrypted_ebs": sum(1 for f in all_findings if f["unencrypted_volumes"]),
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
        f"Done. {len(all_findings)} instances. "
        f"CRITICAL={risk_counts['CRITICAL']} HIGH={risk_counts['HIGH']} "
        f"MEDIUM={risk_counts['MEDIUM']} LOW={risk_counts['LOW']}"
    )


def main():
    parser = argparse.ArgumentParser(description="EC2 Instance Security Auditor")
    parser.add_argument("--output", default="ec2_report", help="Output file prefix")
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
