#!/usr/bin/env python3
"""
IAM Privilege Mapper v2
=======================
Enhanced IAM analysis tool with:
- JSON, CSV, and HTML output
- Stale credential & access key detection
- Permission boundary analysis
- Cross-account role trust flagging
- SCP awareness (AWS Orgs)
- Numeric severity scoring (1-10)
- Multi-profile support

Usage:
    python3 iam_mapper_v2.py
    python3 iam_mapper_v2.py --output report --format all
    python3 iam_mapper_v2.py --format csv
    python3 iam_mapper_v2.py --principal-type users --profile prod
"""

import boto3
import html
import json
import csv
import argparse
import logging
import os
from datetime import datetime, timezone, timedelta
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

# ── Constants ─────────────────────────────────────────────────────────────────
ACCESS_KEY_MAX_AGE_DAYS = 90
CREDENTIAL_UNUSED_DAYS = 90
NOW = datetime.now(timezone.utc)

HIGH_RISK_ACTIONS = {
    "*",
    "iam:*", "iam:createaccesskey", "iam:createloginprofile",
    "iam:updateloginprofile", "iam:attachuserpolicy", "iam:attachrolepolicy",
    "iam:attachgrouppolicy", "iam:putuserpolicy", "iam:putrolepolicy",
    "iam:putgrouppolicy", "iam:addusertogroup", "iam:setdefaultpolicyversion",
    "iam:createpolicyversion", "iam:passrole",
    "sts:*", "sts:assumerole",
    "s3:*", "ec2:*", "lambda:*", "cloudformation:*",
    "secretsmanager:*", "ssm:*", "kms:*",
    "organizations:*",
}

PRIVESC_COMBOS = [
    {"name": "Attach policy to self (user)",         "actions": {"iam:attachuserpolicy"}},
    {"name": "Create & set new policy version",      "actions": {"iam:createpolicyversion", "iam:setdefaultpolicyversion"}},
    {"name": "PassRole + Lambda invoke",             "actions": {"iam:passrole", "lambda:createfunction", "lambda:invokefunction"}},
    {"name": "PassRole + EC2 run",                   "actions": {"iam:passrole", "ec2:runinstances"}},
    {"name": "PassRole + CloudFormation deploy",     "actions": {"iam:passrole", "cloudformation:createstack"}},
    {"name": "Add user to privileged group",         "actions": {"iam:addusertogroup"}},
    {"name": "Create access key for other user",     "actions": {"iam:createaccesskey"}},
    {"name": "Reset another user password",          "actions": {"iam:updateloginprofile"}},
    {"name": "Inline policy injection",              "actions": {"iam:putuserpolicy"}},
    {"name": "Attach role policy escalation",        "actions": {"iam:attachrolepolicy"}},
]

ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}

# ── Scoring ───────────────────────────────────────────────────────────────────

def calculate_score(high_risk_actions, privesc_paths, has_admin_policy,
                    stale_keys, no_mfa, console_access, boundary_in_place,
                    cross_account_trust):
    score = 0
    if "*" in high_risk_actions or "iam:*" in high_risk_actions:
        score += 4
    elif high_risk_actions:
        score += min(len(high_risk_actions), 3)
    score += min(len(privesc_paths) * 2, 4)
    if has_admin_policy:
        score += 3
    if stale_keys:
        score += 1
    if no_mfa and console_access:
        score += 1
    if cross_account_trust:
        score += 1
    if boundary_in_place:
        score = max(0, score - 2)
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


# ── Policy helpers ────────────────────────────────────────────────────────────

def get_policy_document(iam, policy_arn, version_id=None):
    try:
        if version_id is None:
            policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
            version_id = policy["DefaultVersionId"]
        doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        return doc["PolicyVersion"]["Document"]
    except ClientError as e:
        log.warning(f"Could not fetch policy {policy_arn}: {e}")
        return {}


def extract_actions(policy_document):
    actions = set()
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        raw = stmt.get("Action", [])
        if isinstance(raw, str):
            raw = [raw]
        actions.update(a.lower() for a in raw)
    return actions


def collect_actions(iam, attached_policies, inline_docs_fn):
    all_actions = set()
    has_admin = False
    for policy in attached_policies:
        if policy["PolicyArn"] in ADMIN_POLICY_ARNS:
            has_admin = True
        doc = get_policy_document(iam, policy["PolicyArn"])
        all_actions.update(extract_actions(doc))
    for doc in inline_docs_fn():
        all_actions.update(extract_actions(doc))
    return all_actions, has_admin


def score_actions(actions):
    flagged = []
    for a in actions:
        if a in HIGH_RISK_ACTIONS or a.endswith(":*") or a == "*":
            flagged.append(a)
    return sorted(set(flagged))


def check_privesc(actions):
    paths = []
    for combo in PRIVESC_COMBOS:
        required = combo["actions"]
        covered = set()
        for req in required:
            service = req.split(":")[0]
            if req in actions or f"{service}:*" in actions or "*" in actions:
                covered.add(req)
        if covered == required:
            paths.append(combo["name"])
    return paths


def check_permission_boundary(iam, principal_type, name):
    try:
        if principal_type == "user":
            resp = iam.get_user(UserName=name)["User"]
        else:
            resp = iam.get_role(RoleName=name)["Role"]
        boundary = resp.get("PermissionsBoundary", {})
        return boundary.get("PermissionsBoundaryArn", None)
    except ClientError:
        return None


# ── SCP helpers ───────────────────────────────────────────────────────────────

def get_effective_scps(org_client, account_id):
    """Return a set of denied actions from SCPs applied to this account.

    Note: Allow statements with Condition blocks are not fully modelled here.
    SCPs with Allow+Condition may still restrict actions not listed as denied.
    """
    denied = set()
    try:
        paginator = org_client.get_paginator("list_policies_for_target")
        policies = []
        for page in paginator.paginate(TargetId=account_id, Filter="SERVICE_CONTROL_POLICY"):
            policies.extend(page["Policies"])
        for p in policies:
            doc = org_client.describe_policy(PolicyId=p["Id"])["Policy"]["Content"]
            doc = json.loads(doc)
            has_allow_with_condition = False
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") == "Deny":
                    raw = stmt.get("Action", [])
                    if isinstance(raw, str):
                        raw = [raw]
                    denied.update(a.lower() for a in raw)
                elif stmt.get("Effect") == "Allow" and stmt.get("Condition"):
                    has_allow_with_condition = True
            if has_allow_with_condition:
                log.warning(
                    f"SCP {p['Id']} has Allow+Condition statements — "
                    "conditional restrictions are not fully modelled"
                )
    except ClientError:
        pass
    return denied


# ── Credential checks ─────────────────────────────────────────────────────────

def check_access_keys(iam, username):
    issues = []
    keys = []
    try:
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
    except ClientError:
        return issues, keys

    for key in keys:
        key_id = key["AccessKeyId"]
        status = key["Status"]
        created = key["CreateDate"]
        age_days = (NOW - created).days

        last_used_date = None
        last_used_service = None
        days_since_used = None
        try:
            lu = iam.get_access_key_last_used(AccessKeyId=key_id)["AccessKeyLastUsed"]
            last_used_date = lu.get("LastUsedDate")
            last_used_service = lu.get("ServiceName", "N/A")
            if last_used_date:
                days_since_used = (NOW - last_used_date).days
        except ClientError:
            pass

        key["age_days"] = age_days
        key["last_used_date"] = last_used_date.isoformat() if last_used_date else "Never"
        key["last_used_service"] = last_used_service
        key["days_since_used"] = days_since_used

        if status == "Active" and age_days > ACCESS_KEY_MAX_AGE_DAYS:
            issues.append(f"Key {key_id} is {age_days} days old (>{ACCESS_KEY_MAX_AGE_DAYS} day limit)")
        if status == "Active" and days_since_used and days_since_used > CREDENTIAL_UNUSED_DAYS:
            issues.append(f"Key {key_id} unused for {days_since_used} days")
        if status == "Active" and last_used_date is None:
            issues.append(f"Key {key_id} has never been used")

    if len([k for k in keys if k["Status"] == "Active"]) > 1:
        issues.append("Multiple active access keys detected")

    return issues, keys


# ── Principal analysers ───────────────────────────────────────────────────────

def _build_iam_flags(finding):
    """Build parallel flags/remediations lists from a finding dict.

    Mirrors the conditions rendered by write_html so that the JSON report
    carries the same actionable information as the HTML output.  The flags
    list is what exec_summary.py reads for quick_wins (ℹ️-prefixed items on
    HIGH/CRITICAL findings) and for the top-findings table.
    """
    flags = []
    remediations = []

    if finding.get("mfa_warning"):
        flags.append("⚠️ No MFA")
        remediations.append(
            "Enable MFA: IAM Console → Users → select user → "
            "Security credentials → Assign MFA device"
        )

    if finding.get("has_admin_policy"):
        flags.append("⚠️ Admin Policy")
        remediations.append(
            "Review need for AdministratorAccess; replace with least-privilege "
            "policies scoped to required services only"
        )

    if finding.get("cross_account_trust"):
        flags.append("⚠️ Cross-Account Trust")
        remediations.append(
            "Review trust policy; ensure ExternalId condition is required; "
            "scope to specific trusted principal ARNs"
        )

    if finding.get("privilege_escalation_paths"):
        flags.append("⚠️ Privilege Escalation Path")
        remediations.append(
            "Remove the action(s) forming the escalation path; "
            "review IAM PassRole usage; consider permission boundaries"
        )

    if finding.get("high_risk_actions"):
        flags.append("ℹ️ High-Risk Actions")
        remediations.append(
            "Remove unused high-risk permissions; apply least-privilege; "
            "use IAM Access Analyzer to identify unused access"
        )

    for issue in finding.get("access_key_issues", []):
        flags.append(f"⚠️ Key: {issue}")
        remediations.append(
            "Rotate or deactivate the affected key: IAM Console → Users → "
            "Security credentials → Access keys"
        )

    if finding.get("permission_boundary"):
        flags.append("✅ Boundary Set")
        remediations.append("")

    return flags, remediations


def analyse_user(iam, user, scp_denied):
    name = user["UserName"]
    arn = user["Arn"]
    log.info(f"  User: {name}")

    try:
        attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
    except ClientError:
        attached = []

    def inline_docs():
        docs = []
        try:
            for pname in iam.list_user_policies(UserName=name)["PolicyNames"]:
                docs.append(iam.get_user_policy(UserName=name, PolicyName=pname)["PolicyDocument"])
        except ClientError:
            pass
        return docs

    # Group permissions
    group_actions = set()
    groups = []
    group_admin = False
    try:
        for g in iam.list_groups_for_user(UserName=name)["Groups"]:
            groups.append(g["GroupName"])
            ga = iam.list_attached_group_policies(GroupName=g["GroupName"])["AttachedPolicies"]
            for p in ga:
                if p["PolicyArn"] in ADMIN_POLICY_ARNS:
                    group_admin = True
                doc = get_policy_document(iam, p["PolicyArn"])
                group_actions.update(extract_actions(doc))
            for iname in iam.list_group_policies(GroupName=g["GroupName"])["PolicyNames"]:
                doc = iam.get_group_policy(GroupName=g["GroupName"], PolicyName=iname)["PolicyDocument"]
                group_actions.update(extract_actions(doc))
    except ClientError:
        pass

    direct_actions, has_admin = collect_actions(iam, attached, inline_docs)
    all_actions = (direct_actions | group_actions) - scp_denied
    has_admin = has_admin or group_admin

    high_risk = score_actions(all_actions)
    privesc = check_privesc(all_actions)
    boundary = check_permission_boundary(iam, "user", name)
    key_issues, keys = check_access_keys(iam, name)

    has_console = False
    password_last_used = None
    try:
        iam.get_login_profile(UserName=name)
        has_console = True
        password_last_used = user.get("PasswordLastUsed")
        if password_last_used:
            password_last_used = password_last_used.isoformat()
    except ClientError:
        pass

    mfa_enabled = False
    try:
        mfa_enabled = len(iam.list_mfa_devices(UserName=name)["MFADevices"]) > 0
    except ClientError:
        pass

    no_mfa = has_console and not mfa_enabled
    stale_keys = len(key_issues) > 0

    score, risk_level = calculate_score(
        high_risk, privesc, has_admin, stale_keys,
        no_mfa, has_console, boundary is not None, False
    )

    finding = {
        "type": "user",
        "name": name,
        "arn": arn,
        "risk_level": risk_level,
        "severity_score": score,
        "console_access": has_console,
        "password_last_used": password_last_used,
        "mfa_enabled": mfa_enabled,
        "mfa_warning": no_mfa,
        "groups": groups,
        "has_admin_policy": has_admin,
        "permission_boundary": boundary,
        "high_risk_actions": high_risk,
        "privilege_escalation_paths": privesc,
        "access_key_issues": key_issues,
        "access_keys": [
            {
                "key_id": k["AccessKeyId"],
                "status": k["Status"],
                "age_days": k.get("age_days"),
                "last_used": k.get("last_used_date"),
                "last_used_service": k.get("last_used_service"),
            }
            for k in keys
        ],
        "total_actions_count": len(all_actions),
        "scp_restrictions_applied": len(scp_denied) > 0,
        "cis_control": "CIS 6",
    }
    finding["flags"], finding["remediations"] = _build_iam_flags(finding)
    return finding


def analyse_role(iam, role, scp_denied):
    name = role["RoleName"]
    arn = role["Arn"]
    log.info(f"  Role: {name}")

    try:
        attached = iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]
    except ClientError:
        attached = []

    def inline_docs():
        docs = []
        try:
            for pname in iam.list_role_policies(RoleName=name)["PolicyNames"]:
                docs.append(iam.get_role_policy(RoleName=name, PolicyName=pname)["PolicyDocument"])
        except ClientError:
            pass
        return docs

    all_actions, has_admin = collect_actions(iam, attached, inline_docs)
    all_actions -= scp_denied

    high_risk = score_actions(all_actions)
    privesc = check_privesc(all_actions)
    boundary = check_permission_boundary(iam, "role", name)

    # Trust policy
    trust_principals = []
    cross_account = False
    external_ids = []
    try:
        trust_doc = role.get("AssumeRolePolicyDocument", {})
        for stmt in trust_doc.get("Statement", []):
            principal = stmt.get("Principal", {})
            if isinstance(principal, str):
                trust_principals.append(principal)
            elif isinstance(principal, dict):
                for v in principal.values():
                    items = v if isinstance(v, list) else [v]
                    trust_principals.extend(items)
                    for item in items:
                        # Cross-account if principal is an ARN from a different account
                        if "arn:aws:iam::" in str(item):
                            cross_account = True
            cond = stmt.get("Condition", {})
            ext = cond.get("StringEquals", {}).get("sts:ExternalId")
            if ext:
                external_ids.append(ext)
    except Exception:
        pass

    score, risk_level = calculate_score(
        high_risk, privesc, has_admin, False,
        False, False, boundary is not None, cross_account
    )

    finding = {
        "type": "role",
        "name": name,
        "arn": arn,
        "risk_level": risk_level,
        "severity_score": score,
        "has_admin_policy": has_admin,
        "permission_boundary": boundary,
        "trust_principals": trust_principals,
        "cross_account_trust": cross_account,
        "external_id_required": len(external_ids) > 0,
        "high_risk_actions": high_risk,
        "privilege_escalation_paths": privesc,
        "total_actions_count": len(all_actions),
        "scp_restrictions_applied": len(scp_denied) > 0,
        "cis_control": "CIS 6",
    }
    finding["flags"], finding["remediations"] = _build_iam_flags(finding)
    return finding


def analyse_group(iam, group, scp_denied):
    name = group["GroupName"]
    arn = group["Arn"]
    log.info(f"  Group: {name}")

    try:
        attached = iam.list_attached_group_policies(GroupName=name)["AttachedPolicies"]
    except ClientError:
        attached = []

    def inline_docs():
        docs = []
        try:
            for pname in iam.list_group_policies(GroupName=name)["PolicyNames"]:
                docs.append(iam.get_group_policy(GroupName=name, PolicyName=pname)["PolicyDocument"])
        except ClientError:
            pass
        return docs

    all_actions, has_admin = collect_actions(iam, attached, inline_docs)
    all_actions -= scp_denied
    high_risk = score_actions(all_actions)
    privesc = check_privesc(all_actions)

    members = []
    try:
        members = [u["UserName"] for u in iam.get_group(GroupName=name)["Users"]]
    except ClientError:
        pass

    score, risk_level = calculate_score(
        high_risk, privesc, has_admin, False,
        False, False, False, False
    )

    finding = {
        "type": "group",
        "name": name,
        "arn": arn,
        "risk_level": risk_level,
        "severity_score": score,
        "has_admin_policy": has_admin,
        "members": members,
        "member_count": len(members),
        "high_risk_actions": high_risk,
        "privilege_escalation_paths": privesc,
        "total_actions_count": len(all_actions),
        "scp_restrictions_applied": len(scp_denied) > 0,
        "cis_control": "CIS 6",
    }
    finding["flags"], finding["remediations"] = _build_iam_flags(finding)
    return finding


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
        "type", "name", "arn", "risk_level", "severity_score",
        "has_admin_policy", "console_access", "mfa_enabled", "mfa_warning",
        "permission_boundary", "cross_account_trust", "external_id_required",
        "high_risk_actions", "privilege_escalation_paths",
        "access_key_issues", "total_actions_count", "scp_restrictions_applied",
        "groups", "members", "trust_principals", "cis_control",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            row = finding.copy()
            # Flatten lists to semicolon-separated strings
            for field in ["high_risk_actions", "privilege_escalation_paths",
                          "access_key_issues", "groups", "members", "trust_principals"]:
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
        privesc = "<br>".join(html.escape(p) for p in f.get("privilege_escalation_paths", [])) or "None"
        high_risk_list = f.get("high_risk_actions", [])
        high_risk = "<br>".join(html.escape(a) for a in high_risk_list[:5]) or "None"
        if len(high_risk_list) > 5:
            high_risk += f"<br>...+{len(high_risk_list)-5} more"
        key_issues = "<br>".join(html.escape(k) for k in f.get("access_key_issues", [])) or "N/A"
        # Remediation hints keyed by warning condition
        remediation_hints = {
            "mfa_warning": (
                "Enable MFA: IAM Console → Users → select user → "
                "Security credentials → Assign MFA device"
            ),
            "has_admin_policy": (
                "Review need for AdministratorAccess; replace with least-privilege "
                "policies scoped to required services only"
            ),
            "cross_account_trust": (
                "Review trust policy; ensure ExternalId condition is required; "
                "scope to specific trusted principal ARNs"
            ),
        }

        warning_parts = []
        if f.get("mfa_warning"):
            hint = remediation_hints["mfa_warning"]
            warning_parts.append(
                f'<div class="flag-item">'
                f'<span class="flag-text">⚠️ No MFA</span>'
                f'<span class="rem-text">↳ {html.escape(hint)}</span>'
                f'</div>'
            )
        if f.get("has_admin_policy"):
            hint = remediation_hints["has_admin_policy"]
            warning_parts.append(
                f'<div class="flag-item">'
                f'<span class="flag-text">⚠️ Admin Policy</span>'
                f'<span class="rem-text">↳ {html.escape(hint)}</span>'
                f'</div>'
            )
        if f.get("cross_account_trust"):
            hint = remediation_hints["cross_account_trust"]
            warning_parts.append(
                f'<div class="flag-item">'
                f'<span class="flag-text">⚠️ Cross-Account Trust</span>'
                f'<span class="rem-text">↳ {html.escape(hint)}</span>'
                f'</div>'
            )
        if f.get("permission_boundary"):
            warning_parts.append(
                '<div class="flag-item"><span class="flag-text">✅ Boundary Set</span></div>'
            )
        warning_html = "".join(warning_parts)

        high_risk_rem = ""
        if high_risk_list:
            high_risk_rem = (
                '<div class="rem-text" style="margin-top:4px">↳ Remove unused high-risk permissions; '
                'apply least-privilege; use IAM Access Analyzer to identify unused access</div>'
            )
        privesc_rem = ""
        if f.get("privilege_escalation_paths"):
            privesc_rem = (
                '<div class="rem-text" style="margin-top:4px">↳ Remove the action(s) forming the '
                'escalation path; review IAM PassRole usage; consider permission boundaries</div>'
            )
        name_escaped = html.escape(f["name"])
        arn_escaped = html.escape(f["arn"])

        rows += f"""
        <tr>
            <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{f['risk_level']}</span></td>
            <td style="font-weight:bold">{f['severity_score']}/10</td>
            <td><span style="background:#2c3e50;color:white;padding:2px 6px;border-radius:3px;font-size:0.8em">{f['type'].upper()}</span></td>
            <td>{name_escaped}</td>
            <td style="font-size:0.8em;color:#666">{arn_escaped}</td>
            <td style="font-size:0.85em">{high_risk}{high_risk_rem}</td>
            <td style="font-size:0.85em;color:#dc3545">{privesc}{privesc_rem}</td>
            <td style="font-size:0.85em">{key_issues}</td>
            <td style="font-size:0.85em">{warning_html}</td>
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
<title>IAM Privilege Mapper Report</title>
<style>
{get_styles(extra_css)}
</style>
</head>
<body>
<div class="header">
  <h1>🔐 IAM Privilege Mapper Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; Account findings: {summary['total_principals']} principals analysed</p>
</div>
<div class="summary">
  <div class="card total"><div class="num">{summary['total_principals']}</div><div class="label">Total Principals</div></div>
  <div class="card critical"><div class="num">{summary['critical']}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{summary['high']}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{summary.get('medium', 0)}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{summary['low']}</div><div class="label">Low</div></div>
  <div class="card" style="border-left: 4px solid #e74c3c"><div class="num" style="color:#e74c3c">{summary['users_without_mfa']}</div><div class="label">No MFA (console users)</div></div>
  <div class="card" style="border-left: 4px solid #fd7e14"><div class="num" style="color:#fd7e14">{summary.get('stale_keys', 0)}</div><div class="label">Stale Access Keys</div></div>
  <div class="card" style="border-left: 4px solid #9b59b6"><div class="num" style="color:#9b59b6">{summary.get('cross_account_roles', 0)}</div><div class="label">Cross-Account Roles</div></div>
</div>
<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Risk</th><th>Score</th><th>Type</th><th>Name</th><th>ARN</th>
        <th>High-Risk Actions</th><th>Privesc Paths</th><th>Key Issues</th><th>Flags</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">IAM Privilege Mapper v2 &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, "w") as fh:
        fh.write(html_content)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")


# ── Paginator ─────────────────────────────────────────────────────────────────

def paginate(client_fn, key, **kwargs):
    results = []
    kw = kwargs.copy()
    while True:
        resp = client_fn(**kw)
        results.extend(resp.get(key, []))
        marker = resp.get("Marker") or resp.get("NextToken")
        if not marker:
            break
        kw["Marker" if "Marker" in resp else "NextToken"] = marker
    return results


# ── Main ──────────────────────────────────────────────────────────────────────

def run(principal_type="all", output_prefix="iam_report", fmt="all", profile=None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam = session.client("iam", config=BOTO_CONFIG)

    # Try to get account ID + SCPs
    scp_denied = set()
    account_id = None
    try:
        sts = session.client("sts", config=BOTO_CONFIG)
        account_id = sts.get_caller_identity()["Account"]
        log.info(f"Account ID: {account_id}")
        try:
            org = session.client("organizations", config=BOTO_CONFIG)
            scp_denied = get_effective_scps(org, account_id)
            if scp_denied:
                log.info(f"SCP restrictions found: {len(scp_denied)} denied actions")
        except ClientError:
            log.info("No AWS Organizations access — skipping SCP analysis")
    except ClientError:
        log.warning("Could not determine account ID")

    findings = []

    if principal_type in ("all", "users"):
        log.info("Enumerating IAM users...")
        for u in paginate(iam.list_users, "Users"):
            findings.append(analyse_user(iam, u, scp_denied))

    if principal_type in ("all", "roles"):
        log.info("Enumerating IAM roles...")
        for r in paginate(iam.list_roles, "Roles"):
            findings.append(analyse_role(iam, r, scp_denied))

    if principal_type in ("all", "groups"):
        log.info("Enumerating IAM groups...")
        for g in paginate(iam.list_groups, "Groups"):
            findings.append(analyse_group(iam, g, scp_denied))

    # Sort by severity score descending
    findings.sort(key=lambda x: x["severity_score"], reverse=True)

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        risk_counts[f["risk_level"]] = risk_counts.get(f["risk_level"], 0) + 1

    report = {
        "generated_at": NOW.isoformat(),
        "account_id": account_id,
        "scp_analysis": len(scp_denied) > 0,
        "summary": {
            "total_principals": len(findings),
            "critical": risk_counts.get("CRITICAL", 0),
            "high": risk_counts.get("HIGH", 0),
            "medium": risk_counts.get("MEDIUM", 0),
            "low": risk_counts.get("LOW", 0),
            "users_without_mfa": sum(1 for f in findings if f.get("mfa_warning")),
            "stale_keys": sum(1 for f in findings if f.get("access_key_issues")),
            "cross_account_roles": sum(1 for f in findings if f.get("cross_account_trust")),
            "admin_policy_holders": sum(1 for f in findings if f.get("has_admin_policy")),
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

    # Print quick summary to terminal
    s = report["summary"]
    print(f"""
╔══════════════════════════════════════════╗
║         IAM MAPPER v2 — SUMMARY          ║
╠══════════════════════════════════════════╣
║  Total principals:    {s['total_principals']:<20}║
║  CRITICAL:            {s['critical']:<20}║
║  HIGH:                {s['high']:<20}║
║  MEDIUM:              {s['medium']:<20}║
║  LOW:                 {s['low']:<20}║
║  No MFA (console):    {s['users_without_mfa']:<20}║
║  Stale access keys:   {s['stale_keys']:<20}║
║  Cross-account roles: {s['cross_account_roles']:<20}║
║  Admin policy holders:{s['admin_policy_holders']:<20}║
╚══════════════════════════════════════════╝
""")

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IAM Privilege Mapper v2")
    parser.add_argument("--output", "-o", default="iam_report",
                        help="Output file prefix (default: iam_report)")
    parser.add_argument("--format", "-f",
                        choices=["json", "csv", "html", "all", "stdout"],
                        default="all",
                        help="Output format (default: all)")
    parser.add_argument("--principal-type",
                        choices=["all", "users", "roles", "groups"],
                        default="all",
                        help="Limit scan to principal type")
    parser.add_argument("--profile", default=None,
                        help="AWS CLI profile name to use")
    args = parser.parse_args()
    run(
        principal_type=args.principal_type,
        output_prefix=args.output,
        fmt=args.format,
        profile=args.profile,
    )
