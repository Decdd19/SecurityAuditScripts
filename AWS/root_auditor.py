"""
Root Account Auditor
====================
Audits AWS root account security posture including:
- Root account MFA status
- Root access keys existence and last usage
- Root account last login
- Account password policy
- Alternate contacts configured
- Support plan (indicator of account maturity)
- AWS Organizations root detection

Usage:
    python3 root_auditor.py
    python3 root_auditor.py --output report --format all
    python3 root_auditor.py --format csv
    python3 root_auditor.py --profile prod
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
PASSWORD_POLICY_DEFAULTS = {
    "MinimumPasswordLength": 8,
    "RequireUppercaseCharacters": False,
    "RequireLowercaseCharacters": False,
    "RequireNumbers": False,
    "RequireSymbols": False,
    "MaxPasswordAge": 0,
    "PasswordReusePrevention": 0,
    "HardExpiry": False,
}


# ── Scoring ───────────────────────────────────────────────────────────────────

def calculate_score(no_mfa, active_root_keys, root_used_recently,
                    weak_password_policy, no_alternate_contacts,
                    no_support_plan, account_age_days):
    score = 0
    if no_mfa:
        score += 5
    if active_root_keys:
        score += 4
    if root_used_recently:
        score += 3
    if weak_password_policy:
        score += 2
    if no_alternate_contacts:
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


# ── Checks ────────────────────────────────────────────────────────────────────

def check_credential_report(iam):
    """Generate and retrieve the IAM credential report."""
    try:
        # Request generation
        iam.generate_credential_report()
        import time
        for _ in range(10):
            try:
                resp = iam.get_credential_report()
                content = resp["Content"].decode("utf-8")
                lines = content.strip().split("\n")
                headers = lines[0].split(",")
                root_line = None
                for line in lines[1:]:
                    fields = line.split(",")
                    if fields[0] == "<root_account>":
                        root_line = dict(zip(headers, fields))
                        break
                return root_line
            except ClientError as e:
                if e.response["Error"]["Code"] == "ReportNotPresent":
                    time.sleep(2)
                else:
                    break
    except ClientError as e:
        log.warning(f"Could not generate credential report: {e}")
    return None


def check_mfa_devices(iam):
    """Check if root has MFA enabled (virtual or hardware)."""
    try:
        resp = iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")
        for device in resp.get("VirtualMFADevices", []):
            user = device.get("User", {})
            if user.get("Arn", "").endswith(":root"):
                return True, "Virtual MFA"
        return False, None
    except ClientError:
        return False, None


def check_root_access_keys(iam):
    """Check for active root access keys via account summary."""
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        key_count = summary.get("AccountAccessKeysPresent", 0)
        return key_count > 0, key_count
    except ClientError:
        return False, 0


def check_password_policy(iam):
    """Retrieve and evaluate account password policy."""
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append(f"Min length {policy.get('MinimumPasswordLength')} (recommend ≥14)")
        if not policy.get("RequireUppercaseCharacters"):
            issues.append("Uppercase not required")
        if not policy.get("RequireLowercaseCharacters"):
            issues.append("Lowercase not required")
        if not policy.get("RequireNumbers"):
            issues.append("Numbers not required")
        if not policy.get("RequireSymbols"):
            issues.append("Symbols not required")
        max_age = policy.get("MaxPasswordAge", 0)
        if max_age == 0:
            issues.append("No password expiry set")
        elif max_age > 90:
            issues.append(f"Password expiry {max_age} days (recommend ≤90)")
        reuse = policy.get("PasswordReusePrevention", 0)
        if reuse < 24:
            issues.append(f"Only {reuse} previous passwords prevented from reuse (recommend 24)")
        return policy, issues
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return None, ["No password policy configured — AWS defaults apply (very weak)"]
        return None, [f"Could not retrieve policy: {e}"]


def check_alternate_contacts(account_id, session):
    """Check if billing, operations, security alternate contacts are set."""
    contacts = {}
    try:
        account = session.client("account")
        for contact_type in ["BILLING", "OPERATIONS", "SECURITY"]:
            try:
                resp = account.get_alternate_contact(AlternateContactType=contact_type)
                contacts[contact_type] = resp.get("AlternateContact", {}).get("EmailAddress", "Set")
            except ClientError as e:
                if e.response["Error"]["Code"] in ("ResourceNotFoundException", "AccessDeniedException"):
                    contacts[contact_type] = None
    except Exception:
        contacts = {"BILLING": None, "OPERATIONS": None, "SECURITY": None}
    return contacts


def check_organizations(session):
    """Check if this account is a management/root account in an Org."""
    try:
        org = session.client("organizations")
        resp = org.describe_organization()["Organization"]
        master_id = resp.get("MasterAccountId")
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        return account_id == master_id, resp.get("Id"), resp.get("Arn")
    except ClientError:
        return False, None, None


def check_support_plan(session):
    """Attempt to determine support plan tier."""
    try:
        support = session.client("support", region_name="us-east-1")
        support.describe_severity_levels(language="en")
        return "Business or higher"
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "SubscriptionRequiredException":
            return "Basic (no paid support)"
        return "Unknown"


# ── Main audit ────────────────────────────────────────────────────────────────

def audit_root(session):
    iam = session.client("iam")

    account_id = None
    try:
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        log.info(f"Account ID: {account_id}")
    except ClientError:
        log.warning("Could not determine account ID")

    log.info("Generating credential report...")
    cred_report = check_credential_report(iam)

    log.info("Checking root MFA...")
    mfa_enabled, mfa_type = check_mfa_devices(iam)

    log.info("Checking root access keys...")
    has_root_keys, key_count = check_root_access_keys(iam)

    log.info("Checking password policy...")
    password_policy, policy_issues = check_password_policy(iam)

    log.info("Checking alternate contacts...")
    alternate_contacts = check_alternate_contacts(account_id, session)
    missing_contacts = [k for k, v in alternate_contacts.items() if v is None]

    log.info("Checking AWS Organizations...")
    is_org_master, org_id, org_arn = check_organizations(session)

    log.info("Checking support plan...")
    support_plan = check_support_plan(session)

    # Parse credential report for root specifics
    root_last_login = None
    root_mfa_active = False
    root_last_used = None
    root_used_recently = False

    if cred_report:
        root_mfa_active = cred_report.get("mfa_active", "false").lower() == "true"
        mfa_enabled = mfa_enabled or root_mfa_active

        last_login = cred_report.get("password_last_used", "N/A")
        if last_login not in ("N/A", "no_information", ""):
            try:
                last_login_dt = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                days_since = (NOW - last_login_dt).days
                root_last_login = last_login
                if days_since < 90:
                    root_used_recently = True
            except Exception:
                root_last_login = last_login

        key1_last = cred_report.get("access_key_1_last_used_date", "N/A")
        key2_last = cred_report.get("access_key_2_last_used_date", "N/A")
        for k in [key1_last, key2_last]:
            if k not in ("N/A", "no_information", ""):
                root_last_used = k

    weak_policy = len(policy_issues) > 0
    no_alternate = len(missing_contacts) > 0

    score, risk_level = calculate_score(
        not mfa_enabled, has_root_keys, root_used_recently,
        weak_policy, no_alternate, support_plan == "Basic (no paid support)",
        0
    )

    flags = []
    if not mfa_enabled:
        flags.append("❌ CRITICAL: Root account has NO MFA enabled")
    else:
        flags.append(f"✅ Root MFA enabled ({mfa_type or 'confirmed via credential report'})")
    if has_root_keys:
        flags.append(f"❌ CRITICAL: {key_count} root access key(s) exist — delete immediately")
    else:
        flags.append("✅ No root access keys present")
    if root_used_recently:
        flags.append(f"⚠️ Root account was used recently (last login: {root_last_login})")
    elif root_last_login:
        flags.append(f"ℹ️ Root last login: {root_last_login}")
    else:
        flags.append("✅ No recent root console logins detected")
    for issue in policy_issues:
        flags.append(f"⚠️ Password policy: {issue}")
    for contact in missing_contacts:
        flags.append(f"⚠️ Alternate contact missing: {contact}")
    if is_org_master:
        flags.append("ℹ️ This is the AWS Organizations management account")
    if support_plan == "Basic (no paid support)":
        flags.append("ℹ️ Basic support plan — consider upgrading for security response SLAs")

    return {
        "account_id": account_id,
        "risk_level": risk_level,
        "severity_score": score,
        "root_mfa_enabled": mfa_enabled,
        "root_mfa_type": mfa_type,
        "root_access_keys_present": has_root_keys,
        "root_access_key_count": key_count,
        "root_last_console_login": root_last_login,
        "root_used_recently": root_used_recently,
        "root_key_last_used": root_last_used,
        "password_policy_issues": policy_issues,
        "password_policy": password_policy,
        "alternate_contacts": alternate_contacts,
        "missing_alternate_contacts": missing_contacts,
        "is_org_management_account": is_org_master,
        "org_id": org_id,
        "support_plan": support_plan,
        "flags": flags,
    }


# ── Output formatters ─────────────────────────────────────────────────────────

def write_json(report, path):
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    log.info(f"JSON report: {path}")


def write_csv(findings, path):
    fieldnames = [
        "account_id", "risk_level", "severity_score",
        "root_mfa_enabled", "root_mfa_type",
        "root_access_keys_present", "root_access_key_count",
        "root_last_console_login", "root_used_recently",
        "root_key_last_used", "password_policy_issues",
        "missing_alternate_contacts", "is_org_management_account",
        "support_plan", "flags",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        row = findings.copy()
        for field in ["password_policy_issues", "missing_alternate_contacts", "flags"]:
            val = row.get(field, [])
            row[field] = "; ".join(val) if isinstance(val, list) else (val or "")
        row.pop("password_policy", None)
        row.pop("alternate_contacts", None)
        writer.writerow(row)
    log.info(f"CSV report: {path}")


def write_html(report, path):
    f = report["finding"]
    generated = report["generated_at"]
    risk_colors = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "LOW": "#27ae60"}
    color = risk_colors.get(f["risk_level"], "#999")
    flags_html = "".join(f'<li>{flag}</li>' for flag in f.get("flags", []))
    policy_html = "".join(f'<li>{issue}</li>' for issue in f.get("password_policy_issues", []))

    contacts = f.get("alternate_contacts", {})
    contact_rows = "".join(
        f'<tr><td>{k}</td><td>{"✅ " + v if v else "❌ Not configured"}</td></tr>'
        for k, v in contacts.items()
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Root Account Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f5f6fa; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #2c3e50, #c0392b); color: white; padding: 30px 40px; }}
  .header h1 {{ margin: 0; font-size: 1.8em; }}
  .header p {{ margin: 5px 0 0; opacity: 0.8; }}
  .content {{ padding: 30px 40px; display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  .card {{ background: white; border-radius: 8px; padding: 25px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  .card h2 {{ margin: 0 0 15px; font-size: 1em; text-transform: uppercase; letter-spacing: 0.5px; color: #666; }}
  .risk-badge {{ display: inline-block; background: {color}; color: white; padding: 6px 18px; border-radius: 20px; font-weight: bold; font-size: 1.2em; margin-bottom: 10px; }}
  .score {{ font-size: 3em; font-weight: bold; color: {color}; }}
  ul {{ margin: 0; padding-left: 20px; line-height: 1.9; }}
  table {{ width: 100%; border-collapse: collapse; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #ecf0f1; }}
  tr:last-child td {{ border-bottom: none; }}
  .metric {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #ecf0f1; }}
  .metric:last-child {{ border-bottom: none; }}
  .metric .label {{ color: #666; }}
  .metric .value {{ font-weight: bold; }}
  .footer {{ text-align: center; padding: 20px; color: #999; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="header">
  <h1>👑 Root Account Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; Account: {f['account_id']}</p>
</div>
<div class="content">
  <div class="card">
    <h2>Overall Risk</h2>
    <div class="risk-badge">{f['risk_level']}</div>
    <div class="score">{f['severity_score']}/10</div>
  </div>
  <div class="card">
    <h2>Key Metrics</h2>
    <div class="metric"><span class="label">Root MFA</span><span class="value">{'✅ Enabled' if f['root_mfa_enabled'] else '❌ NOT ENABLED'}</span></div>
    <div class="metric"><span class="label">Root Access Keys</span><span class="value">{'❌ ' + str(f['root_access_key_count']) + ' key(s) exist' if f['root_access_keys_present'] else '✅ None'}</span></div>
    <div class="metric"><span class="label">Root Used Recently</span><span class="value">{'⚠️ Yes' if f['root_used_recently'] else '✅ No'}</span></div>
    <div class="metric"><span class="label">Last Login</span><span class="value">{f['root_last_console_login'] or 'Never / Unknown'}</span></div>
    <div class="metric"><span class="label">Org Management Account</span><span class="value">{'Yes — ' + (f['org_id'] or '') if f['is_org_management_account'] else 'No'}</span></div>
    <div class="metric"><span class="label">Support Plan</span><span class="value">{f['support_plan']}</span></div>
  </div>
  <div class="card">
    <h2>Findings & Flags</h2>
    <ul>{flags_html}</ul>
  </div>
  <div class="card">
    <h2>Password Policy Issues</h2>
    {'<ul>' + policy_html + '</ul>' if policy_html else '<p style="color:#27ae60">✅ No major policy issues</p>'}
  </div>
  <div class="card">
    <h2>Alternate Contacts</h2>
    <table>{contact_rows}</table>
  </div>
</div>
<div class="footer">Root Account Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, "w") as fh:
        fh.write(html)
    log.info(f"HTML report: {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(output_prefix="root_report", fmt="all", profile=None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()

    log.info("Auditing root account security posture...")
    finding = audit_root(session)

    report = {
        "generated_at": NOW.isoformat(),
        "account_id": finding.get("account_id"),
        "finding": finding,
    }

    if fmt in ("json", "all"):
        write_json(report, f"{output_prefix}.json")
    if fmt in ("csv", "all"):
        write_csv(finding, f"{output_prefix}.csv")
    if fmt in ("html", "all"):
        write_html(report, f"{output_prefix}.html")
    if fmt == "stdout":
        print(json.dumps(report, indent=2, default=str))

    f = finding
    print(f"""
╔══════════════════════════════════════════╗
║      ROOT ACCOUNT AUDITOR — SUMMARY      ║
╠══════════════════════════════════════════╣
║  Account ID:          {f.get('account_id', 'Unknown'):<20}║
║  Risk Level:          {f['risk_level']:<20}║
║  Severity Score:      {f['severity_score']}/10{'':<17}║
║  Root MFA:            {'✅ Enabled' if f['root_mfa_enabled'] else '❌ NOT ENABLED':<20}║
║  Root Access Keys:    {'❌ Present (' + str(f['root_access_key_count']) + ')' if f['root_access_keys_present'] else '✅ None':<20}║
║  Root Used Recently:  {'⚠️  Yes' if f['root_used_recently'] else '✅ No':<20}║
║  Missing Contacts:    {', '.join(f['missing_alternate_contacts']) or 'None':<20}║
║  Support Plan:        {f['support_plan']:<20}║
╚══════════════════════════════════════════╝
""")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Root Account Auditor")
    parser.add_argument("--output", "-o", default="root_report", help="Output file prefix (default: root_report)")
    parser.add_argument("--format", "-f", choices=["json", "csv", "html", "all", "stdout"], default="all", help="Output format (default: all)")
    parser.add_argument("--profile", default=None, help="AWS CLI profile name to use")
    args = parser.parse_args()
    run(output_prefix=args.output, fmt=args.format, profile=args.profile)
