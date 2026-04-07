#!/usr/bin/env python3
"""Executive Summary Report aggregator.

Reads JSON output files from AWS and Azure auditor scripts and generates
a single executive-facing HTML report.

Score algorithm (100 − weighted deductions):
  CRITICAL = -8 pts, HIGH = -3 pts, MEDIUM = -1 pt, LOW = 0 pts

Weights are calibrated for SMB environments where first-time assessments
typically produce 10–20 CRITICAL findings.  At -8 pts/CRITICAL a client
needs 13 CRITICALs to reach score 0 — enough to show real severity without
making every first-time client read an identical "F / 0" score.
"""
import json
import os
import html as html_lib
import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

# Known report filename patterns (auto-discovered)
KNOWN_PATTERNS = [
    "s3_report.json",
    "sg_report.json",
    "cloudtrail_report.json",
    "root_report.json",
    "iam_report.json",
    "ec2_report.json",
    "rds_report.json",
    "guardduty_report.json",
    "vpcflowlogs_report.json",
    "lambda_report.json",
    "securityhub_report.json",
    # Azure (JSON output from Azure scripts if run with -Format json)
    "keyvault_report.json",
    "storage_report.json",
    "nsg_report.json",
    "activitylog_report.json",
    "subscription_report.json",
    "entra_report.json",
    "entrapwd_report.json",
    # Windows on-prem
    "ad_report.json",
    "localuser_report.json",
    "winfirewall_report.json",
    "smbsigning_report.json",
    "auditpolicy_report.json",
    "bitlocker_report.json",
    # Linux on-prem
    "user_report.json",
    "fw_report.json",
    "sysctl_report.json",
    "patch_report.json",
    "ssh_report.json",
    # Additional AWS
    "kms_report.json",
    "elb_report.json",
    # Additional Azure
    "defender_report.json",
    # Email security
    "email_report.json",
    # Network / SSL-TLS
    "ssl_report.json",
    # Network / HTTP Headers
    "http_headers_report.json",
    # M365 / Exchange Online
    "m365_report.json",
    "sharepoint_report.json",
    "teams_report.json",
    "intune_report.json",
    "exchange_report.json",
    # Additional AWS
    "config_report.json",
    "backup_report.json",
    # Additional Azure
    "policy_report.json",
    "azbackup_report.json",
    # Windows on-prem
    "laps_report.json",
    "winpatch_report.json",
    "netexpose_report.json",
    # M365 endpoint security
    "mde_report.json",
]

# Azure/Windows patterns that require manual copy-back from a Windows machine.
# exec_summary warns if none of these are present (silent incompleteness risk).
AZURE_WINDOWS_PATTERNS = [
    "keyvault_report.json",
    "storage_report.json",
    "nsg_report.json",
    "activitylog_report.json",
    "subscription_report.json",
    "entra_report.json",
    "entrapwd_report.json",
    "defender_report.json",
    "ad_report.json",
    "localuser_report.json",
    "winfirewall_report.json",
    "smbsigning_report.json",
    "auditpolicy_report.json",
    "bitlocker_report.json",
    "m365_report.json",
    "sharepoint_report.json",
    "teams_report.json",
    "intune_report.json",
    "exchange_report.json",
    "policy_report.json",
    "azbackup_report.json",
    "laps_report.json",
    "winpatch_report.json",
    "netexpose_report.json",
    # M365 endpoint security
    "mde_report.json",
]

# Human-readable names for display
PILLAR_LABELS = {
    "s3": "S3 Buckets",
    "sg": "Security Groups",
    "cloudtrail": "CloudTrail",
    "root": "Root Account",
    "iam": "IAM Privileges",
    "ec2": "EC2 Instances",
    "rds": "RDS Databases",
    "guardduty": "GuardDuty",
    "vpcflowlogs": "VPC Flow Logs",
    "lambda": "Lambda Functions",
    "securityhub": "Security Hub",
    "keyvault": "Azure Key Vault",
    "storage": "Azure Storage",
    "nsg": "Azure NSGs",
    "activitylog": "Azure Activity Log",
    "subscription": "Azure Subscription",
    "entra": "Azure Entra ID",
    "entrapwd": "Entra Password Policy",
    "m365": "M365 / Exchange Online",
    "sharepoint": "SharePoint Online",
    "teams": "Microsoft Teams",
    "intune": "Intune Device Compliance",
    "exchange": "Exchange Online",
    "ad": "Active Directory",
    "localuser": "Local Users",
    "winfirewall": "Windows Firewall",
    "smbsigning": "SMB Signing",
    "auditpolicy": "Audit Policy",
    "bitlocker": "BitLocker",
    "user": "Linux Users",
    "fw": "Linux Firewall",
    "sysctl": "Linux Sysctl Hardening",
    "patch": "Linux Patch Status",
    "kms": "AWS KMS Keys",
    "elb": "Load Balancers",
    "defender": "Defender for Cloud",
    "email": "Email Security (SPF/DKIM/DMARC)",
    "ssl":   "SSL/TLS Certificates",
    "http_headers": "HTTP Security Headers",
    "config": "AWS Config",
    "backup": "AWS Backup",
    "policy": "Azure Policy",
    "azbackup": "Azure Backup",
    "laps": "Windows LAPS",
    "winpatch": "Windows Patch Status",
    "netexpose": "Network Exposure",
    "mde":      "Defender for Endpoint",
}

GRADE_COLOURS = {
    "A": "#28a745", "B": "#5cb85c", "C": "#ffc107", "D": "#fd7e14", "F": "#dc3545"
}

RISK_COLOURS = {
    "CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#28a745",
    "UNKNOWN": "#6c757d",   # grey — pillar unverifiable (e.g. SSH without sudo)
}


def load_report(path):
    """Load a JSON report file. Returns dict or None on error."""
    # Try UTF-8-SIG first (handles PowerShell UTF-8 BOM and plain UTF-8),
    # then UTF-16 (PowerShell Out-File default on Windows PS5), then cp1252.
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            with open(path, encoding=enc) as f:
                return json.load(f)
        except (UnicodeDecodeError, UnicodeError):
            continue
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None
    return None


def discover_reports(directory):
    """Return list of paths to report files found in directory.

    Primary: matches KNOWN_PATTERNS (preserves ordering).
    Fallback: globs *_report.json for any file not already in the known list,
    so new auditors are picked up without manual KNOWN_PATTERNS edits.
    """
    found = []
    found_set = set()
    for pattern in KNOWN_PATTERNS:
        p = os.path.join(directory, pattern)
        if os.path.exists(p):
            found.append(p)
            found_set.add(os.path.abspath(p))
    # Glob fallback — catches any *_report.json not in KNOWN_PATTERNS
    for p in sorted(Path(directory).glob("*_report.json")):
        abs_p = str(p.resolve())
        if abs_p not in found_set:
            found.append(str(p))
            found_set.add(abs_p)
    return found


_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def compute_pillar_stats(pillar_name, report):
    """Compute risk counts and overall risk level for a single pillar report."""
    raw_findings = report.get("findings", [])
    findings = []
    for f in raw_findings:
        try:
            findings.append(validate_finding(f))
        except (ValueError, TypeError) as exc:
            log.warning("Skipping malformed finding in %s pillar: %s", pillar_name, exc)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        rl = f.get("risk_level", "LOW")
        counts[rl] = counts.get(rl, 0) + 1

    if counts["CRITICAL"] > 0:
        pillar_risk = "CRITICAL"
    elif counts["HIGH"] > 0:
        pillar_risk = "HIGH"
    elif counts["MEDIUM"] > 0:
        pillar_risk = "MEDIUM"
    else:
        pillar_risk = "LOW"

    # Bug 2 fix: honour the report's own overall_risk classification if more severe
    summary_risk = report.get("summary", {}).get("overall_risk", "").upper()
    if summary_risk in _SEVERITY_RANK:
        if _SEVERITY_RANK[summary_risk] < _SEVERITY_RANK.get(pillar_risk, 3):
            pillar_risk = summary_risk

    # P1-2: SSH pillar — escalate to UNKNOWN when >50% findings are N/A (no sudo).
    # N/A findings have compliant=null and are downgraded to LOW, producing a
    # false-safe signal. UNKNOWN signals "incomplete audit" rather than "low risk".
    # Only fires when sshd IS installed — if ssh_daemon_installed==False the
    # auditor returned 0 findings and UNKNOWN must not trigger.
    if pillar_name == "ssh" and report.get("ssh_daemon_installed", True):
        na_count = sum(1 for f in findings if f.get("compliant") is None)
        if findings and na_count / len(findings) > 0.5:
            pillar_risk = "UNKNOWN"

    return {
        "pillar": pillar_name,
        "label": PILLAR_LABELS.get(pillar_name, pillar_name.upper()),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "total": len(findings),
        "pillar_risk": pillar_risk,
        "generated_at": report.get("generated_at", ""),
    }


FULL_LINUX_AUDIT_MODULES = {"user", "fw", "sysctl", "patch", "ssh", "ssl", "http_headers"}

# Grade + scoring logic extracted to scoring.py for unit-testable isolation
import sys as _sys
import os as _os
_sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scoring import compute_overall_score  # noqa: E402
from schema import validate_finding        # noqa: E402


def get_top_findings(all_findings, n=10):
    """Return top N findings sorted by severity_score descending."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(
        all_findings,
        key=lambda f: (severity_order.get(f.get("risk_level") or f.get("severity", "LOW"), 3),
                       -f.get("severity_score", 0))
    )
    return sorted_findings[:n]


def get_quick_wins(all_findings, max_wins=10):
    """
    Return quick-win items: low-effort fixes with meaningful security impact.

    Two sources:
    1. ℹ️-flagged issues on HIGH/CRITICAL findings (AWS-style list schema).
    2. MEDIUM FAIL findings with a remediation string and no flags (SSL/HTTP-style
       single-string schema). MEDIUM findings are inherently lower-effort fixes.
    """
    wins = []
    for finding in all_findings:
        flags = finding.get("flags", [])
        remediations = finding.get("remediations", [])

        # Source 1: ℹ️ flags on HIGH/CRITICAL (AWS-style schema)
        if finding.get("risk_level") in ("HIGH", "CRITICAL") and flags:
            for i, flag in enumerate(flags):
                if flag.startswith("ℹ️"):
                    rem = remediations[i] if i < len(remediations) else ""
                    wins.append({
                        "pillar": finding.get("pillar", ""),
                        "risk_level": finding.get("risk_level"),
                        "resource": (finding.get("name") or finding.get("bucket_name")
                                     or finding.get("group_id") or finding.get("instance_id")
                                     or finding.get("db_identifier") or ""),
                        "flag": flag,
                        "remediation": rem,
                    })
                    if len(wins) >= max_wins:
                        return wins

        # Source 2: MEDIUM FAIL with remediation string (SSL/HTTP-style schema)
        elif (not flags
              and finding.get("status") == "FAIL"
              and finding.get("risk_level") == "MEDIUM"
              and finding.get("remediation")):
            wins.append({
                "pillar": finding.get("pillar", ""),
                "risk_level": finding.get("risk_level"),
                "resource": (finding.get("name") or finding.get("resource") or ""),
                "flag": finding.get("detail", "Fix available"),
                "remediation": finding.get("remediation", ""),
            })
            if len(wins) >= max_wins:
                return wins

    return wins


def write_html(overall_score, grade, pillar_stats, top_findings, quick_wins,
               generated_at, path, client_name="", assessor="", scope="",
               grade_note="", modules_scanned=None, not_run_pillars=None,
               baseline_data=None):
    """Write executive summary HTML report to path with 0o600 permissions."""
    grade_colour = GRADE_COLOURS.get(grade, "#6c757d")
    is_capped = bool(grade_note)
    total_modules = len(FULL_LINUX_AUDIT_MODULES)

    # Pillar cards — with inline dot legend per card
    pillar_cards_html = ""
    for ps in pillar_stats:
        risk = ps["pillar_risk"]
        colour = RISK_COLOURS.get(risk, "#6c757d")
        pillar_cards_html += f"""
        <div class="pillar-card" style="border-left:5px solid {colour}">
          <div class="pillar-name">{html_lib.escape(ps['label'])}</div>
          <div class="pillar-risk" style="color:{colour}">{risk}</div>
          <div class="pillar-counts">
            <span style="color:#dc3545" title="Critical">● CRIT {ps['critical']}</span>
            <span style="color:#fd7e14" title="High">● HIGH {ps['high']}</span>
            <span style="color:#ffc107" title="Medium">● MED {ps['medium']}</span>
            <span style="color:#28a745" title="Low">● LOW {ps['low']}</span>
          </div>
          <div class="pillar-total">{ps['total']} resources checked</div>
        </div>"""
    # Not-run pillar cards (auditor attempted but produced no report JSON)
    for pname in (not_run_pillars or []):
        label = html_lib.escape(PILLAR_LABELS.get(pname, pname.upper()))
        pillar_cards_html += (
            f'<div class="pillar-card" style="border-left:5px solid #adb5bd;opacity:0.65">'
            f'<div class="pillar-name">{label}</div>'
            f'<div class="pillar-risk" style="color:#adb5bd">NOT RUN</div>'
            f'<div class="pillar-total" style="color:#adb5bd">Auditor ran but no report found</div>'
            f'</div>'
        )

    # Top findings table rows
    finding_rows = ""
    for f in top_findings:
        risk = f.get("risk_level") or f.get("severity", "LOW")
        colour = RISK_COLOURS.get(risk, "#6c757d")
        resource = (f.get("name") or f.get("bucket_name") or f.get("group_id")
                    or f.get("instance_id") or f.get("db_identifier") or f.get("resource")
                    or f.get("param") or "—")
        # Use flags/remediations lists (AWS-style) or fall back to detail/flag/remediation strings (Linux/SSL-style)
        raw_flags = f.get("flags", [])
        display_flags = (raw_flags if raw_flags
                         else ([f["detail"]] if f.get("detail")
                               else ([f["flag"]] if f.get("flag") else [])))
        display_rems = (f.get("remediations", []) if raw_flags
                        else [f.get("remediation") or f.get("recommendation") or ""])
        flag_items = []
        for flag, rem in zip(display_flags, display_rems):
            flag_items.append(
                f'<div class="flag-item">'
                f'<span class="flag-text">{html_lib.escape(flag)}</span>'
                + (f'<span class="rem-text">↳ {html_lib.escape(rem)}</span>' if rem else '')
                + f'</div>'
            )
        for flag in display_flags[len(display_rems):]:
            flag_items.append(
                f'<div class="flag-item"><span class="flag-text">{html_lib.escape(flag)}</span></div>'
            )
        finding_rows += (
            f'<tr data-risk="{risk}">'
            f'<td>{html_lib.escape(PILLAR_LABELS.get(f.get("pillar", ""), f.get("pillar", "").upper()))}</td>'
            f'<td><span style="background:{colour};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em">{risk}</span></td>'
            f'<td><code>{html_lib.escape(str(resource))}</code></td>'
            f'<td>{"".join(flag_items)}</td>'
            f'</tr>\n'
        )

    # Quick wins rows
    qw_rows = ""
    for w in quick_wins:
        qw_rows += (
            f'<tr>'
            f'<td>{html_lib.escape(PILLAR_LABELS.get(w.get("pillar", ""), w.get("pillar", "").upper()))}</td>'
            f'<td><code>{html_lib.escape(str(w.get("resource", "—")))}</code></td>'
            f'<td>{html_lib.escape(w.get("flag", ""))}</td>'
            f'<td style="font-size:0.85em;color:#555;font-style:italic">{html_lib.escape(w.get("remediation", ""))}</td>'
            f'</tr>\n'
        )

    # P1-4: CRITICAL callout block — up to 3 critical findings, plain-English, above the main table
    critical_only = [
        f for f in top_findings
        if (f.get("risk_level") or f.get("severity", "")).upper() == "CRITICAL"
    ][:3]
    crit_callout_html = ""
    if critical_only:
        crit_items_html = ""
        for f in critical_only:
            pillar_label = html_lib.escape(
                PILLAR_LABELS.get(f.get("pillar", ""), f.get("pillar", "").upper())
            )
            raw_flags = f.get("flags", [])
            detail = (raw_flags[0] if raw_flags
                      else f.get("detail") or f.get("flag") or "")
            rem = (f.get("remediations", [""])[0] if f.get("remediations")
                   else f.get("remediation") or f.get("recommendation") or "")
            crit_items_html += (
                f'<div class="crit-item">'
                f'<div class="crit-meta"><span class="crit-badge">CRITICAL</span>'
                f' <strong>{pillar_label}</strong></div>'
                f'<div class="crit-detail">{html_lib.escape(detail)}</div>'
                + (f'<div class="crit-rem">\u21b3 {html_lib.escape(rem)}</div>' if rem else '')
                + '</div>'
            )
        crit_callout_html = (
            '<div class="section crit-callout">'
            '<h2>\u26a0 Critical Findings \u2014 Requires Immediate Action</h2>'
            '<p style="color:#666;font-size:0.9em;margin:0 0 16px">'
            'These findings represent active risk to your business. '
            'Address these before any other remediation work.</p>'
            f'<div class="crit-items">{crit_items_html}</div>'
            '</div>'
        )

    no_top_findings = ('<tr><td colspan="4" style="text-align:center;color:#888">'
                       'No high/critical findings — great work!</td></tr>') if not top_findings else ""
    no_quick_wins = ('<tr><td colspan="4" style="text-align:center;color:#888">'
                     'No quick wins identified.</td></tr>') if not quick_wins else ""

    client_meta_lines = []
    if client_name:
        client_meta_lines.append(f'<p style="color:#ccc;margin:8px 0 0;font-size:0.95em">{html_lib.escape(client_name)}</p>')
    if assessor:
        client_meta_lines.append(f'<p style="color:#aaa;margin:4px 0 0;font-size:0.85em">Prepared by: {html_lib.escape(assessor)}</p>')
    client_meta_html = "".join(client_meta_lines)

    scope_section_html = ""
    if scope:
        scope_section_html = f"""
<div class="scope-note">
  <strong>Scope of Assessment</strong>
  <p style="margin:8px 0 0;color:#555;font-size:0.92em">{html_lib.escape(scope)}</p>
</div>"""

    footer_client = html_lib.escape(client_name) if client_name else "Security Assessment"
    footer_assessor = html_lib.escape(assessor) if assessor else "SecurityAuditScripts"

    # Grade badge — capped state gets warning border and subtitle
    capped_class = " capped" if is_capped else ""
    if grade == "?":
        grade_badge_inner = '<span class="grade-letter">—</span><span class="grade-subtitle">Insufficient coverage</span>'
    elif is_capped:
        grade_badge_inner = (f'<span class="grade-letter">Grade: {grade}</span>'
                             f'<span class="grade-subtitle">{html_lib.escape(grade_note)}</span>')
    else:
        grade_badge_inner = f'<span class="grade-letter">Grade: {grade}</span>'

    # Coverage note for score zone
    coverage_html = ""
    if modules_scanned is not None and modules_scanned < total_modules:
        coverage_html = (f'<p class="coverage-note">Score based on {modules_scanned} of '
                         f'{total_modules} audit modules.</p>')

    # Diff section (item 9) — only rendered when baseline_data is provided
    diff_section_html = ""
    if baseline_data:
        baseline_findings = {
            (f.get("pillar", ""), f.get("finding_type") or f.get("check") or f.get("param") or "")
            for f in baseline_data.get("top_findings", [])
        }
        current_findings = {
            (f.get("pillar", ""), f.get("finding_type") or f.get("check") or f.get("param") or "")
            for f in top_findings
        }
        fixed = baseline_findings - current_findings
        new_issues = current_findings - baseline_findings
        baseline_score = baseline_data.get("score", "?")
        baseline_grade = baseline_data.get("grade", "?")

        fixed_rows = "".join(
            f'<div class="diff-row diff-fixed">&#10003; {html_lib.escape(p.upper())} — {html_lib.escape(t)}</div>'
            for p, t in sorted(fixed) if p or t
        ) or '<div class="diff-row" style="color:#888">No newly fixed findings in top-N list.</div>'
        new_rows = "".join(
            f'<div class="diff-row diff-new">&#x2715; {html_lib.escape(p.upper())} — {html_lib.escape(t)}</div>'
            for p, t in sorted(new_issues) if p or t
        ) or '<div class="diff-row" style="color:#888">No new findings since baseline.</div>'

        diff_section_html = (
            f'<div class="section"><div class="diff-section">'
            f'<h2 style="font-size:1.1em;margin-bottom:16px">&#128200; Change Since Baseline '
            f'(Score: {baseline_score} {baseline_grade} &rarr; {overall_score} {grade})</h2>'
            f'<h3 class="diff-fixed">&#10003; Fixed ({len(fixed)})</h3>{fixed_rows}'
            f'<h3 class="diff-new" style="margin-top:14px">&#x2715; New ({len(new_issues)})</h3>{new_rows}'
            f'</div></div>'
        )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Security Executive Summary{' — ' + html_lib.escape(client_name) if client_name else ''}</title>
<style>
  /* === BRAND TOKENS — DO NOT CHANGE INDEPENDENTLY ===
     brand-dark:   #1a1a2e  (headers, th, dark chrome)
     body-text:    #333     (paragraph text)
     body-bg:      #f5f6fa  (page background)
     badge-radius: 8px
     ================================================ */
  body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; margin:0; background:#f5f6fa; color:#333; }}
  .header {{ background:#1a1a2e; color:#fff; padding:40px; text-align:center; }}
  .section {{ padding:24px 40px; }}
  .section h2 {{ font-size:1.2em; color:#333; margin-bottom:16px; border-bottom:2px solid #e0e0e0; padding-bottom:8px; }}
  .pillars {{ display:flex; flex-wrap:wrap; gap:16px; }}
  .pillar-card {{ background:#fff; border-radius:8px; padding:16px 20px; min-width:160px; box-shadow:0 2px 8px rgba(0,0,0,.06); }}
  .pillar-name {{ font-weight:600; font-size:0.95em; margin-bottom:4px; }}
  .pillar-risk {{ font-weight:700; font-size:1.1em; margin-bottom:6px; }}
  .pillar-counts {{ font-size:0.82em; letter-spacing:0; margin-bottom:4px; display:flex; gap:10px; flex-wrap:wrap; }}
  .pillar-total {{ font-size:0.78em; color:#888; }}
  .score-zone {{ background:#fff; border-radius:8px; padding:28px 32px; margin:0 40px 24px; box-shadow:0 2px 8px rgba(0,0,0,.06); text-align:center; }}
  .score-gauge {{ font-size:5em; font-weight:900; color:{grade_colour}; line-height:1; }}
  .score-label {{ font-size:1.2em; color:#666; margin-top:8px; }}
  .grade-badge {{ display:inline-flex; flex-direction:column; align-items:center; background:{grade_colour}; color:#fff; padding:8px 24px; border-radius:20px; margin:12px 0; }}
  .grade-badge.capped {{ border:3px solid #dc3545; box-shadow:0 0 0 2px #dc354533; }}
  .grade-letter {{ font-size:1.4em; font-weight:700; line-height:1.2; }}
  .grade-subtitle {{ font-size:0.72em; font-weight:400; opacity:0.92; margin-top:2px; }}
  .score-bands {{ font-size:0.8em; color:#999; margin-top:8px; letter-spacing:1px; }}
  .score-bands span {{ margin:0 6px; }}
  .coverage-note {{ font-size:0.82em; color:#888; margin:6px 0 0; font-style:italic; }}
  .scope-note {{ background:#fff; border-left:4px solid #1a1a2e; margin:0 40px; padding:16px 20px; border-radius:0 8px 8px 0; box-shadow:0 2px 8px rgba(0,0,0,.06); }}
  table {{ width:100%; border-collapse:collapse; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,.06); }}
  th {{ background:#1a1a2e; color:#fff; padding:10px 14px; text-align:left; font-size:0.85em; text-transform:uppercase; letter-spacing:0.5px; }}
  td {{ padding:10px 14px; border-bottom:1px solid #f0f0f0; font-size:0.88em; vertical-align:top; }}
  tr:hover td {{ background:#fafbff; }}
  .next-steps {{ padding-left:20px; margin:0; color:#444; }}
  .next-steps li {{ padding:4px 0; font-size:0.92em; }}
  .footer {{ text-align:center; padding:20px; color:#999; font-size:0.85em; border-top:1px solid #e0e0e0; margin-top:20px; }}
  .flag-item {{ margin-bottom:6px; }}
  .flag-text {{ display:block; font-size:0.85em; }}
  .rem-text {{ display:block; font-size:0.78em; color:#555; padding-left:12px; font-style:italic; }}
  .crit-callout {{ border-top:3px solid #dc3545; }}
  .crit-callout h2 {{ color:#dc3545; border-color:#dc354533; }}
  .crit-items {{ display:flex; flex-direction:column; gap:12px; }}
  .crit-item {{ background:#fff5f5; border-left:4px solid #dc3545; border-radius:0 8px 8px 0; padding:14px 18px; }}
  .crit-meta {{ margin-bottom:6px; display:flex; align-items:center; gap:10px; font-size:0.9em; }}
  .crit-badge {{ background:#dc3545; color:#fff; padding:2px 8px; border-radius:4px; font-size:0.78em; font-weight:700; letter-spacing:0.5px; }}
  .crit-detail {{ font-size:0.88em; color:#333; margin-bottom:4px; }}
  .crit-rem {{ font-size:0.82em; color:#555; font-style:italic; }}
  .filter-bar {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px; }}
  .filter-btn {{ padding:4px 14px; border:1px solid #ccc; border-radius:16px; background:#fff;
                cursor:pointer; font-size:0.82em; font-weight:600; transition:background 0.15s; }}
  .filter-btn:hover {{ background:#f0f4ff; }}
  .filter-btn.active {{ color:#fff; border-color:transparent; }}
  .filter-btn[data-f="ALL"].active {{ background:#1a1a2e; }}
  .filter-btn[data-f="CRITICAL"].active {{ background:#dc3545; }}
  .filter-btn[data-f="HIGH"].active {{ background:#fd7e14; }}
  .filter-btn[data-f="MEDIUM"].active {{ background:#c9a000; }}
  .filter-btn[data-f="LOW"].active {{ background:#28a745; }}
  tr[data-risk].hidden {{ display:none; }}
  .diff-section {{ background:#fff; border-radius:8px; padding:20px 24px;
                   margin:0 40px 24px; box-shadow:0 2px 8px rgba(0,0,0,.06); }}
  .diff-section h3 {{ font-size:1em; margin:0 0 10px; }}
  .diff-fixed {{ color:#28a745; font-weight:700; }}
  .diff-new {{ color:#dc3545; font-weight:700; }}
  .diff-row {{ font-size:0.85em; padding:4px 0; border-bottom:1px solid #f5f5f5; }}
  @media print {{
    body {{ font-size:10pt; }}
    .header {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
    .card {{ box-shadow:none; border:1px solid #ddd; }}
    table {{ box-shadow:none; }}
    .footer {{ display:none; }}
    .filter-bar {{ display:none; }}
    tr[data-risk].hidden {{ display:table-row !important; }}
  }}
</style>
</head>
<body>
<div class="header">
  {client_meta_html}
  <p style="color:#aaa;margin:8px 0 0;font-size:0.85em">Generated: {html_lib.escape(generated_at)} &nbsp;|&nbsp; {len(pillar_stats)} pillar{'s' if len(pillar_stats) != 1 else ''} analysed</p>
</div>
{scope_section_html}
<div class="section">
  <h2>Security Posture by Pillar</h2>
  <div class="pillars">{pillar_cards_html}</div>
</div>

<div class="score-zone">
  <div class="score-gauge">{overall_score}</div>
  <div class="score-label">/ 100 &nbsp; Security Score</div>
  <p style="text-align:center;color:#888;font-size:0.85rem;margin:4px 0 8px;letter-spacing:0.08em;text-transform:uppercase">Security Assessment Report</p>
  <div class="grade-badge{capped_class}">{grade_badge_inner}</div>
  <div class="score-bands">
    <span style="color:#28a745">A ≥85</span>
    <span style="color:#5cb85c">B ≥70</span>
    <span style="color:#ffc107">C ≥55</span>
    <span style="color:#fd7e14">D ≥40</span>
    <span style="color:#dc3545">F &lt;40</span>
  </div>
  {coverage_html}
</div>

{crit_callout_html}

<div class="section">
  <h2>Top Critical &amp; High Findings</h2>
  <div class="filter-bar">
    <button class="filter-btn active" data-f="ALL" onclick="applyFilter('ALL')">All</button>
    <button class="filter-btn" data-f="CRITICAL" onclick="applyFilter('CRITICAL')">Critical</button>
    <button class="filter-btn" data-f="HIGH" onclick="applyFilter('HIGH')">High</button>
    <button class="filter-btn" data-f="MEDIUM" onclick="applyFilter('MEDIUM')">Medium</button>
    <button class="filter-btn" data-f="LOW" onclick="applyFilter('LOW')">Low</button>
  </div>
  <table id="findings-tbl">
    <thead><tr><th>Pillar</th><th>Risk</th><th>Resource</th><th>Detail &amp; Remediation</th></tr></thead>
    <tbody>{finding_rows or no_top_findings}</tbody>
  </table>
</div>

<div class="section">
  <h2>Quick Wins (Low Effort · High Impact)</h2>
  <table>
    <thead><tr><th>Pillar</th><th>Resource</th><th>Issue</th><th>Remediation</th></tr></thead>
    <tbody>{qw_rows or no_quick_wins}</tbody>
  </table>
</div>

{diff_section_html}

<div class="section">
  <h2>Recommended Next Steps</h2>
  <ol class="next-steps">
    <li><strong>CRITICAL findings:</strong> Address immediately — these represent active risk to your business and may be exploitable now.</li>
    <li><strong>HIGH findings:</strong> Engage your IT team or managed service provider within 30 days.</li>
    <li><strong>Quick Wins:</strong> Implement low-effort remediations first to improve your score with minimal disruption.</li>
    <li><strong>Follow-up assessment:</strong> Schedule a re-assessment after remediation to verify all fixes are effective.</li>
  </ol>
</div>

<div class="footer">Confidential &nbsp;|&nbsp; {footer_client} &nbsp;|&nbsp; {footer_assessor}</div>
<script>
function applyFilter(f) {{
  document.querySelectorAll('#findings-tbl tbody tr[data-risk]').forEach(function(r) {{
    r.classList.toggle('hidden', f !== 'ALL' && r.dataset.risk !== f);
  }});
  document.querySelectorAll('.filter-btn').forEach(function(b) {{
    b.classList.toggle('active', b.dataset.f === f);
  }});
}}
</script>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)
    try:
        os.chmod(path, 0o600)
    except (AttributeError, NotImplementedError):
        pass
    log.info(f"Executive summary written: {path}")


def warn_missing_azure_windows(input_dir):
    """Warn about Azure/Windows report files that were not copied back."""
    found_patterns = {os.path.basename(p) for p in discover_reports(input_dir)}
    missing = [p for p in AZURE_WINDOWS_PATTERNS if p not in found_patterns]
    if missing and len(missing) < len(AZURE_WINDOWS_PATTERNS):
        # Some Azure/Windows files present but others absent — targeted warning
        log.warning(
            "The following Azure/Windows report files were not found in %s — "
            "these pillars will be absent from the executive summary. "
            "Copy the JSON files from your Windows machine first:\n  %s",
            input_dir,
            "\n  ".join(missing),
        )
    elif missing and len(missing) == len(AZURE_WINDOWS_PATTERNS):
        # All absent — likely a pure AWS/Linux run; suppress warning
        pass


def run(input_dir=".", output_path="exec_summary.html", top_n=5, max_wins=10,
        client_name="", assessor="", scope="", baseline_path=""):
    """Discover reports, compute stats, write HTML summary."""
    report_paths = discover_reports(input_dir)
    if not report_paths:
        log.warning(f"No known report files found in {input_dir}")
    warn_missing_azure_windows(input_dir)

    pillar_stats_list = []
    all_findings_flat = []
    found_pillars = set()

    for rpath in report_paths:
        pillar_name = os.path.basename(rpath).replace("_report.json", "")
        report = load_report(rpath)
        if report is None:
            log.warning(f"Skipping unreadable report: {rpath}")
            continue
        stats = compute_pillar_stats(pillar_name, report)
        pillar_stats_list.append(stats)
        found_pillars.add(pillar_name)
        for f in report.get("findings", []):
            all_findings_flat.append({**f, "pillar": pillar_name})
        log.info(f"Loaded {pillar_name}: {stats['total']} findings "
                 f"(CRITICAL={stats['critical']} HIGH={stats['high']})")

    # Load manifest to identify auditors that were attempted but produced no report
    not_run_pillars = []
    manifest_path = os.path.join(input_dir, "audit_manifest.json")
    if os.path.exists(manifest_path):
        manifest = load_report(manifest_path)
        if manifest:
            attempted = manifest.get("auditors_attempted", [])
            # Map auditor keys → pillar names (strip linux_ prefix used in AUDITOR_MAP)
            for key in attempted:
                pillar = key.replace("linux_", "") if key.startswith("linux_") else key
                if pillar not in found_pillars:
                    not_run_pillars.append(pillar)

    modules_scanned = len(pillar_stats_list)
    score, grade, grade_note = compute_overall_score(pillar_stats_list, modules_scanned=modules_scanned)
    top_findings = get_top_findings(all_findings_flat, n=top_n)
    quick_wins = get_quick_wins(all_findings_flat, max_wins=max_wins)

    # Load baseline for diff section
    baseline_data = None
    if baseline_path and os.path.exists(baseline_path):
        baseline_data = load_report(baseline_path)
        if baseline_data is None:
            log.warning(f"Could not load baseline: {baseline_path}")

    # Write machine-readable JSON sidecar for future baseline comparisons
    sidecar_path = os.path.splitext(output_path)[0] + "_data.json"
    sidecar = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "grade": grade,
        "pillar_stats": pillar_stats_list,
        "top_findings": top_findings,
    }
    try:
        with open(sidecar_path, "w") as f:
            json.dump(sidecar, f, indent=2, default=str)
        os.chmod(sidecar_path, 0o600)
        log.info(f"Data sidecar: {sidecar_path}")
    except OSError as exc:
        log.warning(f"Could not write sidecar: {exc}")

    write_html(
        overall_score=score,
        grade=grade,
        pillar_stats=pillar_stats_list,
        top_findings=top_findings,
        quick_wins=quick_wins,
        generated_at=datetime.now(timezone.utc).isoformat(),
        path=output_path,
        client_name=client_name,
        assessor=assessor,
        scope=scope,
        grade_note=grade_note,
        modules_scanned=modules_scanned,
        not_run_pillars=not_run_pillars,
        baseline_data=baseline_data,
    )

    cap_info = f" [{grade_note}]" if grade_note else ""
    log.info(f"Score: {score}/100 (Grade {grade}{cap_info})")
    log.info(f"Executive summary: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Security Executive Summary Report")
    parser.add_argument(
        "--input-dir", default=".",
        help="Directory containing *_report.json files (default: current directory)"
    )
    parser.add_argument(
        "--output", default="exec_summary.html",
        help="Output HTML file path (default: exec_summary.html)"
    )
    parser.add_argument("--top-n", type=int, default=5,
                        help="Number of top findings to show (default: 5)")
    parser.add_argument("--max-wins", type=int, default=10,
                        help="Max quick wins to show (default: 10)")
    parser.add_argument("--client-name", default="",
                        help="Client name to display in the report header and footer")
    parser.add_argument("--assessor", default="",
                        help="Assessor / consultant name to display in the report")
    parser.add_argument("--scope", default="",
                        help="Scope description shown as an intro paragraph in the report")
    parser.add_argument("--baseline", default="",
                        metavar="FILE",
                        help="Path to a previous exec_summary_data.json for diff comparison")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    run(input_dir=args.input_dir, output_path=args.output,
        top_n=args.top_n, max_wins=args.max_wins,
        client_name=args.client_name, assessor=args.assessor, scope=args.scope,
        baseline_path=args.baseline)


if __name__ == "__main__":
    main()
