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
    "defender_report.json",
    "ad_report.json",
    "localuser_report.json",
    "winfirewall_report.json",
    "smbsigning_report.json",
    "auditpolicy_report.json",
    "bitlocker_report.json",
    "m365_report.json",
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
    "m365": "M365 / Exchange Online",
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
    "tls":   "SSL/TLS Certificates",
    "http_headers": "HTTP Security Headers",
}

GRADE_COLOURS = {
    "A": "#28a745", "B": "#5cb85c", "C": "#ffc107", "D": "#fd7e14", "F": "#dc3545"
}

RISK_COLOURS = {
    "CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#28a745"
}


def load_report(path):
    """Load a JSON report file. Returns dict or None on error."""
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def discover_reports(directory):
    """Return list of paths to known report files found in directory."""
    found = []
    for pattern in KNOWN_PATTERNS:
        p = os.path.join(directory, pattern)
        if os.path.exists(p):
            found.append(p)
    return found


_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def compute_pillar_stats(pillar_name, report):
    """Compute risk counts and overall risk level for a single pillar report."""
    findings = report.get("findings", [])
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        # Bug 1 fix: some reports use "severity" instead of "risk_level"
        rl = f.get("risk_level") or f.get("severity", "LOW")
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


def compute_overall_score(pillar_stats_list, modules_scanned=None):
    """
    Compute 0-100 security score, letter grade, and optional cap note.

    Deductions are per-pillar (not per-finding) to avoid inflating the penalty
    for regional auditors that emit one finding per AWS region:
      CRITICAL pillar: -8 pts
      HIGH pillar:     -3 pts
      MEDIUM pillar:   -1 pt
      LOW pillar:       0 pts  (minor issues; not penalised)

    With 20 pillars the worst-case deduction is 160 pts (score floors at 0).
    A typical first-time SMB assessment with 5-8 CRITICAL pillars scores 36-60.

    Returns (score, grade, grade_note) where grade_note is a string describing
    any hard-cap that was applied, or "" if no cap fired.
    """
    if not pillar_stats_list:
        return 100, "A", ""

    deductions = 0
    for stats in pillar_stats_list:
        # Use pillar_risk as the authoritative level (covers summary.overall_risk overrides)
        pr = stats.get("pillar_risk", "LOW")
        if stats.get("critical", 0) > 0 or pr == "CRITICAL":
            deductions += 8
        elif stats.get("high", 0) > 0 or pr == "HIGH":
            deductions += 3
        elif stats.get("medium", 0) > 0 or pr == "MEDIUM":
            deductions += 1

    score = max(0, min(100, 100 - deductions))

    if score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    grade_note = ""

    # Coverage gate: suppress grade if too few modules scanned
    if modules_scanned is not None and modules_scanned <= 3:
        return round(score, 1), "?", "Insufficient coverage"

    # Grade hard-caps (applied in ascending severity order so D-floor wins)
    critical_pillars = [
        s for s in pillar_stats_list
        if s.get("critical", 0) > 0 or s.get("pillar_risk") == "CRITICAL"
    ]

    # a) B-cap: any CRITICAL pillar → grade ≤ B
    if critical_pillars and grade == "A":
        grade = "B"
        grade_note = "capped: CRITICAL pillar present"

    # b) C-cap: 2+ CRITICAL pillars → grade ≤ C
    if len(critical_pillars) >= 2 and grade in ("A", "B"):
        grade = "C"
        grade_note = f"capped: {len(critical_pillars)} CRITICAL pillars"

    # c) D-floor: fw pillar CRITICAL (proxy for no firewall detected) → grade ≤ D
    fw_critical = any(
        s["pillar"] == "fw" and (s.get("critical", 0) > 0 or s.get("pillar_risk") == "CRITICAL")
        for s in pillar_stats_list
    )
    if fw_critical and grade in ("A", "B", "C"):
        grade = "D"
        grade_note = "floored: no firewall detected"

    return round(score, 1), grade, grade_note


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
               grade_note="", modules_scanned=None):
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
            f'<tr>'
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

<div class="section">
  <h2>Top Critical &amp; High Findings</h2>
  <table>
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
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html_content)
    os.chmod(path, 0o600)
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


def run(input_dir=".", output_path="exec_summary.html", top_n=10, max_wins=10,
        client_name="", assessor="", scope=""):
    """Discover reports, compute stats, write HTML summary."""
    report_paths = discover_reports(input_dir)
    if not report_paths:
        log.warning(f"No known report files found in {input_dir}")
    warn_missing_azure_windows(input_dir)

    pillar_stats_list = []
    all_findings_flat = []

    for rpath in report_paths:
        pillar_name = os.path.basename(rpath).replace("_report.json", "")
        report = load_report(rpath)
        if report is None:
            log.warning(f"Skipping unreadable report: {rpath}")
            continue
        stats = compute_pillar_stats(pillar_name, report)
        pillar_stats_list.append(stats)
        for f in report.get("findings", []):
            all_findings_flat.append({**f, "pillar": pillar_name})
        log.info(f"Loaded {pillar_name}: {stats['total']} findings "
                 f"(CRITICAL={stats['critical']} HIGH={stats['high']})")

    modules_scanned = len(pillar_stats_list)
    score, grade, grade_note = compute_overall_score(pillar_stats_list, modules_scanned=modules_scanned)
    top_findings = get_top_findings(all_findings_flat, n=top_n)
    quick_wins = get_quick_wins(all_findings_flat, max_wins=max_wins)

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
    parser.add_argument("--top-n", type=int, default=10,
                        help="Number of top findings to show (default: 10)")
    parser.add_argument("--max-wins", type=int, default=10,
                        help="Max quick wins to show (default: 10)")
    parser.add_argument("--client-name", default="",
                        help="Client name to display in the report header and footer")
    parser.add_argument("--assessor", default="",
                        help="Assessor / consultant name to display in the report")
    parser.add_argument("--scope", default="",
                        help="Scope description shown as an intro paragraph in the report")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    run(input_dir=args.input_dir, output_path=args.output,
        top_n=args.top_n, max_wins=args.max_wins,
        client_name=args.client_name, assessor=args.assessor, scope=args.scope)


if __name__ == "__main__":
    main()
