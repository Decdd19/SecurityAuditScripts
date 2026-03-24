#!/usr/bin/env python3
"""Executive Summary Report aggregator.

Reads JSON output files from AWS and Azure auditor scripts and generates
a single executive-facing HTML report.

Score algorithm (100 − weighted deductions):
  CRITICAL = -8 pts, HIGH = -4 pts, MEDIUM = -2 pts, LOW = -0.5 pts

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
    # Azure (JSON output from Azure scripts if run with -Format json)
    "storage_report.json",
    "nsg_report.json",
    "activitylog_report.json",
    "subscription_report.json",
    "entra_report.json",
    # Windows on-prem
    "ad_report.json",
    "localuser_report.json",
    "winfirewall_report.json",
    # Linux on-prem
    "user_report.json",
    "fw_report.json",
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
    "storage": "Azure Storage",
    "nsg": "Azure NSGs",
    "activitylog": "Azure Activity Log",
    "subscription": "Azure Subscription",
    "entra": "Azure Entra ID",
    "ad": "Active Directory",
    "localuser": "Local Users",
    "winfirewall": "Windows Firewall",
    "user": "Linux Users",
    "fw": "Linux Firewall",
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


def compute_pillar_stats(pillar_name, report):
    """Compute risk counts and overall risk level for a single pillar report."""
    findings = report.get("findings", [])
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


def compute_overall_score(pillar_stats_list):
    """
    Compute 0-100 security score and letter grade.
    Deductions: CRITICAL=-8, HIGH=-4, MEDIUM=-2, LOW=-0.5

    Calibrated for SMB environments: a client needs 13 CRITICALs to reach
    score 0, giving meaningful differentiation between first-time assessments.
    """
    if not pillar_stats_list:
        return 100, "A"

    deductions = 0
    for stats in pillar_stats_list:
        deductions += stats.get("critical", 0) * 8
        deductions += stats.get("high", 0) * 4
        deductions += stats.get("medium", 0) * 2
        deductions += stats.get("low", 0) * 0.5

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

    return round(score, 1), grade


def get_top_findings(all_findings, n=10):
    """Return top N findings sorted by severity_score descending."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(
        all_findings,
        key=lambda f: (severity_order.get(f.get("risk_level", "LOW"), 3),
                       -f.get("severity_score", 0))
    )
    return sorted_findings[:n]


def get_quick_wins(all_findings, max_wins=10):
    """
    Return ℹ️-flagged issues on HIGH/CRITICAL findings.
    These are low-effort (informational severity) but high-impact (on bad resources).
    """
    wins = []
    for finding in all_findings:
        if finding.get("risk_level") not in ("HIGH", "CRITICAL"):
            continue
        flags = finding.get("flags", [])
        remediations = finding.get("remediations", [])
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
    return wins


def write_html(overall_score, grade, pillar_stats, top_findings, quick_wins,
               generated_at, path):
    """Write executive summary HTML report to path with 0o600 permissions."""
    grade_colour = GRADE_COLOURS.get(grade, "#6c757d")

    # Pillar cards
    pillar_cards_html = ""
    for ps in pillar_stats:
        risk = ps["pillar_risk"]
        colour = RISK_COLOURS.get(risk, "#6c757d")
        pillar_cards_html += f"""
        <div class="pillar-card" style="border-left:5px solid {colour}">
          <div class="pillar-name">{html_lib.escape(ps['label'])}</div>
          <div class="pillar-risk" style="color:{colour}">{risk}</div>
          <div class="pillar-counts">
            <span style="color:#dc3545">●{ps['critical']}</span>
            <span style="color:#fd7e14">●{ps['high']}</span>
            <span style="color:#ffc107">●{ps['medium']}</span>
            <span style="color:#28a745">●{ps['low']}</span>
          </div>
          <div class="pillar-total">{ps['total']} resources checked</div>
        </div>"""

    # Top findings table rows
    finding_rows = ""
    for f in top_findings:
        risk = f.get("risk_level", "LOW")
        colour = RISK_COLOURS.get(risk, "#6c757d")
        resource = (f.get("name") or f.get("bucket_name") or f.get("group_id")
                    or f.get("instance_id") or f.get("db_identifier") or f.get("resource") or "—")
        flags = f.get("flags", [])
        rems = f.get("remediations", [])
        flag_items = []
        for flag, rem in zip(flags, rems):
            flag_items.append(
                f'<div class="flag-item">'
                f'<span class="flag-text">{html_lib.escape(flag)}</span>'
                f'<span class="rem-text">↳ {html_lib.escape(rem)}</span>'
                f'</div>'
            )
        for flag in flags[len(rems):]:
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

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Security Executive Summary</title>
<style>
  body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; margin:0; background:#f5f6fa; color:#333; }}
  .header {{ background: linear-gradient(135deg,#1a1a2e,#16213e); color:#fff; padding:40px; text-align:center; }}
  .score-gauge {{ font-size:5em; font-weight:900; color:{grade_colour}; line-height:1; }}
  .score-label {{ font-size:1.2em; color:#ccc; margin-top:8px; }}
  .grade-badge {{ display:inline-block; background:{grade_colour}; color:#fff; padding:6px 20px; border-radius:20px; font-size:1.4em; font-weight:700; margin:12px 0; }}
  .section {{ padding:24px 40px; }}
  .section h2 {{ font-size:1.2em; color:#333; margin-bottom:16px; border-bottom:2px solid #e0e0e0; padding-bottom:8px; }}
  .pillars {{ display:flex; flex-wrap:wrap; gap:16px; }}
  .pillar-card {{ background:#fff; border-radius:8px; padding:16px 20px; min-width:160px; box-shadow:0 2px 8px rgba(0,0,0,.06); }}
  .pillar-name {{ font-weight:600; font-size:0.95em; margin-bottom:4px; }}
  .pillar-risk {{ font-weight:700; font-size:1.1em; margin-bottom:6px; }}
  .pillar-counts {{ font-size:0.9em; letter-spacing:2px; margin-bottom:4px; }}
  .pillar-total {{ font-size:0.78em; color:#888; }}
  table {{ width:100%; border-collapse:collapse; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,.06); }}
  th {{ background:#1a1a2e; color:#fff; padding:10px 14px; text-align:left; font-size:0.85em; }}
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
  <div class="score-gauge">{overall_score}</div>
  <div class="score-label">/ 100 &nbsp; Security Score</div>
  <div class="grade-badge">Grade: {grade}</div>
  <p style="color:#aaa;margin:8px 0 0">Generated: {html_lib.escape(generated_at)} &nbsp;|&nbsp; {len(pillar_stats)} pillars analysed</p>
</div>

<div class="section">
  <h2>Security Posture by Pillar</h2>
  <div class="pillars">{pillar_cards_html}</div>
</div>

<div class="section">
  <h2>Top Critical &amp; High Findings</h2>
  <table>
    <thead><tr><th>Pillar</th><th>Risk</th><th>Resource</th><th>Flags &amp; Remediations</th></tr></thead>
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

<div class="footer">Executive Security Summary &nbsp;|&nbsp; For internal use only</div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html_content)
    os.chmod(path, 0o600)
    log.info(f"Executive summary written: {path}")


def run(input_dir=".", output_path="exec_summary.html", top_n=10, max_wins=10):
    """Discover reports, compute stats, write HTML summary."""
    report_paths = discover_reports(input_dir)
    if not report_paths:
        log.warning(f"No known report files found in {input_dir}")

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

    score, grade = compute_overall_score(pillar_stats_list)
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
    )

    log.info(f"Score: {score}/100 (Grade {grade})")
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
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    run(input_dir=args.input_dir, output_path=args.output,
        top_n=args.top_n, max_wins=args.max_wins)


if __name__ == "__main__":
    main()
