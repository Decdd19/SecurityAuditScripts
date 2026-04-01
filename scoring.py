"""
Scoring engine for SecurityAuditScripts executive summary reports.

Extracted from tools/exec_summary.py so that grade logic is unit-testable
in isolation without importing the full exec_summary module.

Usage:
    from scoring import compute_overall_score
    score, grade, note = compute_overall_score(pillar_stats_list)
"""


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
        if pr == "UNKNOWN":
            deductions += 3   # Treat as HIGH — incomplete audit is itself a risk signal
        elif stats.get("critical", 0) > 0 or pr == "CRITICAL":
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

    # c) D-floor: fw pillar CRITICAL (no firewall or default-allow policy) → grade ≤ D
    fw_critical = any(
        s.get("pillar") == "fw" and (s.get("critical", 0) > 0 or s.get("pillar_risk") == "CRITICAL")
        for s in pillar_stats_list
    )
    if fw_critical and grade in ("A", "B", "C"):
        grade = "D"
        grade_note = "floored: firewall absent or default-allow policy"

    # d) B-cap: any UNKNOWN pillar → grade ≤ B (incomplete audit cannot earn A)
    unknown_pillars = [s for s in pillar_stats_list if s.get("pillar_risk") == "UNKNOWN"]
    if unknown_pillars and grade == "A":
        grade = "B"
        grade_note = f"capped: {len(unknown_pillars)} pillar(s) unverifiable (re-run with elevated access)"

    return round(score, 1), grade, grade_note
