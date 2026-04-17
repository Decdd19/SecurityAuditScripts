"""
Shared utilities for SecurityAuditScripts HTML reports and auditor helpers.

Each auditor's write_html() calls get_styles() and embeds the result inline.
HTML output remains a fully standalone single-file document — no external deps.

To update brand tokens: change BRAND here. Everywhere picks it up on next run.
"""

from botocore.exceptions import ClientError


def client_error_unknown_flag(check_name: str, err: ClientError) -> str:
    """Return a standardised UNKNOWN flag string for an inaccessible API check.

    Use when a ClientError (e.g. AccessDenied) prevents a security check from
    completing.  The caller should emit this as a warning flag rather than
    silently returning False (which implies the check passed).
    """
    code = err.response.get("Error", {}).get("Code", "Unknown")
    return f"⚠️ UNKNOWN — could not verify {check_name} ({code})"


BRAND = {
    "dark":         "#1a1a2e",  # header, th backgrounds
    "body_text":    "#333",
    "body_bg":      "#f5f6fa",
    "badge_radius": "8px",
    "critical":     "#dc3545",
    "high":         "#fd7e14",
    "medium":       "#ffc107",
    "low":          "#28a745",
    "info":         "#3498db",
}


def get_styles(extra: str = "") -> str:
    """Return shared base CSS for SecurityAuditScripts reports.

    Pass auditor-specific CSS as `extra`; it is appended after the base styles.
    The combined string is embedded directly in <style>…</style> tags so the
    output HTML remains a fully standalone, portable document.
    """
    b = BRAND
    return (
        f"  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;"
        f" margin: 0; background: {b['body_bg']}; color: {b['body_text']}; }}\n"
        f"  .header {{ background: {b['dark']}; color: white; padding: 30px 40px; }}\n"
        f"  .header h1 {{ margin: 0; font-size: 1.8em; }}\n"
        f"  .header p {{ margin: 5px 0 0; opacity: 0.8; }}\n"
        f"  .summary {{ display: flex; gap: 20px; padding: 20px 40px; flex-wrap: wrap; }}\n"
        f"  .card {{ background: white; border-radius: {b['badge_radius']}; padding: 20px 30px;"
        f" flex: 1; min-width: 140px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }}\n"
        f"  .card .num {{ font-size: 2.5em; font-weight: bold; }}\n"
        f"  .card .label {{ color: #666; font-size: 0.9em; margin-top: 4px; }}\n"
        f"  .critical .num {{ color: {b['critical']}; }} .high .num {{ color: {b['high']}; }}\n"
        f"  .medium .num {{ color: {b['medium']}; }} .low .num {{ color: {b['low']}; }}\n"
        f"  .total .num {{ color: {b['info']}; }}\n"
        f"  .noncompliant .num {{ color: {b['high']}; }}\n"
        f"  .compliant .num {{ color: {b['low']}; }}\n"
        f"  .table-wrap {{ padding: 0 40px 40px; overflow-x: auto; }}\n"
        f"  table {{ width: 100%; border-collapse: collapse; background: white;"
        f" border-radius: {b['badge_radius']}; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}\n"
        f"  th {{ background: {b['dark']}; color: white; padding: 12px 15px; text-align: left;"
        f" font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }}\n"
        f"  td {{ padding: 10px 15px; border-bottom: 1px solid #ecf0f1; vertical-align: top; }}\n"
        f"  tr:last-child td {{ border-bottom: none; }}\n"
        f"  tr:hover td {{ background: #f8f9ff; }}\n"
        f"  code {{ background: #ecf0f1; padding: 2px 5px; border-radius: 3px; font-size: 0.85em; }}\n"
        f"  .footer {{ text-align: center; padding: 20px; color: #999; font-size: 0.85em; }}\n"
        f"  @media print {{\n"
        f"    body {{ font-size: 10pt; }}\n"
        f"    .header {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}\n"
        f"    .card {{ box-shadow: none; border: 1px solid #ddd; }}\n"
        f"    table {{ box-shadow: none; }}\n"
        f"    .footer {{ display: none; }}\n"
        f"  }}\n"
        + extra
    )
