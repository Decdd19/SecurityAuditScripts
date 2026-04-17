#!/usr/bin/env python3
"""
Add Auditor Scaffold
====================
Generates a new auditor stub and wires it into audit.py and exec_summary.py.

Usage:
    python3 tools/add_auditor.py --name linux_disk
    python3 tools/add_auditor.py --name linux_disk --category linux --output-prefix disk_report

Supported categories: linux, aws, azure, windows, network, email
"""

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CATEGORY_PATH = {
    "linux":   "OnPrem/Linux",
    "windows": "OnPrem/Windows",
    "aws":     "AWS",
    "azure":   "Azure",
    "network": "Network",
    "email":   "Email",
}

LINUX_STUB_TEMPLATE = '''\
#!/usr/bin/env python3
"""
Linux {title} Auditor
{{"=" * (len("Linux {title} Auditor") + 1)}}
TODO: describe what this auditor checks.

Usage:
    sudo python3 {script_name}.py
    python3 {script_name}.py --format html --output {output_prefix}
    python3 {script_name}.py --format all
"""

import os
import sys
import json
import csv
import argparse
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# Shared CSS generator (repo root — 4 levels up from this auditor directory)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))
from report_utils import get_styles

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

NOW = datetime.now(timezone.utc)


def run_command(cmd):
    """Run command, return (stdout, returncode). Returns ('', 1) on error."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.stdout, r.returncode
    except Exception:
        return '', 1


def run_checks():
    """Execute all checks and return a list of finding dicts."""
    findings = []
    # TODO: implement checks
    # Example:
    # findings.append({{
    #     "check": "Example check",
    #     "compliant": True,
    #     "risk_level": "LOW",
    #     "remediation": "",
    #     "flag": "",
    # }})
    return findings


def write_json(report, path):
    import os
    with open(path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    os.chmod(path, 0o600)
    log.info(f"JSON report: {{path}}")


def write_html(report, path):
    import os
    findings = report.get("findings", [])
    generated = report["generated_at"]
    hostname = report.get("hostname", "unknown")

    rows = ""
    for f in findings:
        rl = f.get("risk_level", "LOW")
        badge = f\'<span style="color:var(--c-{{rl.lower()}});font-weight:bold">{{rl}}</span>\'
        rows += (
            f\'<tr><td>{{f.get("check","")}}</td>\'\
            f\'<td>{{badge}}</td>\'\
            f\'<td><code>{{f.get("flag","")}}</code></td>\'\
            f\'<td>{{f.get("remediation","")}}</td></tr>\\n\'
        )

    extra_css = """
  .badge {{ border-radius: 4px; padding: 2px 8px; font-size: 0.8em; }}
"""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title} Security Audit Report</title>
<style>
{{get_styles(extra_css)}}
</style>
</head>
<body>
<div class="header">
  <h1>{title} Security Audit Report</h1>
  <p>Generated: {{generated}} &nbsp;|&nbsp; Host: {{hostname}}</p>
</div>
<div class="table-wrap">
<table>
  <tr><th>Check</th><th>Status</th><th>Detail</th><th>Remediation</th></tr>
  {{rows}}
</table>
</div>
<div class="footer">Linux {title} Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, 'w') as f:
        f.write(html)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {{path}}")


def run(output_prefix='{output_prefix}', fmt='all'):
    import socket
    hostname = socket.gethostname()

    findings = run_checks()

    risk_levels = [f.get("risk_level", "LOW") for f in findings]
    overall = "CRITICAL" if "CRITICAL" in risk_levels else (
        "HIGH" if "HIGH" in risk_levels else (
        "MEDIUM" if "MEDIUM" in risk_levels else "LOW"
    ))

    report = {{
        "generated_at": NOW.isoformat(),
        "hostname": hostname,
        "pillar": "{short_name}",
        "risk_level": overall,
        "findings": findings,
        "summary": {{
            "total": len(findings),
            "overall_risk": overall,
        }},
    }}

    if fmt in ('json', 'all'):
        write_json(report, f"{{output_prefix}}.json")
    if fmt in ('html', 'all'):
        write_html(report, f"{{output_prefix}}.html")
    if fmt == 'stdout':
        print(json.dumps(report, indent=2, default=str))

    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Linux {title} Auditor')
    parser.add_argument('--output', '-o', default='{output_prefix}')
    parser.add_argument('--format', '-f', choices=['json', 'html', 'all', 'stdout'],
                        default='all')
    args = parser.parse_args()
    run(output_prefix=args.output, fmt=args.format)
'''

GENERIC_STUB_TEMPLATE = '''\
#!/usr/bin/env python3
"""
{title} Auditor
{{"=" * (len("{title} Auditor") + 1)}}
TODO: describe what this auditor checks.

Usage:
    python3 {script_name}.py
    python3 {script_name}.py --format all --output {output_prefix}
"""

import os
import sys
import json
import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

NOW = datetime.now(timezone.utc)


def run_checks():
    """Execute all checks and return a list of finding dicts."""
    findings = []
    # TODO: implement checks
    return findings


def write_json(report, path):
    with open(path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    os.chmod(path, 0o600)
    log.info(f"JSON report: {{path}}")


def run(output_prefix='{output_prefix}', fmt='all'):
    findings = run_checks()

    risk_levels = [f.get("risk_level", "LOW") for f in findings]
    overall = "CRITICAL" if "CRITICAL" in risk_levels else (
        "HIGH" if "HIGH" in risk_levels else (
        "MEDIUM" if "MEDIUM" in risk_levels else "LOW"
    ))

    report = {{
        "generated_at": NOW.isoformat(),
        "pillar": "{short_name}",
        "risk_level": overall,
        "findings": findings,
        "summary": {{"total": len(findings), "overall_risk": overall}},
    }}

    if fmt in ('json', 'all'):
        write_json(report, f"{{output_prefix}}.json")
    if fmt == 'stdout':
        print(json.dumps(report, indent=2, default=str))

    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='{title} Auditor')
    parser.add_argument('--output', '-o', default='{output_prefix}')
    parser.add_argument('--format', '-f', choices=['json', 'all', 'stdout'], default='all')
    args = parser.parse_args()
    run(output_prefix=args.output, fmt=args.format)
'''


def derive_parts(name: str, category: str, output_prefix: str | None):
    """Return (short_name, title, script_name, dir_path, output_prefix)."""
    # short_name: strip category prefix for path/title (linux_disk → disk)
    if name.startswith(f"{category}_"):
        short_name = name[len(category) + 1:]
    else:
        short_name = name

    title = short_name.replace("_", " ").title()
    script_name = f"{category}_{short_name}_auditor" if category in ("linux", "windows") else f"{short_name}_auditor"
    dir_name = f"{category}-{short_name.replace('_', '-')}-auditor"

    base = CATEGORY_PATH.get(category, category)
    dir_path = REPO_ROOT / base / dir_name

    prefix = output_prefix or f"{short_name}_report"
    return short_name, title, script_name, dir_path, prefix


def create_stub(short_name, title, script_name, dir_path, output_prefix, category):
    """Write the auditor stub and tests/__init__.py."""
    dir_path.mkdir(parents=True, exist_ok=True)
    tests_dir = dir_path / "tests"
    tests_dir.mkdir(exist_ok=True)
    (tests_dir / "__init__.py").write_text("")

    script_path = dir_path / f"{script_name}.py"
    if script_path.exists():
        print(f"  [SKIP] {script_path} already exists — not overwriting")
        return script_path

    template = LINUX_STUB_TEMPLATE if category in ("linux", "windows") else GENERIC_STUB_TEMPLATE
    # Render title/short_name/etc. into the template
    content = template.format(
        title=title,
        short_name=short_name,
        script_name=script_name,
        output_prefix=output_prefix,
    )
    script_path.write_text(content)
    script_path.chmod(0o755)
    print(f"  [CREATE] {script_path.relative_to(REPO_ROOT)}")
    return script_path


def add_to_audit_py(auditor_key, script_path, output_prefix):
    """Insert an entry into AUDITOR_MAP in audit.py."""
    audit_py = REPO_ROOT / "audit.py"
    content = audit_py.read_text()

    # Check if key already exists
    if f'"{auditor_key}"' in content or f"'{auditor_key}'" in content:
        print(f"  [SKIP] audit.py already has key '{auditor_key}'")
        return

    rel_path = script_path.relative_to(REPO_ROOT)
    new_entry = (
        f'    "{auditor_key}":   '
        f'AuditorDef(REPO_ROOT / "{rel_path.as_posix()}", '
        f'"{output_prefix}", False),\n'
    )

    marker = '    # @@AUDITOR_MAP_END@@'
    idx = content.find(marker)
    if idx == -1:
        print(f"  [WARN] @@AUDITOR_MAP_END@@ marker not found in audit.py — add manually:")
        print(f"         {new_entry.strip()}")
        return

    new_content = content[:idx] + new_entry + content[idx:]
    audit_py.write_text(new_content)
    print(f"  [UPDATE] audit.py — added key '{auditor_key}'")


def add_to_exec_summary(output_prefix):
    """Add the JSON filename to KNOWN_PATTERNS in exec_summary.py."""
    exec_py = REPO_ROOT / "tools" / "exec_summary.py"
    content = exec_py.read_text()

    pattern_entry = f'    "{output_prefix}.json"'
    if pattern_entry in content:
        print(f"  [SKIP] exec_summary.py already has '{output_prefix}.json'")
        return

    marker = '    # @@KNOWN_PATTERNS_END@@'
    idx = content.find(marker)
    if idx == -1:
        print(f"  [WARN] @@KNOWN_PATTERNS_END@@ marker not found in exec_summary.py — add manually:")
        print(f"         {pattern_entry},")
        return

    new_content = content[:idx] + f'{pattern_entry},\n' + content[idx:]
    exec_py.write_text(new_content)
    print(f"  [UPDATE] exec_summary.py — added '{output_prefix}.json'")


# Pytest paths that need to be added per category (azure/windows use Pester, not pytest)
_PYTEST_PATHS = {
    "network": "Network/",
    "email":   "Email/",
}


def add_to_ci_yml(category):
    """Add the category test path to the pytest command in ci.yml if absent."""
    pytest_path = _PYTEST_PATHS.get(category)
    if not pytest_path:
        return  # linux/aws already in CI; azure/windows use Pester

    ci_yml = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    if not ci_yml.exists():
        print(f"  [SKIP] .github/workflows/ci.yml not found — add {pytest_path} manually")
        return

    content = ci_yml.read_text()
    # Find the pytest run line
    match = re.search(r'(        run: pytest )([^\n]+)', content)
    if not match:
        print(f"  [SKIP] Could not find pytest run line in ci.yml — add {pytest_path} manually")
        return

    current_line = match.group(2)
    if pytest_path in current_line:
        print(f"  [SKIP] ci.yml already includes {pytest_path}")
        return

    # Insert before the first occurrence of tests/ to keep paths grouped
    if "tests/" in current_line:
        new_line = current_line.replace("tests/", f"{pytest_path} tests/")
    else:
        new_line = current_line + f" {pytest_path}"

    new_content = content[:match.start(2)] + new_line + content[match.end(2):]
    ci_yml.write_text(new_content)
    print(f"  [UPDATE] .github/workflows/ci.yml — added {pytest_path} to pytest path")


def main():
    parser = argparse.ArgumentParser(
        description="Scaffold a new SecurityAuditScripts auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 tools/add_auditor.py --name linux_disk
  python3 tools/add_auditor.py --name aws_config --category aws
  python3 tools/add_auditor.py --name ssl --category network --output-prefix ssl_report
        """,
    )
    parser.add_argument("--name", required=True,
                        help="Auditor key name, e.g. linux_disk or aws_config")
    parser.add_argument("--category",
                        choices=list(CATEGORY_PATH.keys()),
                        help="Category (inferred from --name prefix if omitted)")
    parser.add_argument("--output-prefix",
                        help="JSON/HTML output filename prefix (default: {short_name}_report)")
    args = parser.parse_args()

    # Infer category from name prefix if not specified
    category = args.category
    if not category:
        for cat in CATEGORY_PATH:
            if args.name.startswith(f"{cat}_"):
                category = cat
                break
        if not category:
            print(f"ERROR: Could not infer category from '{args.name}'. Use --category.")
            sys.exit(1)

    short_name, title, script_name, dir_path, output_prefix = derive_parts(
        args.name, category, args.output_prefix
    )
    auditor_key = args.name if args.name.startswith(f"{category}_") else f"{category}_{short_name}"

    print(f"\nScaffolding auditor: {auditor_key}")
    print(f"  Title:         {title}")
    print(f"  Script:        {dir_path.relative_to(REPO_ROOT)}/{script_name}.py")
    print(f"  Output prefix: {output_prefix}")
    print()

    script_path = create_stub(short_name, title, script_name, dir_path, output_prefix, category)
    add_to_audit_py(auditor_key, script_path, output_prefix)
    add_to_exec_summary(output_prefix)
    add_to_ci_yml(category)

    print(f"\nDone. Next steps:")
    print(f"  1. Implement run_checks() in {script_path.name}")
    print(f"  2. Add tests to {dir_path.relative_to(REPO_ROOT)}/tests/")
    print(f"  3. Run: python3 {script_path} --format stdout")


if __name__ == "__main__":
    main()
