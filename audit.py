#!/usr/bin/env python3
"""
Security Audit Orchestrator
============================
Runs any combination of AWS, Linux, Azure, and Windows auditors in parallel,
displays a Rich progress UI, and produces an executive summary report.

Usage:
    python3 audit.py --client "Acme Corp" --aws --linux --output ./reports/
    python3 audit.py --client "Acme Corp" --all --profile prod --regions eu-west-1
    python3 audit.py --client "Acme Corp" --s3 --ec2 --linux_user
    python3 audit.py --windows   # prints PS1 instructions only
"""

import argparse
import logging
import os
import subprocess
import sys
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional

from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

log = logging.getLogger(__name__)
console = Console()

# ── Repo root (directory where this script lives) ────────────────────────────
REPO_ROOT = Path(__file__).parent.resolve()


# ── Auditor definitions ───────────────────────────────────────────────────────

@dataclass
class AuditorDef:
    """Metadata for a single Python auditor script."""
    script: Path          # Absolute path to the .py file
    output_prefix: str    # Default output filename prefix passed as --output
    supports_regions: bool = False  # Whether the script accepts --regions


AUDITOR_MAP: Dict[str, AuditorDef] = {
    # ── AWS ──────────────────────────────────────────────────────────────────
    "s3":          AuditorDef(REPO_ROOT / "AWS/s3-auditor/s3_auditor.py",          "s3_report",          False),
    "ec2":         AuditorDef(REPO_ROOT / "AWS/ec2-auditor/ec2_auditor.py",         "ec2_report",         True),
    "sg":          AuditorDef(REPO_ROOT / "AWS/sg-auditor/sg_auditor.py",           "sg_report",          False),  # uses --region (singular)
    "cloudtrail":  AuditorDef(REPO_ROOT / "AWS/cloudtrail-auditor/cloudtrail_auditor.py", "cloudtrail_report", False),
    "rds":         AuditorDef(REPO_ROOT / "AWS/rds-auditor/rds_auditor.py",         "rds_report",         True),
    "iam":         AuditorDef(REPO_ROOT / "AWS/iam-privilege-mapper/iam_mapper_v2.py", "iam_report",       False),
    "root":        AuditorDef(REPO_ROOT / "AWS/root-auditor/root_auditor.py",       "root_report",        False),
    "guardduty":   AuditorDef(REPO_ROOT / "AWS/guardduty-auditor/guardduty_auditor.py", "guardduty_report", True),
    "vpcflowlogs": AuditorDef(REPO_ROOT / "AWS/vpcflowlogs-auditor/vpcflowlogs_auditor.py", "vpcflowlogs_report", True),
    "lambda":      AuditorDef(REPO_ROOT / "AWS/lambda-auditor/lambda_auditor.py",   "lambda_report",      True),
    "securityhub": AuditorDef(REPO_ROOT / "AWS/securityhub-auditor/securityhub_auditor.py", "securityhub_report", True),
    "kms":         AuditorDef(REPO_ROOT / "AWS/kms-auditor/kms_auditor.py",         "kms_report",         True),
    "elb":         AuditorDef(REPO_ROOT / "AWS/elb-auditor/elb_auditor.py",         "elb_report",         True),
    # ── Linux ─────────────────────────────────────────────────────────────────
    "linux_user":     AuditorDef(REPO_ROOT / "OnPrem/Linux/linux-user-auditor/linux_user_auditor.py",         "user_report",   False),
    "linux_firewall": AuditorDef(REPO_ROOT / "OnPrem/Linux/linux-firewall-auditor/linux_firewall_auditor.py", "fw_report",     False),
    "linux_sysctl":   AuditorDef(REPO_ROOT / "OnPrem/Linux/linux-sysctl-auditor/linux_sysctl_auditor.py",     "sysctl_report", False),
    "linux_patch":    AuditorDef(REPO_ROOT / "OnPrem/Linux/linux-patch-auditor/linux_patch_auditor.py",       "patch_report",  False),
}

AWS_GROUP: List[str] = [
    "s3", "ec2", "sg", "cloudtrail", "rds", "iam",
    "root", "guardduty", "vpcflowlogs", "lambda",
    "securityhub", "kms", "elb",
]

LINUX_GROUP: List[str] = [
    "linux_user", "linux_firewall", "linux_sysctl", "linux_patch",
]

# Azure / Windows PS1 scripts — cannot run on Linux; print instructions only
WINDOWS_PS1: Dict[str, str] = {
    "keyvault":     "Azure/keyvault-auditor/keyvault_auditor.ps1",
    "storage":      "Azure/storage-auditor/storage_auditor.ps1",
    "nsg":          "Azure/nsg-auditor/nsg_auditor.ps1",
    "activitylog":  "Azure/activitylog-auditor/activitylog_auditor.ps1",
    "subscription": "Azure/subscription-auditor/subscription_auditor.ps1",
    "entra":        "Azure/entra-auditor/entra_auditor.ps1",
    "defender":     "Azure/defender-auditor/defender_auditor.ps1",
}


# ── Argument parsing ──────────────────────────────────────────────────────────

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="audit.py",
        description="Security Audit Orchestrator — run all auditors in one command.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━ EXAMPLES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  # Full AWS + Linux audit for a client
  python3 audit.py --client "Acme Corp" --aws --linux --output ./reports/

  # Everything — AWS, Linux, plus PS1 instructions for Azure/Windows
  python3 audit.py --client "Acme Corp" --all --profile prod

  # Multi-region AWS scan
  python3 audit.py --client "Acme Corp" --aws --profile prod --regions eu-west-1 us-east-1

  # Cherry-pick specific auditors
  python3 audit.py --client "Acme Corp" --s3 --ec2 --iam --linux_user

  # Print Azure/Windows PS1 instructions only (no Python auditors run)
  python3 audit.py --client "Acme Corp" --windows

  # JSON output only, 8 parallel workers, open summary in browser when done
  python3 audit.py --client "Acme Corp" --aws --format json --workers 8 --open

━━━ AWS AUDITORS (--aws runs all 13) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  --s3           Bucket public access, encryption, versioning, logging
  --ec2          Instance exposure, IMDSv2, security groups, EBS encryption  *
  --sg           Security group rules, 0.0.0.0/0 ingress, unrestricted ports
  --cloudtrail   Trail enabled, log validation, multi-region, S3 protection
  --rds          Publicly accessible instances, encryption, backups, auth     *
  --iam          Privilege mapping, admin roles, unused keys, policy review
  --root         Root account MFA, access keys, last-used activity
  --guardduty    Detector status, threat findings by severity                 *
  --vpcflowlogs  Flow log coverage per VPC                                    *
  --lambda       Function exposure, env var secrets, outdated runtimes        *
  --securityhub  Standards compliance (CIS, FSBP), finding summary           *
  --kms          Key rotation, cross-account access, disabled keys            *
  --elb          HTTPS enforcement, SSL policies, access logging              *

  * Supports --regions (multi-region scan). All others use the default region
    from your AWS CLI profile.

━━━ LINUX AUDITORS (--linux runs all 4) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  --linux_user      Local users, sudoers, password policy, SSH keys
  --linux_firewall  iptables/nftables/ufw rules, default policy
  --linux_sysctl    Kernel hardening parameters (net, fs, kernel namespaces)
  --linux_patch     Installed packages vs available updates, CVE exposure

  Run these directly on the target Linux host (not your workstation).

━━━ AZURE / WINDOWS (--azure or --windows) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  These are PowerShell scripts that must run on a Windows machine with the
  Az module installed. Passing --azure or --windows prints the commands to run
  manually, then copy the JSON output back into the report folder so the
  executive summary can include them.

  Scripts: keyvault, storage, nsg, activitylog, subscription, entra, defender

━━━ OUTPUT STRUCTURE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  {--output}/
  └── {client}-{YYYY-MM-DD}/
      ├── s3_report.json          ← per-auditor JSON report
      ├── s3_report.html          ← per-auditor HTML report
      ├── s3.log                  ← auditor stdout/stderr
      ├── ec2_report.json
      ├── ...
      └── exec_summary.html       ← aggregated executive summary (auto-generated)

  The executive summary is generated automatically after all auditors finish.
  It aggregates findings across all reports, scores the environment, and
  highlights top risks and quick wins.

━━━ PREREQUISITES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  AWS auditors:   AWS CLI configured (aws configure / --profile)
                  boto3 installed (pip install boto3)
                  IAM permissions: SecurityAudit or ReadOnlyAccess policy

  Linux auditors: Run on the target host as root or with sudo
                  Python 3.8+ on the target host

  This orchestrator: Python 3.10+, rich (pip install rich)
""",
    )

    # Group flags
    groups = parser.add_argument_group("auditor groups")
    groups.add_argument("--aws",     action="store_true", help="Run all AWS auditors")
    groups.add_argument("--linux",   action="store_true", help="Run all Linux auditors")
    groups.add_argument("--azure",   action="store_true", help="Print Azure PS1 instructions (Windows-only scripts)")
    groups.add_argument("--windows", action="store_true", help="Print Windows PS1 instructions")
    groups.add_argument("--all",     action="store_true", help="Run all Python auditors + print PS1 instructions")

    # Individual AWS auditor flags
    _aws_help = {
        "s3":          "S3 bucket public access, encryption, versioning, logging",
        "ec2":         "EC2 exposure, IMDSv2, EBS encryption [multi-region]",
        "sg":          "Security group rules, unrestricted ingress",
        "cloudtrail":  "CloudTrail enabled, log validation, S3 protection",
        "rds":         "RDS public access, encryption, backups [multi-region]",
        "iam":         "IAM privilege mapping, admin roles, unused keys",
        "root":        "Root account MFA, access keys, activity",
        "guardduty":   "GuardDuty detector status and threat findings [multi-region]",
        "vpcflowlogs": "VPC flow log coverage per VPC [multi-region]",
        "lambda":      "Lambda exposure, env var secrets, runtimes [multi-region]",
        "securityhub": "Security Hub standards compliance and findings [multi-region]",
        "kms":         "KMS key rotation, cross-account access [multi-region]",
        "elb":         "ELB/ALB/NLB HTTPS enforcement, SSL policies [multi-region]",
    }
    aws_ind = parser.add_argument_group("individual AWS auditors")
    for name in AWS_GROUP:
        aws_ind.add_argument(f"--{name}", action="store_true", help=_aws_help.get(name, f"Run {name} auditor"))

    _linux_help = {
        "linux_user":     "Local users, sudoers, password policy, SSH keys",
        "linux_firewall": "iptables/nftables/ufw rules and default policy",
        "linux_sysctl":   "Kernel hardening parameters",
        "linux_patch":    "Package updates and CVE exposure",
    }
    linux_ind = parser.add_argument_group("individual Linux auditors")
    for name in LINUX_GROUP:
        linux_ind.add_argument(f"--{name}", action="store_true", help=_linux_help.get(name, f"Run {name} auditor"))

    # Runtime options
    opts = parser.add_argument_group("options")
    opts.add_argument("--client",  default="audit",      metavar="NAME", help="Client name for output folder (default: audit)")
    opts.add_argument("--output",  default="./reports/", metavar="DIR",  help="Base output directory (default: ./reports/)")
    opts.add_argument("--profile", default=None,         metavar="NAME", help="AWS CLI profile name")
    opts.add_argument("--regions", nargs="+",            metavar="REGION", help="AWS regions (passed to multi-region auditors)")
    opts.add_argument("--format",  default="all",        choices=["json", "html", "all"], help="Report format (default: all)")
    opts.add_argument("--workers", type=int, default=4,  metavar="N",    help="Parallel worker threads (default: 4)")
    opts.add_argument("--open",    action="store_true",  help="Open exec_summary.html in browser when done")
    opts.add_argument("--timeout", type=int, default=600, metavar="SEC", help="Per-auditor timeout in seconds (default: 600)")
    opts.add_argument("-v", "--verbose", action="store_true", help="Show auditor stdout/stderr in terminal")

    return parser.parse_args(argv)


# ── Selection logic ───────────────────────────────────────────────────────────

def select_auditors(args: argparse.Namespace):
    """Return (selected_python_auditors, show_windows_ps1) based on flags."""
    selected: List[str] = []
    show_ps1 = False

    if args.all:
        selected = list(AWS_GROUP) + list(LINUX_GROUP)
        show_ps1 = True
    else:
        if args.aws:
            selected.extend(AWS_GROUP)
        if args.linux:
            selected.extend(LINUX_GROUP)
        if args.azure or args.windows:
            show_ps1 = True

        for name in AUDITOR_MAP:
            if getattr(args, name, False) and name not in selected:
                selected.append(name)

    return selected, show_ps1


# ── Pre-flight checks ─────────────────────────────────────────────────────────

def preflight_check(selected: List[str], args: argparse.Namespace) -> bool:
    """Validate prerequisites before launching any auditors. Returns True if all pass."""
    errors: List[str] = []

    aws_selected = any(name in AWS_GROUP for name in selected)
    linux_selected = any(name in LINUX_GROUP for name in selected)

    if aws_selected:
        # Check boto3 is installed
        try:
            import importlib
            boto3 = importlib.import_module("boto3")
        except ImportError:
            errors.append("boto3 not installed — run: pip install boto3")
            boto3 = None

        if boto3 is not None:
            # Check credentials are valid
            try:
                session = boto3.Session(profile_name=args.profile)
                identity = session.client("sts").get_caller_identity()
                account = identity["Account"]
                caller = identity["Arn"].split("/")[-1]
                console.print(f"[green]✓ AWS credentials valid[/green] — account [bold]{account}[/bold] ({caller})")
            except Exception as exc:
                hint = f"--profile {args.profile}" if args.profile else "aws configure"
                errors.append(
                    f"AWS credentials not valid: {exc}\n"
                    f"  Fix: {hint}"
                )

    if linux_selected:
        if os.geteuid() != 0:
            errors.append(
                "Linux auditors require root privileges\n"
                "  Fix: re-run with sudo python3 audit.py ..."
            )
        else:
            console.print("[green]✓ Running as root[/green] — Linux auditors ready")

    if errors:
        console.print("\n[bold red]Pre-flight checks failed — fix these before running:[/bold red]\n")
        for err in errors:
            console.print(f"  [red]✗[/red] {err}\n")
        return False

    return True


# ── Command building ──────────────────────────────────────────────────────────

def build_cmd(name: str, defn: AuditorDef, client_dir: Path, args: argparse.Namespace) -> List[str]:
    """Build the subprocess command list for a single auditor."""
    output_path = str(client_dir / defn.output_prefix)
    cmd = [sys.executable, str(defn.script), "--output", output_path, "--format", args.format]

    if args.profile and name in AWS_GROUP:
        cmd += ["--profile", args.profile]

    if args.regions and defn.supports_regions:
        cmd += ["--regions"] + args.regions

    return cmd


# ── Auditor runner ────────────────────────────────────────────────────────────

@dataclass
class AuditorResult:
    name: str
    status: str        # "DONE" | "FAILED" | "TIMEOUT"
    duration: float    # seconds
    returncode: int
    log_file: Path


def run_auditor(
    name: str,
    defn: AuditorDef,
    client_dir: Path,
    args: argparse.Namespace,
    progress: Progress,
    task_id: TaskID,
) -> AuditorResult:
    """Run a single auditor subprocess, capture output, update progress."""
    log_file = client_dir / f"{name}.log"
    cmd = build_cmd(name, defn, client_dir, args)
    start = time.monotonic()

    progress.update(task_id, description=f"[yellow]RUNNING[/yellow] {name}")

    try:
        with open(log_file, "w") as lf:
            proc = subprocess.run(
                cmd,
                stdout=lf,
                stderr=subprocess.STDOUT,
                timeout=args.timeout,
            )
        duration = time.monotonic() - start
        if proc.returncode == 0:
            status = "DONE"
            progress.update(task_id, description=f"[green]DONE ✓[/green]  {name}", advance=1)
        else:
            status = "FAILED"
            progress.update(task_id, description=f"[red]FAILED ✗[/red] {name}", advance=1)
        return AuditorResult(name=name, status=status, duration=duration,
                             returncode=proc.returncode, log_file=log_file)

    except subprocess.TimeoutExpired:
        duration = time.monotonic() - start
        progress.update(task_id, description=f"[red]TIMEOUT ✗[/red] {name}", advance=1)
        return AuditorResult(name=name, status="TIMEOUT", duration=duration,
                             returncode=-1, log_file=log_file)

    except Exception as exc:
        duration = time.monotonic() - start
        with log_file.open("a") as lf:
            lf.write(f"Orchestrator error: {exc}\n")
        progress.update(task_id, description=f"[red]FAILED ✗[/red] {name}", advance=1)
        return AuditorResult(name=name, status="FAILED", duration=duration,
                             returncode=-1, log_file=log_file)


# ── Parallel runner ───────────────────────────────────────────────────────────

def run_parallel(
    selected: List[str],
    client_dir: Path,
    args: argparse.Namespace,
) -> List[AuditorResult]:
    """Run selected auditors in parallel with a Rich progress display."""
    results: List[AuditorResult] = []

    overall_progress = Progress(
        TextColumn("[bold blue]Overall"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
    )
    auditor_progress = Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        TimeElapsedColumn(),
    )

    overall_task = overall_progress.add_task("", total=len(selected))

    auditor_tasks: Dict[str, TaskID] = {}
    for name in selected:
        tid = auditor_progress.add_task(f"[dim]QUEUED  [/dim] {name}", total=1)
        auditor_tasks[name] = tid

    group_display = Table.grid()
    group_display.add_row(overall_progress)
    group_display.add_row(auditor_progress)

    with Live(Panel(group_display, title="[bold]Security Audit Progress[/bold]", box=box.ROUNDED),
              refresh_per_second=4, console=console):
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    run_auditor,
                    name,
                    AUDITOR_MAP[name],
                    client_dir,
                    args,
                    auditor_progress,
                    auditor_tasks[name],
                ): name
                for name in selected
            }
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                overall_progress.advance(overall_task)

    return results


# ── Executive summary ─────────────────────────────────────────────────────────

def run_exec_summary(client_dir: Path) -> Optional[Path]:
    """Run exec_summary.py over the client output directory."""
    exec_script = REPO_ROOT / "tools" / "exec_summary.py"
    if not exec_script.exists():
        log.warning("exec_summary.py not found at %s — skipping summary", exec_script)
        return None

    html_path = client_dir / "exec_summary.html"
    cmd = [
        sys.executable, str(exec_script),
        "--input-dir", str(client_dir),
        "--output", str(html_path),
    ]
    console.print("\n[bold]Running executive summary…[/bold]")
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=120)
        return html_path
    except subprocess.CalledProcessError as e:
        log.error("exec_summary failed: %s", e.stderr)
        return None
    except Exception as exc:
        log.error("exec_summary error: %s", exc)
        return None


# ── Summary table ─────────────────────────────────────────────────────────────

def print_summary(results: List[AuditorResult], html_path: Optional[Path]) -> None:
    """Print final Rich summary table."""
    table = Table(title="Audit Results", show_header=True, header_style="bold cyan")
    table.add_column("Auditor",   style="bold")
    table.add_column("Status",    justify="center")
    table.add_column("Duration",  justify="right")
    table.add_column("Log")

    for r in sorted(results, key=lambda x: x.name):
        if r.status == "DONE":
            status_str = "[green]DONE ✓[/green]"
        elif r.status == "TIMEOUT":
            status_str = "[yellow]TIMEOUT[/yellow]"
        else:
            status_str = "[red]FAILED ✗[/red]"
        table.add_row(
            r.name,
            status_str,
            f"{r.duration:.1f}s",
            str(r.log_file.name),
        )

    console.print()
    console.print(table)

    if html_path and html_path.exists():
        console.print(f"\n[bold green]Executive summary:[/bold green] {html_path}")
    elif html_path:
        console.print(f"\n[yellow]Executive summary not generated (check logs)[/yellow]")


# ── Startup banner ───────────────────────────────────────────────────────────

def print_banner() -> None:
    """Print ASCII art startup banner with capability summary."""
    art = Text(justify="left")
    art.append("  ███████╗███████╗ ██████╗ \n", style="bold red")
    art.append("  ██╔════╝██╔════╝██╔════╝\n", style="bold red")
    art.append("  ███████╗█████╗  ██║     \n", style="bold red")
    art.append("  ╚════██║██╔══╝  ██║     \n", style="bold red")
    art.append("  ███████║███████╗╚██████╗\n", style="bold red")
    art.append("  ╚══════╝╚══════╝ ╚═════╝", style="bold red")

    info = Text(justify="left")
    info.append("SECURITY AUDIT ORCHESTRATOR\n", style="bold white")
    info.append("─" * 31 + "\n", style="dim")
    info.append("  AWS    ", style="bold yellow")
    info.append("13 auditors   S3 · EC2 · IAM · KMS…\n")
    info.append("  Linux  ", style="bold green")
    info.append(" 4 auditors   users · fw · sysctl · patch\n")
    info.append("  Azure  ", style="bold cyan")
    info.append(" 7 PS1 scripts keyvault · nsg · defender…\n")
    info.append("─" * 31 + "\n", style="dim")
    info.append("  Parallel execution  ·  Rich progress UI\n", style="dim")
    info.append("  JSON + HTML reports ·  Executive summary", style="dim")

    grid = Table.grid(padding=(0, 3))
    grid.add_column(no_wrap=True)
    grid.add_column(no_wrap=True)
    grid.add_row(art, info)

    console.print(
        Panel(grid, box=box.DOUBLE_EDGE, border_style="bold red", padding=(1, 2))
    )
    console.print()


# ── Windows / Azure PS1 instructions ─────────────────────────────────────────

def print_windows_instructions(client_dir: Path) -> None:
    """Print formatted instructions for running PS1 auditors on Windows."""
    console.print("\n[bold cyan]━━━ Windows / Azure PS1 Auditors ━━━[/bold cyan]")
    console.print(
        "[yellow]These scripts must be run manually on a Windows machine with "
        "PowerShell and the Az module installed.[/yellow]\n"
    )
    for script_name, rel_path in WINDOWS_PS1.items():
        win_path = rel_path.replace("/", "\\")
        console.print(f"  [bold]{script_name}[/bold]")
        console.print(f"    .\\{win_path}\n")

    console.print("[bold]After running, copy the JSON output files back to:[/bold]")
    console.print(f"  {client_dir}\n")
    console.print(
        "Then re-run the exec summary:\n"
        f"  python3 tools/exec_summary.py --input-dir {client_dir} "
        f"--output {client_dir / 'exec_summary.html'}\n"
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    args = parse_args(argv)
    print_banner()
    selected, show_ps1 = select_auditors(args)

    if not selected and not show_ps1:
        console.print(
            "[red]No auditors selected.[/red] "
            "Use --aws, --linux, --all, --windows, or individual flags.\n"
            "Run [bold]python3 audit.py --help[/bold] for usage."
        )
        return 1

    if selected and not preflight_check(selected, args):
        return 1

    today = date.today().strftime("%Y-%m-%d")
    client_slug = args.client.replace(" ", "-")
    client_dir = Path(args.output) / f"{client_slug}-{today}"
    client_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"\n[bold]Client:[/bold] {args.client}")
    console.print(f"[bold]Output:[/bold] {client_dir}\n")

    if show_ps1:
        print_windows_instructions(client_dir)

    results: List[AuditorResult] = []
    if selected:
        results = run_parallel(selected, client_dir, args)

    html_path: Optional[Path] = None
    if results:
        html_path = run_exec_summary(client_dir)
        print_summary(results, html_path)

    if args.open and html_path and html_path.exists():
        webbrowser.open(html_path.as_uri())

    any_failed = any(r.status in ("FAILED", "TIMEOUT") for r in results)
    return 1 if any_failed else 0


if __name__ == "__main__":
    sys.exit(main())
