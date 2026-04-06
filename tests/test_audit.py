"""Tests for audit.py — the SecurityAuditScripts master orchestrator."""

import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add repo root to sys.path so we can import audit.py
REPO_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(REPO_ROOT))

import audit  # noqa: E402  (after sys.path manipulation)


class TestParseArgs(unittest.TestCase):
    """Argument parsing tests."""

    def _args(self, *argv):
        return audit.parse_args(list(argv))

    def test_aws_flag_present(self):
        args = self._args("--aws", "--client", "TestCo")
        self.assertTrue(args.aws)

    def test_linux_flag_present(self):
        args = self._args("--linux")
        self.assertTrue(args.linux)

    def test_all_flag_present(self):
        args = self._args("--all")
        self.assertTrue(args.all)

    def test_windows_flag_present(self):
        args = self._args("--windows")
        self.assertTrue(args.windows)

    def test_azure_flag_present(self):
        args = self._args("--azure")
        self.assertTrue(args.azure)

    def test_client_name_set(self):
        args = self._args("--aws", "--client", "Acme Corp")
        self.assertEqual(args.client, "Acme Corp")

    def test_client_default(self):
        args = self._args("--aws")
        self.assertEqual(args.client, "audit")

    def test_output_set(self):
        args = self._args("--aws", "--output", "/tmp/reports")
        self.assertEqual(args.output, "/tmp/reports")

    def test_profile_set(self):
        args = self._args("--aws", "--profile", "prod")
        self.assertEqual(args.profile, "prod")

    def test_regions_set(self):
        args = self._args("--aws", "--regions", "eu-west-1", "us-east-1")
        self.assertEqual(args.regions, ["eu-west-1", "us-east-1"])

    def test_format_default(self):
        args = self._args("--aws")
        self.assertEqual(args.format, "all")

    def test_format_html(self):
        args = self._args("--aws", "--format", "html")
        self.assertEqual(args.format, "html")

    def test_workers_default(self):
        args = self._args("--aws")
        self.assertEqual(args.workers, 4)

    def test_workers_custom(self):
        args = self._args("--aws", "--workers", "8")
        self.assertEqual(args.workers, 8)

    def test_individual_s3_flag(self):
        args = self._args("--s3")
        self.assertTrue(args.s3)

    def test_individual_ec2_flag(self):
        args = self._args("--ec2")
        self.assertTrue(args.ec2)

    def test_individual_linux_user_flag(self):
        args = self._args("--linux_user")
        self.assertTrue(args.linux_user)

    def test_open_flag(self):
        args = self._args("--aws", "--open")
        self.assertTrue(args.open)


class TestSelectAuditors(unittest.TestCase):
    """select_auditors() logic tests."""

    def _args(self, *argv):
        return audit.parse_args(list(argv))

    def test_aws_selects_all_aws(self):
        args = self._args("--aws")
        selected, show_ps1 = audit.select_auditors(args)
        for name in audit.AWS_GROUP:
            self.assertIn(name, selected, f"Expected {name} in AWS selection")
        self.assertFalse(show_ps1)

    def test_aws_selects_exactly_15(self):
        args = self._args("--aws")
        selected, _ = audit.select_auditors(args)
        self.assertEqual(len(selected), 15)

    def test_linux_selects_all_linux(self):
        args = self._args("--linux")
        selected, show_ps1 = audit.select_auditors(args)
        for name in audit.LINUX_GROUP:
            self.assertIn(name, selected)
        self.assertFalse(show_ps1)

    def test_linux_selects_exactly_4(self):
        args = self._args("--linux")
        selected, _ = audit.select_auditors(args)
        self.assertEqual(len(selected), 5)

    def test_all_selects_aws_and_linux(self):
        args = self._args("--all")
        selected, show_ps1 = audit.select_auditors(args)
        for name in audit.AWS_GROUP:
            self.assertIn(name, selected)
        for name in audit.LINUX_GROUP:
            self.assertIn(name, selected)
        self.assertTrue(show_ps1)

    def test_windows_shows_ps1(self):
        args = self._args("--windows")
        selected, show_ps1 = audit.select_auditors(args)
        self.assertEqual(selected, [])
        self.assertTrue(show_ps1)

    def test_azure_shows_ps1(self):
        args = self._args("--azure")
        selected, show_ps1 = audit.select_auditors(args)
        self.assertEqual(selected, [])
        self.assertTrue(show_ps1)

    def test_individual_s3_only(self):
        args = self._args("--s3")
        selected, _ = audit.select_auditors(args)
        self.assertEqual(selected, ["s3"])

    def test_individual_ec2_only(self):
        args = self._args("--ec2")
        selected, _ = audit.select_auditors(args)
        self.assertEqual(selected, ["ec2"])

    def test_individual_linux_user_only(self):
        args = self._args("--linux_user")
        selected, _ = audit.select_auditors(args)
        self.assertEqual(selected, ["linux_user"])

    def test_combination_s3_ec2(self):
        args = self._args("--s3", "--ec2")
        selected, _ = audit.select_auditors(args)
        self.assertIn("s3", selected)
        self.assertIn("ec2", selected)
        self.assertEqual(len(selected), 2)


class TestOutputFolderNaming(unittest.TestCase):
    """Output folder name format: {client}-{YYYY-MM-DD}."""

    def test_folder_name_format(self):
        from datetime import date
        today = date.today().strftime("%Y-%m-%d")
        expected = f"Acme-Corp-{today}"
        args = audit.parse_args(["--aws", "--client", "Acme Corp", "--output", "/tmp"])
        client_slug = args.client.replace(" ", "-")
        folder_name = f"{client_slug}-{today}"
        self.assertEqual(folder_name, expected)

    def test_folder_name_default_client(self):
        from datetime import date
        today = date.today().strftime("%Y-%m-%d")
        args = audit.parse_args(["--aws"])
        client_slug = args.client.replace(" ", "-")
        folder_name = f"{client_slug}-{today}"
        self.assertEqual(folder_name, f"audit-{today}")


class TestAuditorMapCompleteness(unittest.TestCase):
    """Verify all expected auditors are registered in AUDITOR_MAP."""

    def test_aws_group_count(self):
        self.assertEqual(len(audit.AWS_GROUP), 15)

    def test_aws_group_all_in_map(self):
        for name in audit.AWS_GROUP:
            self.assertIn(name, audit.AUDITOR_MAP, f"{name} missing from AUDITOR_MAP")

    def test_linux_group_count(self):
        self.assertEqual(len(audit.LINUX_GROUP), 5)

    def test_linux_group_all_in_map(self):
        for name in audit.LINUX_GROUP:
            self.assertIn(name, audit.AUDITOR_MAP, f"{name} missing from AUDITOR_MAP")

    def test_windows_ps1_count(self):
        self.assertEqual(len(audit.WINDOWS_PS1), 16)  # 7 Azure + m365/sharepoint/teams/intune/exchange + policy + azbackup + laps + netexpose

    def test_specific_aws_auditors_present(self):
        expected = ["s3", "ec2", "sg", "cloudtrail", "rds", "iam",
                    "root", "guardduty", "vpcflowlogs", "lambda",
                    "securityhub", "kms", "elb"]
        for name in expected:
            self.assertIn(name, audit.AUDITOR_MAP)

    def test_specific_linux_auditors_present(self):
        expected = ["linux_user", "linux_firewall", "linux_sysctl", "linux_patch"]
        for name in expected:
            self.assertIn(name, audit.AUDITOR_MAP)

    def test_specific_windows_ps1_present(self):
        expected = ["keyvault", "storage", "nsg", "activitylog",
                    "subscription", "entra", "defender"]
        for name in expected:
            self.assertIn(name, audit.WINDOWS_PS1)

    def test_regions_support_ec2(self):
        self.assertTrue(audit.AUDITOR_MAP["ec2"].supports_regions)

    def test_regions_support_kms(self):
        self.assertTrue(audit.AUDITOR_MAP["kms"].supports_regions)

    def test_no_regions_support_s3(self):
        self.assertFalse(audit.AUDITOR_MAP["s3"].supports_regions)

    def test_no_regions_support_sg(self):
        # sg uses --region (singular), orchestrator skips --regions for it
        self.assertFalse(audit.AUDITOR_MAP["sg"].supports_regions)

    def test_iam_script_path_contains_mapper(self):
        self.assertIn("iam_mapper_v2", str(audit.AUDITOR_MAP["iam"].script))


class TestBuildCmd(unittest.TestCase):
    """build_cmd() constructs correct subprocess argument lists."""

    def setUp(self):
        self.client_dir = Path("/tmp/test-client-2026-01-01")
        self.base_args = audit.parse_args(["--s3", "--output", "/tmp", "--client", "test"])

    def test_basic_cmd_structure(self):
        defn = audit.AUDITOR_MAP["s3"]
        cmd = audit.build_cmd("s3", defn, self.client_dir, self.base_args)
        self.assertEqual(cmd[0], sys.executable)
        self.assertIn("--output", cmd)
        self.assertIn("--format", cmd)

    def test_profile_included_when_set(self):
        args = audit.parse_args(["--s3", "--profile", "prod"])
        cmd = audit.build_cmd("s3", audit.AUDITOR_MAP["s3"], self.client_dir, args)
        self.assertIn("--profile", cmd)
        self.assertIn("prod", cmd)

    def test_regions_included_for_ec2(self):
        args = audit.parse_args(["--ec2", "--regions", "eu-west-1"])
        cmd = audit.build_cmd("ec2", audit.AUDITOR_MAP["ec2"], self.client_dir, args)
        self.assertIn("--regions", cmd)
        self.assertIn("eu-west-1", cmd)

    def test_regions_not_included_for_s3(self):
        args = audit.parse_args(["--s3", "--regions", "eu-west-1"])
        cmd = audit.build_cmd("s3", audit.AUDITOR_MAP["s3"], self.client_dir, args)
        self.assertNotIn("--regions", cmd)

    def test_output_prefix_in_cmd(self):
        defn = audit.AUDITOR_MAP["s3"]
        cmd = audit.build_cmd("s3", defn, self.client_dir, self.base_args)
        output_idx = cmd.index("--output")
        output_val = cmd[output_idx + 1]
        self.assertIn("s3_report", output_val)


class TestRunAuditor(unittest.TestCase):
    """run_auditor() unit tests with mocked subprocess."""

    def _make_progress(self):
        """Create a minimal Progress mock that accepts update() calls."""
        from rich.progress import Progress
        progress = MagicMock(spec=Progress)
        return progress

    def _args(self):
        return audit.parse_args(["--s3", "--output", "/tmp", "--client", "test"])

    def test_success_case(self):
        progress = self._make_progress()
        task_id = 0

        completed_proc = MagicMock()
        completed_proc.returncode = 0

        with patch("subprocess.run", return_value=completed_proc), \
             patch("builtins.open", unittest.mock.mock_open()):
            result = audit.run_auditor(
                "s3",
                audit.AUDITOR_MAP["s3"],
                Path("/tmp"),
                self._args(),
                progress,
                task_id,
            )

        self.assertEqual(result.status, "DONE")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.name, "s3")

    def test_failure_case(self):
        progress = self._make_progress()
        task_id = 0

        failed_proc = MagicMock()
        failed_proc.returncode = 1

        with patch("subprocess.run", return_value=failed_proc), \
             patch("builtins.open", unittest.mock.mock_open()):
            result = audit.run_auditor(
                "s3",
                audit.AUDITOR_MAP["s3"],
                Path("/tmp"),
                self._args(),
                progress,
                task_id,
            )

        self.assertEqual(result.status, "FAILED")
        self.assertEqual(result.returncode, 1)

    def test_timeout_case(self):
        progress = self._make_progress()
        task_id = 0

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="test", timeout=1)), \
             patch("builtins.open", unittest.mock.mock_open()):
            result = audit.run_auditor(
                "s3",
                audit.AUDITOR_MAP["s3"],
                Path("/tmp"),
                self._args(),
                progress,
                task_id,
            )

        self.assertEqual(result.status, "TIMEOUT")
        self.assertEqual(result.returncode, -1)

    def test_duration_is_positive(self):
        progress = self._make_progress()
        task_id = 0

        completed_proc = MagicMock()
        completed_proc.returncode = 0

        with patch("subprocess.run", return_value=completed_proc), \
             patch("builtins.open", unittest.mock.mock_open()):
            result = audit.run_auditor(
                "s3",
                audit.AUDITOR_MAP["s3"],
                Path("/tmp"),
                self._args(),
                progress,
                task_id,
            )

        self.assertGreaterEqual(result.duration, 0.0)


class TestWindowsInstructions(unittest.TestCase):
    """Windows/Azure PS1 instructions print without error."""

    def test_print_windows_instructions_no_error(self):
        """print_windows_instructions should not raise any exception."""
        from io import StringIO
        from rich.console import Console as RichConsole

        buf = StringIO()
        test_console = RichConsole(file=buf, width=120)

        # Patch the module-level console so print_windows_instructions uses ours
        original_console = audit.console
        audit.console = test_console
        try:
            audit.print_windows_instructions(Path("/tmp/test-client-2026-01-01"))
        finally:
            audit.console = original_console

        output = buf.getvalue()
        self.assertIn("PowerShell", output)
        self.assertIn("keyvault", output)
        self.assertIn("defender", output)

    def test_all_ps1_scripts_mentioned(self):
        """All 7 Azure PS1 scripts appear in instructions output."""
        from io import StringIO
        from rich.console import Console as RichConsole

        buf = StringIO()
        test_console = RichConsole(file=buf, width=120)

        original_console = audit.console
        audit.console = test_console
        try:
            audit.print_windows_instructions(Path("/tmp/test-client-2026-01-01"))
        finally:
            audit.console = original_console

        output = buf.getvalue()
        for name in audit.WINDOWS_PS1:
            self.assertIn(name, output, f"Expected {name} in PS1 instructions")


import subprocess  # needed for TimeoutExpired in test


# ── Email auditor integration tests ───────────────────────────────────────────

def test_email_in_auditor_map():
    """email key exists in AUDITOR_MAP with requires_domain=True."""
    assert "email" in audit.AUDITOR_MAP
    assert audit.AUDITOR_MAP["email"].requires_domain is True
    assert audit.AUDITOR_MAP["email"].supports_regions is False


def test_auditordef_requires_domain_default_false():
    """AuditorDef.requires_domain defaults to False."""
    defn = audit.AuditorDef(Path("/tmp/fake.py"), "fake_report")
    assert defn.requires_domain is False


def test_select_auditors_email_flag():
    """--email flag selects email auditor."""
    args = audit.parse_args(["--email", "--domain", "acme.ie", "--client", "test"])
    selected, _ = audit.select_auditors(args)
    assert "email" in selected


def test_select_auditors_all_excludes_email():
    """--all does NOT include email auditor."""
    args = audit.parse_args(["--all", "--client", "test"])
    selected, _ = audit.select_auditors(args)
    assert "email" not in selected


def test_main_email_without_domain_returns_error(capsys):
    """main() with --email but no --domain prints error and returns 1."""
    result = audit.main(["--email", "--client", "test"])
    captured = capsys.readouterr()
    assert result == 1
    assert "--domain" in captured.out or "domain" in captured.out.lower()


def test_build_cmd_injects_domain():
    """build_cmd injects --domain for auditors with requires_domain=True."""
    defn = audit.AuditorDef(Path("/tmp/fake.py"), "fake_report", requires_domain=True)
    args = audit.parse_args(["--email", "--domain", "acme.ie", "--client", "test"])
    cmd = audit.build_cmd("email", defn, Path("/tmp/out"), args)
    assert "--domain" in cmd
    assert "acme.ie" in cmd


def test_build_cmd_no_domain_for_regular_auditors():
    """build_cmd does NOT inject --domain for auditors with requires_domain=False."""
    defn = audit.AuditorDef(Path("/tmp/fake.py"), "fake_report", requires_domain=False)
    args = audit.parse_args(["--s3", "--domain", "acme.ie", "--client", "test"])
    cmd = audit.build_cmd("s3", defn, Path("/tmp/out"), args)
    assert "--domain" not in cmd


if __name__ == "__main__":
    unittest.main()
