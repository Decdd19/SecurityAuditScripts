"""Unit tests for schema.py — validate_finding() normalisation and rejection."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from schema import validate_finding, VALID_RISK_LEVELS


class TestValidateFindingCanonical(unittest.TestCase):

    def test_canonical_finding_returned_unchanged(self):
        """Finding with all canonical fields passes through untouched."""
        f = {
            "risk_level": "HIGH",
            "remediation": "Fix it",
            "flag": "Port open",
            "cis_control": "CIS 9",
        }
        result = validate_finding(dict(f))
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(result["remediation"], "Fix it")
        self.assertEqual(result["flag"], "Port open")

    def test_all_valid_risk_levels_accepted(self):
        for level in VALID_RISK_LEVELS:
            result = validate_finding({"risk_level": level})
            self.assertEqual(result["risk_level"], level)


class TestValidateFindingAliases(unittest.TestCase):

    def test_severity_mapped_to_risk_level(self):
        """Legacy 'severity' field is copied to 'risk_level'."""
        f = {"severity": "CRITICAL", "remediation": "Fix now"}
        result = validate_finding(f)
        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertEqual(result["severity"], "CRITICAL")  # original preserved

    def test_recommendation_mapped_to_remediation(self):
        """Legacy 'recommendation' field is copied to 'remediation'."""
        f = {"risk_level": "LOW", "recommendation": "Check config"}
        result = validate_finding(f)
        self.assertEqual(result["remediation"], "Check config")
        self.assertEqual(result["recommendation"], "Check config")  # original preserved

    def test_detail_mapped_to_flag(self):
        """Legacy 'detail' field is copied to 'flag' when flag absent."""
        f = {"risk_level": "MEDIUM", "detail": "sshd version 7.2"}
        result = validate_finding(f)
        self.assertEqual(result["flag"], "sshd version 7.2")

    def test_existing_flag_not_overwritten_by_detail(self):
        """If 'flag' already present, 'detail' does not overwrite it."""
        f = {"risk_level": "MEDIUM", "flag": "explicit flag", "detail": "ignored detail"}
        result = validate_finding(f)
        self.assertEqual(result["flag"], "explicit flag")


class TestValidateFindingRejection(unittest.TestCase):

    def test_raises_value_error_when_no_risk_level_or_severity(self):
        with self.assertRaises(ValueError) as ctx:
            validate_finding({"finding_type": "PortOpen", "remediation": "Close it"})
        self.assertIn("risk_level", str(ctx.exception))

    def test_raises_value_error_on_invalid_risk_level(self):
        with self.assertRaises(ValueError) as ctx:
            validate_finding({"risk_level": "SEVERE"})
        self.assertIn("SEVERE", str(ctx.exception))

    def test_raises_value_error_on_lowercase_risk_level(self):
        with self.assertRaises(ValueError):
            validate_finding({"risk_level": "high"})


class TestSchemaContractPerAuditorType(unittest.TestCase):
    """Contract tests: each auditor schema type passes validate_finding() cleanly
    and produces the four canonical fields (risk_level, remediation, flag, cis_control).
    Fixtures mirror the actual field shapes produced by each auditor family.
    """

    # AWS-style: s3, sg, cloudtrail, root, iam, ec2, rds, etc.
    # Uses risk_level + flags[] + remediations[]; no top-level flag/remediation.
    AWS_FINDING = {
        "risk_level": "CRITICAL",
        "severity_score": 9,
        "name": "acme-public-backup",
        "flags": ["❌ Public access enabled", "❌ No encryption"],
        "remediations": ["Block public access via S3 console", "Enable SSE-S3 encryption"],
    }

    # Linux-style: ssh, sysctl, firewall, user, patch.
    # Uses risk_level + recommendation (alias → remediation); no flag.
    LINUX_FINDING = {
        "risk_level": "HIGH",
        "param": "PermitRootLogin",
        "actual": "yes",
        "expected": "no",
        "description": "Root login via SSH is permitted",
        "recommendation": "Set PermitRootLogin no in /etc/ssh/sshd_config",
    }

    # Network/Email-style: ssl_tls, http_headers, email_security.
    # Uses risk_level + remediation (canonical) + detail (alias → flag).
    NETWORK_FINDING = {
        "check_id": "TLS-01",
        "name": "Certificate Expiry",
        "status": "FAIL",
        "risk_level": "CRITICAL",
        "severity_score": 8,
        "detail": "Certificate expired 7 days ago",
        "remediation": "Renew the certificate immediately",
        "pillar": "tls",
        "cis_control": "CIS 4",
    }

    # PowerShell auditor compat: uses 'severity' instead of 'risk_level'.
    POWERSHELL_FINDING = {
        "severity": "HIGH",
        "finding_type": "KeyVault-01",
        "recommendation": "Enable soft-delete on the key vault",
    }

    def _assert_canonical(self, result):
        """Assert all four canonical fields are present and risk_level is valid."""
        self.assertIn("risk_level", result)
        self.assertIn(result["risk_level"], VALID_RISK_LEVELS)
        self.assertIn("remediation", result)
        self.assertIn("flag", result)

    def test_aws_style_finding_passes_contract(self):
        result = validate_finding(dict(self.AWS_FINDING))
        self._assert_canonical(result)
        self.assertEqual(result["risk_level"], "CRITICAL")
        # AWS findings have no top-level remediation — validate_finding sets it to ""
        self.assertEqual(result["remediation"], "")

    def test_linux_style_finding_passes_contract(self):
        result = validate_finding(dict(self.LINUX_FINDING))
        self._assert_canonical(result)
        # recommendation alias → remediation
        self.assertEqual(result["remediation"], "Set PermitRootLogin no in /etc/ssh/sshd_config")
        # original recommendation field preserved
        self.assertEqual(result["recommendation"], "Set PermitRootLogin no in /etc/ssh/sshd_config")

    def test_network_email_style_finding_passes_contract(self):
        result = validate_finding(dict(self.NETWORK_FINDING))
        self._assert_canonical(result)
        # remediation already canonical — preserved unchanged
        self.assertEqual(result["remediation"], "Renew the certificate immediately")
        # detail alias → flag
        self.assertEqual(result["flag"], "Certificate expired 7 days ago")
        # original detail field preserved
        self.assertEqual(result["detail"], "Certificate expired 7 days ago")

    def test_powershell_style_finding_passes_contract(self):
        result = validate_finding(dict(self.POWERSHELL_FINDING))
        self._assert_canonical(result)
        # severity alias → risk_level
        self.assertEqual(result["risk_level"], "HIGH")
        # recommendation alias → remediation
        self.assertEqual(result["remediation"], "Enable soft-delete on the key vault")

    def test_all_auditor_types_preserve_extra_fields(self):
        """Extra auditor-specific fields (param, actual, name, etc.) are not stripped."""
        result = validate_finding(dict(self.LINUX_FINDING))
        self.assertIn("param", result)
        self.assertIn("actual", result)
        self.assertIn("expected", result)

        result = validate_finding(dict(self.NETWORK_FINDING))
        self.assertIn("check_id", result)
        self.assertIn("pillar", result)
        self.assertIn("cis_control", result)


if __name__ == "__main__":
    unittest.main()
