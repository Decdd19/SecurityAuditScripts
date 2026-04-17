"""Tests for add_auditor.py — template rendering and scaffold logic."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import add_auditor


# ── Template rendering (Critical #3 fix) ──────────────────────────────────────

def test_linux_stub_template_renders_without_key_error():
    """LINUX_STUB_TEMPLATE must not raise KeyError on .format() — brace escaping bug."""
    short_name, title, script_name, dir_path, prefix = add_auditor.derive_parts(
        "linux_disk", "linux", None
    )
    # This call used to crash with KeyError due to unescaped {"=" * ...} expression
    content = add_auditor.LINUX_STUB_TEMPLATE.format(
        title=title,
        short_name=short_name,
        script_name=script_name,
        output_prefix=prefix,
    )
    assert isinstance(content, str)
    assert "Linux Disk Auditor" in content


def test_generic_stub_template_renders_without_key_error():
    """GENERIC_STUB_TEMPLATE must not raise KeyError on .format()."""
    short_name, title, script_name, dir_path, prefix = add_auditor.derive_parts(
        "ssl", "network", None
    )
    content = add_auditor.GENERIC_STUB_TEMPLATE.format(
        title=title,
        short_name=short_name,
        script_name=script_name,
        output_prefix=prefix,
    )
    assert isinstance(content, str)
    assert "Ssl Auditor" in content


def test_create_stub_linux_does_not_crash(tmp_path, monkeypatch):
    """create_stub for a linux auditor must not raise KeyError."""
    monkeypatch.setattr(add_auditor, "REPO_ROOT", tmp_path)
    short_name, title, script_name, dir_path, prefix = add_auditor.derive_parts(
        "linux_disk", "linux", None
    )
    dir_path = tmp_path / "OnPrem" / "Linux" / "linux-disk-auditor"
    script_path = add_auditor.create_stub(short_name, title, script_name, dir_path, prefix, "linux")
    assert script_path.exists()
    content = script_path.read_text()
    assert "Linux Disk Auditor" in content


# ── derive_parts ──────────────────────────────────────────────────────────────

def test_derive_parts_linux():
    short_name, title, script_name, dir_path, prefix = add_auditor.derive_parts(
        "linux_disk", "linux", None
    )
    assert short_name == "disk"
    assert title == "Disk"
    assert script_name == "linux_disk_auditor"
    assert prefix == "disk_report"


def test_derive_parts_aws():
    short_name, title, script_name, dir_path, prefix = add_auditor.derive_parts(
        "aws_config", "aws", None
    )
    assert short_name == "config"
    assert script_name == "config_auditor"
    assert prefix == "config_report"


def test_derive_parts_custom_output_prefix():
    short_name, title, script_name, dir_path, prefix = add_auditor.derive_parts(
        "linux_disk", "linux", "my_disk_report"
    )
    assert prefix == "my_disk_report"
