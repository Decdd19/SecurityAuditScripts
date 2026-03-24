"""Tests for lambda_auditor.py"""
import sys
import os
import json
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import lambda_auditor as la


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _fn_config(
    name="my-fn", runtime="python3.12", role="arn:aws:iam::123:role/my-role",
    env_vars=None, tracing_mode="PassThrough", in_vpc=False, has_dlq=False, region="eu-west-1"
):
    cfg = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role,
        "TracingConfig": {"Mode": tracing_mode},
        "_region": region,
        "Environment": {"Variables": env_vars or {}},
    }
    if in_vpc:
        cfg["VpcConfig"] = {"VpcId": "vpc-abc"}
    if has_dlq:
        cfg["DeadLetterConfig"] = {"TargetArn": "arn:aws:sqs:eu-west-1:123:dlq"}
    return cfg


def _lambda_client(has_url=False, url_auth="AWS_IAM", reserved_concurrency=None):
    lc = MagicMock()
    if has_url:
        lc.get_function_url_config.return_value = {"AuthType": url_auth}
    else:
        err = ClientError({"Error": {"Code": "ResourceNotFoundException", "Message": ""}}, "GetFunctionUrlConfig")
        lc.get_function_url_config.side_effect = err
    if reserved_concurrency is None:
        lc.get_function_concurrency.return_value = {}
    else:
        lc.get_function_concurrency.return_value = {"ReservedConcurrentExecutions": reserved_concurrency}
    return lc


def _iam_client(admin=False):
    iam = MagicMock()
    iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
    iam.list_role_policies.return_value = {"PolicyNames": []}
    if admin:
        iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                                  "PolicyName": "AdministratorAccess"}]
        }
    return iam


# ── find_secret_env_keys ──────────────────────────────────────────────────────

def test_find_secret_env_keys_detects_password():
    keys = la.find_secret_env_keys({"DB_PASSWORD": "x", "REGION": "eu-west-1"})
    assert "DB_PASSWORD" in keys
    assert "REGION" not in keys


def test_find_secret_env_keys_detects_api_key():
    keys = la.find_secret_env_keys({"API_KEY": "abc", "PORT": "8080"})
    assert "API_KEY" in keys


def test_find_secret_env_keys_detects_token():
    keys = la.find_secret_env_keys({"AUTH_TOKEN": "tok", "LOG_LEVEL": "INFO"})
    assert "AUTH_TOKEN" in keys
    assert "LOG_LEVEL" not in keys


def test_find_secret_env_keys_empty():
    assert la.find_secret_env_keys({}) == []
    assert la.find_secret_env_keys({"STAGE": "prod", "REGION": "eu-west-1"}) == []


# ── calculate_score ────────────────────────────────────────────────────────────

def test_score_public_url_plus_admin():
    score, risk = la.calculate_score(
        has_public_url=True, has_admin_role=True, has_secret_envs=False,
        has_deprecated_runtime=False, reserved_concurrency_zero=False
    )
    assert score == 8
    assert risk == "CRITICAL"


def test_score_public_url_only():
    score, risk = la.calculate_score(
        has_public_url=True, has_admin_role=False, has_secret_envs=False,
        has_deprecated_runtime=False, reserved_concurrency_zero=False
    )
    assert score == 4
    assert risk == "MEDIUM"


def test_score_clean_function():
    score, risk = la.calculate_score(
        has_public_url=False, has_admin_role=False, has_secret_envs=False,
        has_deprecated_runtime=False, reserved_concurrency_zero=False
    )
    assert score == 0
    assert risk == "LOW"


def test_score_capped_at_10():
    score, risk = la.calculate_score(
        has_public_url=True, has_admin_role=True, has_secret_envs=True,
        has_deprecated_runtime=True, reserved_concurrency_zero=True
    )
    assert score == 10
    assert risk == "CRITICAL"


# ── build_flags_and_remediations ──────────────────────────────────────────────

def test_flags_public_url_no_auth():
    fn = {
        "function_name": "test-fn", "has_function_url": True,
        "function_url_auth_type": "NONE", "has_admin_role": False,
        "high_risk_policies": [], "secret_env_keys": [], "deprecated_runtime": False,
        "has_dlq": True, "tracing_enabled": True, "runtime": "python3.12",
        "reserved_concurrency": None, "role_arn": "arn:aws:iam::123:role/r",
    }
    flags, rems = la.build_flags_and_remediations(fn)
    assert any("no authentication" in f.lower() for f in flags)
    assert any("Auth type" in r for r in rems)
    assert len(flags) == len(rems)


def test_flags_admin_role():
    fn = {
        "function_name": "test-fn", "has_function_url": False,
        "function_url_auth_type": None, "has_admin_role": True,
        "high_risk_policies": ["AdministratorAccess"], "secret_env_keys": [],
        "deprecated_runtime": False, "has_dlq": True, "tracing_enabled": True,
        "runtime": "python3.12", "reserved_concurrency": None,
        "role_arn": "arn:aws:iam::123:role/admin-role",
    }
    flags, rems = la.build_flags_and_remediations(fn)
    assert any("admin" in f.lower() for f in flags)
    assert any("least-privilege" in r.lower() or "FullAccess" in r for r in rems)


def test_flags_secret_env_keys():
    fn = {
        "function_name": "test-fn", "has_function_url": False,
        "function_url_auth_type": None, "has_admin_role": False,
        "high_risk_policies": [], "secret_env_keys": ["DB_PASSWORD", "API_KEY"],
        "deprecated_runtime": False, "has_dlq": True, "tracing_enabled": True,
        "runtime": "python3.12", "reserved_concurrency": None,
        "role_arn": "arn:aws:iam::123:role/r",
    }
    flags, rems = la.build_flags_and_remediations(fn)
    assert any("environment variables" in f.lower() for f in flags)
    assert any("Secrets Manager" in r for r in rems)


def test_flags_no_dlq_uses_info_prefix():
    fn = {
        "function_name": "test-fn", "has_function_url": False,
        "function_url_auth_type": None, "has_admin_role": False,
        "high_risk_policies": [], "secret_env_keys": [],
        "deprecated_runtime": False, "has_dlq": False, "tracing_enabled": True,
        "runtime": "python3.12", "reserved_concurrency": None,
        "role_arn": "arn:aws:iam::123:role/r",
    }
    flags, rems = la.build_flags_and_remediations(fn)
    assert any(f.startswith("ℹ️") and "dead-letter" in f.lower() for f in flags)


def test_flags_tracing_disabled_uses_info_prefix():
    fn = {
        "function_name": "test-fn", "has_function_url": False,
        "function_url_auth_type": None, "has_admin_role": False,
        "high_risk_policies": [], "secret_env_keys": [],
        "deprecated_runtime": False, "has_dlq": True, "tracing_enabled": False,
        "runtime": "python3.12", "reserved_concurrency": None,
        "role_arn": "arn:aws:iam::123:role/r",
    }
    flags, rems = la.build_flags_and_remediations(fn)
    assert any(f.startswith("ℹ️") and "X-Ray" in f for f in flags)


def test_flags_clean_function_has_positive_flag():
    fn = {
        "function_name": "test-fn", "has_function_url": False,
        "function_url_auth_type": None, "has_admin_role": False,
        "high_risk_policies": [], "secret_env_keys": [],
        "deprecated_runtime": False, "has_dlq": True, "tracing_enabled": True,
        "runtime": "python3.12", "reserved_concurrency": None,
        "role_arn": "arn:aws:iam::123:role/r",
    }
    flags, rems = la.build_flags_and_remediations(fn)
    assert any("✅" in f for f in flags)
    assert len(flags) == len(rems)


def test_flags_deprecated_runtime():
    fn = {
        "function_name": "test-fn", "has_function_url": False,
        "function_url_auth_type": None, "has_admin_role": False,
        "high_risk_policies": [], "secret_env_keys": [],
        "deprecated_runtime": True, "has_dlq": True, "tracing_enabled": True,
        "runtime": "python3.7", "reserved_concurrency": None,
        "role_arn": "arn:aws:iam::123:role/r",
    }
    flags, rems = la.build_flags_and_remediations(fn)
    assert any("Deprecated runtime" in f for f in flags)


def test_flags_reserved_concurrency_zero():
    fn = {
        "function_name": "test-fn", "has_function_url": False,
        "function_url_auth_type": None, "has_admin_role": False,
        "high_risk_policies": [], "secret_env_keys": [],
        "deprecated_runtime": False, "has_dlq": True, "tracing_enabled": True,
        "runtime": "python3.12", "reserved_concurrency": 0,
        "role_arn": "arn:aws:iam::123:role/r",
    }
    flags, rems = la.build_flags_and_remediations(fn)
    assert any("concurrency is 0" in f.lower() for f in flags)


def test_flags_parallel_lengths():
    fn = {
        "function_name": "test-fn", "has_function_url": True,
        "function_url_auth_type": "NONE", "has_admin_role": True,
        "high_risk_policies": ["AdministratorAccess"],
        "secret_env_keys": ["DB_PASSWORD"],
        "deprecated_runtime": True, "has_dlq": False, "tracing_enabled": False,
        "runtime": "python3.7", "reserved_concurrency": 0,
        "role_arn": "arn:aws:iam::123:role/admin-role",
    }
    flags, rems = la.build_flags_and_remediations(fn)
    assert len(flags) == len(rems)


# ── analyse_function ──────────────────────────────────────────────────────────

def test_analyse_function_clean():
    lc = _lambda_client(has_url=False)
    iam = _iam_client(admin=False)
    fn = _fn_config(tracing_mode="Active", has_dlq=True)
    result = la.analyse_function(lc, iam, fn)
    assert result["risk_level"] == "LOW"
    assert result["severity_score"] == 0
    assert result["has_function_url"] is False


def test_analyse_function_public_url_is_high_risk():
    lc = _lambda_client(has_url=True, url_auth="NONE")
    iam = _iam_client(admin=False)
    fn = _fn_config()
    result = la.analyse_function(lc, iam, fn)
    assert result["has_function_url"] is True
    assert result["function_url_auth_type"] == "NONE"
    assert result["severity_score"] >= 4


def test_analyse_function_admin_role_is_critical():
    lc = _lambda_client(has_url=True, url_auth="NONE")
    iam = _iam_client(admin=True)
    fn = _fn_config()
    result = la.analyse_function(lc, iam, fn)
    assert result["has_admin_role"] is True
    assert result["risk_level"] == "CRITICAL"


def test_analyse_function_secret_env_detected():
    lc = _lambda_client()
    iam = _iam_client()
    fn = _fn_config(env_vars={"DB_PASSWORD": "secret123", "REGION": "eu-west-1"})
    result = la.analyse_function(lc, iam, fn)
    assert "DB_PASSWORD" in result["secret_env_keys"]


def test_analyse_function_deprecated_runtime():
    lc = _lambda_client()
    iam = _iam_client()
    fn = _fn_config(runtime="python3.7")
    result = la.analyse_function(lc, iam, fn)
    assert result["deprecated_runtime"] is True


def test_analyse_function_reserved_concurrency_zero():
    lc = _lambda_client(reserved_concurrency=0)
    iam = _iam_client()
    fn = _fn_config()
    result = la.analyse_function(lc, iam, fn)
    assert result["reserved_concurrency"] == 0
    assert any("concurrency is 0" in flag.lower() for flag in result["flags"])


def test_analyse_function_result_has_required_keys():
    lc = _lambda_client()
    iam = _iam_client()
    fn = _fn_config()
    result = la.analyse_function(lc, iam, fn)
    for key in ["function_name", "region", "risk_level", "severity_score",
                "flags", "remediations", "has_function_url", "deprecated_runtime"]:
        assert key in result


def test_analyse_function_flags_rems_same_length():
    lc = _lambda_client(has_url=True, url_auth="NONE")
    iam = _iam_client(admin=True)
    fn = _fn_config(env_vars={"DB_PASSWORD": "x"}, runtime="python3.7")
    result = la.analyse_function(lc, iam, fn)
    assert len(result["flags"]) == len(result["remediations"])


# ── DEPRECATED_RUNTIMES constant ─────────────────────────────────────────────

def test_python_312_not_deprecated():
    assert "python3.12" not in la.DEPRECATED_RUNTIMES


def test_python_37_is_deprecated():
    assert "python3.7" in la.DEPRECATED_RUNTIMES


def test_nodejs14_is_deprecated():
    assert "nodejs14.x" in la.DEPRECATED_RUNTIMES


# ── write_json ────────────────────────────────────────────────────────────────

def _sample_report():
    return {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "summary": {"total_functions": 1, "critical": 0, "high": 0, "medium": 0, "low": 1},
        "findings": [{
            "function_name": "my-fn", "region": "eu-west-1",
            "runtime": "python3.12", "role_arn": "arn:aws:iam::123:role/r",
            "has_function_url": False, "function_url_auth_type": None,
            "has_dlq": True, "tracing_enabled": True, "in_vpc": False,
            "reserved_concurrency": None, "deprecated_runtime": False,
            "secret_env_keys": [], "has_admin_role": False,
            "risk_level": "LOW", "severity_score": 0,
            "flags": ["✅ No significant findings"], "remediations": [""],
        }],
    }


def test_write_json_creates_valid_json(tmp_path):
    path = str(tmp_path / "report.json")
    la.write_json(_sample_report(), path)
    data = json.loads(open(path).read())
    assert data["findings"][0]["function_name"] == "my-fn"


def test_write_json_600_permissions(tmp_path):
    path = str(tmp_path / "report.json")
    la.write_json(_sample_report(), path)
    assert oct(os.stat(path).st_mode)[-3:] == "600"


def test_write_html_creates_file(tmp_path):
    path = str(tmp_path / "report.html")
    la.write_html(_sample_report(), path)
    content = open(path).read()
    assert "my-fn" in content
    assert "Lambda" in content


def test_write_html_600_permissions(tmp_path):
    path = str(tmp_path / "report.html")
    la.write_html(_sample_report(), path)
    assert oct(os.stat(path).st_mode)[-3:] == "600"


def test_write_csv_creates_file(tmp_path):
    path = str(tmp_path / "report.csv")
    la.write_csv(_sample_report()["findings"], path)
    assert "my-fn" in open(path).read()
