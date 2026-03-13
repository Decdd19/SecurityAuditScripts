"""Tests for iam_mapper_v2.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../AWS/iam-privilege-mapper"))

import pytest
from unittest.mock import MagicMock, patch
import iam_mapper_v2 as iam


# ── extract_actions ────────────────────────────────────────────────────────────

def test_extract_actions_allow():
    doc = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"]}]}
    assert iam.extract_actions(doc) == {"s3:getobject", "s3:putobject"}


def test_extract_actions_skips_deny():
    doc = {"Statement": [{"Effect": "Deny", "Action": "s3:*"}]}
    assert iam.extract_actions(doc) == set()


def test_extract_actions_string_action():
    doc = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole"}]}
    assert "iam:passrole" in iam.extract_actions(doc)


def test_extract_actions_dict_statement():
    doc = {"Statement": {"Effect": "Allow", "Action": ["ec2:*"]}}
    assert "ec2:*" in iam.extract_actions(doc)


# ── score_actions ──────────────────────────────────────────────────────────────

def test_score_actions_wildcard():
    assert "*" in iam.score_actions({"*"})


def test_score_actions_service_wildcard():
    assert "iam:*" in iam.score_actions({"iam:*"})


def test_score_actions_no_risk():
    result = iam.score_actions({"s3:getobject", "cloudwatch:putmetricdata"})
    assert result == []


# ── check_privesc ──────────────────────────────────────────────────────────────

def test_check_privesc_passrole_lambda():
    actions = {"iam:passrole", "lambda:createfunction", "lambda:invokefunction"}
    paths = iam.check_privesc(actions)
    assert any("PassRole" in p and "Lambda" in p for p in paths)


def test_check_privesc_no_match():
    actions = {"s3:getobject"}
    assert iam.check_privesc(actions) == []


def test_check_privesc_wildcard_covers_all():
    actions = {"*"}
    paths = iam.check_privesc(actions)
    assert len(paths) > 0


# ── calculate_score ────────────────────────────────────────────────────────────

def test_calculate_score_critical():
    score, level = iam.calculate_score({"*", "iam:*"}, ["path1", "path2"], True, True, True, True, False, True)
    assert level == "CRITICAL"
    assert score >= 8


def test_calculate_score_low():
    score, level = iam.calculate_score(set(), [], False, False, False, False, False, False)
    assert level == "LOW"
    assert score == 0


def test_calculate_score_boundary_reduces_score():
    score_no_boundary, _ = iam.calculate_score({"iam:*"}, [], False, False, False, False, False, False)
    score_with_boundary, _ = iam.calculate_score({"iam:*"}, [], False, False, False, False, True, False)
    assert score_with_boundary < score_no_boundary


# ── paginate ───────────────────────────────────────────────────────────────────

def test_paginate_single_page():
    mock_fn = MagicMock(return_value={"Users": [{"UserName": "alice"}]})
    result = iam.paginate(mock_fn, "Users")
    assert result == [{"UserName": "alice"}]


def test_paginate_multiple_pages():
    mock_fn = MagicMock(side_effect=[
        {"Users": [{"UserName": "alice"}], "Marker": "token1"},
        {"Users": [{"UserName": "bob"}]},
    ])
    result = iam.paginate(mock_fn, "Users")
    assert len(result) == 2
