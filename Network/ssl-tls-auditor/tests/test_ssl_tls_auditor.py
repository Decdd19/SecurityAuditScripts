"""Tests for ssl_tls_auditor.py"""
import sys
import os
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import ssl_tls_auditor as sta
