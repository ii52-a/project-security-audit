#!/usr/bin/env python3
"""Unit tests for dependency-audit severity handling (no network)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import self_check  # noqa: E402


class DependencyTests(unittest.TestCase):
    def test_npm_high_is_fail(self) -> None:
        payload = json.dumps({"metadata": {"vulnerabilities": {"high": 2, "critical": 1, "total": 3}}})
        with mock.patch.object(self_check.shutil, "which", return_value="npm"), \
                mock.patch.object(self_check, "run", return_value=(1, payload)):
            level, _message, _details = self_check._dep_npm(ROOT, 5)
        self.assertEqual(level, "FAIL")

    def test_npm_low_is_warn(self) -> None:
        payload = json.dumps({"metadata": {"vulnerabilities": {"high": 0, "critical": 0, "total": 2}}})
        with mock.patch.object(self_check.shutil, "which", return_value="npm"), \
                mock.patch.object(self_check, "run", return_value=(1, payload)):
            level, _message, _details = self_check._dep_npm(ROOT, 5)
        self.assertEqual(level, "WARN")

    def test_npm_v6_advisories_high_is_fail(self) -> None:
        payload = json.dumps({"advisories": {"1": {"severity": "high"}}})
        with mock.patch.object(self_check.shutil, "which", return_value="npm"), \
                mock.patch.object(self_check, "run", return_value=(1, payload)):
            level, _message, _details = self_check._dep_npm(ROOT, 5)
        self.assertEqual(level, "FAIL")

    def test_npm_clean_is_pass(self) -> None:
        payload = json.dumps({"metadata": {"vulnerabilities": {"high": 0, "critical": 0, "total": 0}}})
        with mock.patch.object(self_check.shutil, "which", return_value="npm"), \
                mock.patch.object(self_check, "run", return_value=(0, payload)):
            level, _message, _details = self_check._dep_npm(ROOT, 5)
        self.assertEqual(level, "PASS")

    def test_missing_tool_is_not_clean(self) -> None:
        with mock.patch.object(self_check.shutil, "which", return_value=None):
            level, _message, _details = self_check._dep_npm(ROOT, 5)
        self.assertEqual(level, "WARN")


if __name__ == "__main__":
    unittest.main()
