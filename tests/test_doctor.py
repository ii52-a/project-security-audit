#!/usr/bin/env python3
"""Tests for audit_doctor.py (version, depth docs, rule parity)."""

from __future__ import annotations

import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import audit_doctor  # noqa: E402


class DoctorTests(unittest.TestCase):
    def test_repository_is_consistent(self) -> None:
        checks = audit_doctor.run_checks()
        failures = [item for item in checks if item["level"] == "FAIL"]
        self.assertEqual(failures, [], failures)

    def test_versions_match_version_file(self) -> None:
        expected = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        checks = audit_doctor.check_versions()
        self.assertEqual(checks[0]["level"], "PASS", checks)
        self.assertIn(expected, checks[0]["message"])

    def test_rule_names_match_between_python_and_bash(self) -> None:
        checks = audit_doctor.check_rule_parity()
        self.assertEqual(checks[0]["level"], "PASS", checks)

    def test_depth_docs_and_high_only_ids_present(self) -> None:
        checks = audit_doctor.check_depth_docs()
        failures = [item for item in checks if item["level"] == "FAIL"]
        self.assertEqual(failures, [], failures)


if __name__ == "__main__":
    unittest.main()
