#!/usr/bin/env python3
"""Tests for audit_depth.py (depth metrics, recommendation, H1-H8 checklist)."""

from __future__ import annotations

import unittest
from pathlib import Path
import json
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import audit_depth  # noqa: E402
from evidence_helpers import high_record


def metrics(**overrides) -> dict:
    base = {
        "source_files": 100,
        "source_loc": 10_000,
        "interfaces_estimate": 20,
        "services_estimate": 1,
    }
    base.update(overrides)
    return base


class DepthTests(unittest.TestCase):
    def test_measure_counts_first_party_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-depth-") as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/x')\ndef x():\n    return 'ok'\n",
                encoding="utf-8",
            )
            (root / "src" / "api.ts").write_text("app.get('/y', () => 1)\n", encoding="utf-8")
            (root / "README.md").write_text("docs\n", encoding="utf-8")
            (root / "package.json").write_text("{}", encoding="utf-8")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "dep.js").write_text("x\n", encoding="utf-8")

            measured = audit_depth.measure_project(root)
            self.assertEqual(measured["source_files"], 2)
            self.assertGreater(measured["source_loc"], 0)
            self.assertGreaterEqual(measured["interfaces_estimate"], 2)
            self.assertEqual(measured["services_estimate"], 1)
            self.assertTrue(any("regex" in note for note in measured["notes"]))

    def test_measure_counts_compose_services(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-depth-") as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
            (root / "docker-compose.yml").write_text(
                "services:\n  api:\n    image: x\n  db:\n    image: y\n", encoding="utf-8"
            )
            measured = audit_depth.measure_project(root)
            self.assertEqual(measured["compose_services"], 2)
            self.assertEqual(measured["services_estimate"], 2)

    def test_recommend_low_and_high(self) -> None:
        low = audit_depth.recommend_depth(metrics())
        self.assertEqual(low["recommended"], "comprehensive-low")
        self.assertEqual(low["effective"], "comprehensive-low")
        self.assertFalse(low["downgrade_candidate"])

        high = audit_depth.recommend_depth(metrics(source_files=2_500, risk_factors=["payment"]))
        self.assertEqual(high["recommended"], "comprehensive-high")
        self.assertEqual(high["effective"], "comprehensive-high")

    def test_high_on_small_codebase_is_kept_with_warning(self) -> None:
        decision = audit_depth.recommend_depth(metrics(), requested="high")
        self.assertEqual(decision["effective"], "comprehensive-high")
        self.assertFalse(decision["downgrade_candidate"])
        self.assertIsNone(decision["warning"])

    def test_high_is_kept_on_large_codebase(self) -> None:
        decision = audit_depth.recommend_depth(metrics(source_files=5_000), requested="high")
        self.assertEqual(decision["effective"], "comprehensive-high")
        self.assertFalse(decision["downgrade_candidate"])

    def test_quick_warns_above_advisory_size(self) -> None:
        decision = audit_depth.recommend_depth(metrics(source_files=400), requested="quick")
        self.assertEqual(decision["effective"], "quick")
        self.assertIsNotNone(decision["warning"])

    def test_high_only_checklist_has_h1_to_h8(self) -> None:
        ids = [item["id"] for item in audit_depth.HIGH_ONLY_ITEMS]
        self.assertEqual(ids, [f"H{i}" for i in range(1, 9)])
        rendered = audit_depth.render_high_only_checklist()
        for item_id in ids:
            self.assertIn(f"| {item_id} |", rendered)

    def test_evaluate_high_only_requires_h1_h3_and_six_items(self) -> None:
        incomplete = audit_depth.evaluate_high_only({"H1": "done", "H2": "n/a", "H3": "done"})
        self.assertFalse(incomplete["achieved"])

        complete = audit_depth.evaluate_high_only({f"H{i}": high_record(f"H{i}") for i in range(1, 9)})
        self.assertTrue(complete["achieved"])
        self.assertEqual(complete["count"], 8)

    def test_missing_target_raises(self) -> None:
        with self.assertRaises(NotADirectoryError):
            audit_depth.measure_project(ROOT / "does-not-exist")

    def test_cli_high_status_exit_codes(self) -> None:
        script = ROOT / "scripts" / "audit_depth.py"
        with tempfile.TemporaryDirectory(prefix="audit-depth-") as tmp:
            status_file = Path(tmp) / "high.json"
            status_file.write_text(json.dumps({f"H{i}": high_record(f"H{i}") for i in range(1, 9)}), encoding="utf-8")
            complete = subprocess.run(
                [sys.executable, str(script), "--high-status", str(status_file)],
                capture_output=True, text=True, timeout=60, check=False,
            )
            self.assertEqual(complete.returncode, 0, complete.stdout + complete.stderr)

            status_file.write_text(json.dumps({"H1": "done", "H2": "n/a", "H3": "done"}),
                                   encoding="utf-8")
            incomplete = subprocess.run(
                [sys.executable, str(script), "--high-status", str(status_file)],
                capture_output=True, text=True, timeout=60, check=False,
            )
            self.assertEqual(incomplete.returncode, 1)


if __name__ == "__main__":
    unittest.main()
