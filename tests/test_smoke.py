#!/usr/bin/env python3
"""Smoke tests for scan_secrets.py / self_check.py.

Run:
    python -m unittest discover -s tests -v

测试夹具在临时目录中生成，不把任何真实密钥写进仓库；
源码里的假密钥通过字符串拼接构造，避免 GitHub secret scanning 误报。
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def run_script(name: str, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / name), *args],
        cwd=str(cwd or ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="audit-fixture-")
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def make_dirty_fixture(self) -> None:
        # 假 AWS key 分片拼接，避免仓库源码里出现完整模式
        fake_aws = "AKIA" + "IOSFODNN7EXAMPLE"
        (self.root / "app.py").write_text(
            "DEBUG = True\n"
            f"AWS_ACCESS_KEY = \"{fake_aws}\"\n"
            "password = \"SuperSecret123\"\n",
            encoding="utf-8",
        )
        (self.root / "app.yaml").write_text("debug: true\n", encoding="utf-8")
        (self.root / ".env").write_text("DEBUG=true\n", encoding="utf-8")
        (self.root / "server.pem").write_text("-----BEGIN " + "PRIVATE KEY-----\nnot-real\n", encoding="utf-8")
        (self.root / "docker-compose.yml").write_text(
            "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: postgres\n",
            encoding="utf-8",
        )
        nginx = self.root / "nginx"
        nginx.mkdir()
        (nginx / "site.conf").write_text("autoindex on;\n", encoding="utf-8")

    def make_clean_fixture(self) -> None:
        (self.root / ".gitignore").write_text(".env\nsecurity-reports/\n", encoding="utf-8")
        (self.root / "app.py").write_text("print('hello')\n", encoding="utf-8")

    def test_scan_secrets_finds_rules_and_sensitive_files(self) -> None:
        self.make_dirty_fixture()
        proc = run_script("scan_secrets.py", str(self.root), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        rules = {hit["rule"] for hit in data["hits"]}
        self.assertIn("aws-aksk", rules)
        self.assertIn("password-literal", rules)
        sensitive = set(data["sensitive_files"])
        self.assertIn(".env", sensitive)
        self.assertIn("server.pem", sensitive)

    def test_self_check_detects_failures_and_strict_exit(self) -> None:
        self.make_dirty_fixture()
        proc = run_script("self_check.py", str(self.root), "--json", "--skip-deps")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertGreaterEqual(data["summary"]["fail"], 1)
        checks = {item["check"]: item for item in data["checks"]}
        self.assertEqual(checks["debug"]["level"], "FAIL")
        self.assertEqual(checks["deployment-compose"]["level"], "FAIL")
        self.assertEqual(checks["secrets-hits"]["level"], "FAIL")

        strict = run_script("self_check.py", str(self.root), "--skip-deps", "--strict")
        self.assertEqual(strict.returncode, 1, strict.stdout + strict.stderr)

    def test_self_check_clean_fixture_passes_strict(self) -> None:
        self.make_clean_fixture()
        proc = run_script("self_check.py", str(self.root), "--json", "--skip-deps", "--strict")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["summary"]["fail"], 0)

    def test_scan_secrets_rejects_missing_target(self) -> None:
        proc = run_script("scan_secrets.py", str(self.root / "does-not-exist"))
        self.assertEqual(proc.returncode, 1)


if __name__ == "__main__":
    unittest.main()
