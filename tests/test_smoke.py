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
        # 假 AWS key 分片拼接，且不使用 EXAMPLE 占位符（会被 placeholder 过滤跳过）
        fake_aws = "AKIA" + "1234567890ABCDEF"
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
        # 默认脱敏：原始密钥不得出现在 stdout/JSON
        self.assertNotIn("SuperSecret123", proc.stdout)
        self.assertNotIn("1234567890ABCDEF", proc.stdout)

    def test_scan_redacts_and_reveal_is_opt_in(self) -> None:
        (self.root / "app.py").write_text('password = "SuperSecret123"\n', encoding="utf-8")
        redacted = run_script("scan_secrets.py", str(self.root), "--json")
        self.assertNotIn("SuperSecret123", redacted.stdout)
        self.assertIn("[REDACTED]", redacted.stdout)

        revealed = run_script("scan_secrets.py", str(self.root), "--json", "--reveal")
        self.assertIn("SuperSecret123", revealed.stdout)

    def test_scan_env_secret_is_a_hit(self) -> None:
        (self.root / ".env").write_text("DB_PASSWORD=ProdSecret123\n", encoding="utf-8")
        proc = run_script("scan_secrets.py", str(self.root), "--json")
        data = json.loads(proc.stdout)
        rules = {hit["rule"] for hit in data["hits"]}
        self.assertIn("dotenv-secret", rules)
        strict = run_script("scan_secrets.py", str(self.root), "--fail-on-hit")
        self.assertEqual(strict.returncode, 1)

    def test_pypirc_rule_is_scoped_to_dot_pypirc(self) -> None:
        (self.root / "app.py").write_text('password = "SuperSecret123"\n', encoding="utf-8")
        data = json.loads(run_script("scan_secrets.py", str(self.root), "--json").stdout)
        self.assertEqual({hit["rule"] for hit in data["hits"]}, {"password-literal"})

    def test_docker_config_is_a_sensitive_file(self) -> None:
        docker = self.root / ".docker"
        docker.mkdir()
        (docker / "config.json").write_text('{"auths": {}}\n', encoding="utf-8")
        data = json.loads(run_script("scan_secrets.py", str(self.root), "--json").stdout)
        self.assertIn(".docker/config.json", data["sensitive_files"])

    def test_scan_baseline_and_exclude(self) -> None:
        (self.root / "app.py").write_text('password = "SuperSecret123"\n', encoding="utf-8")
        proc = run_script("scan_secrets.py", str(self.root), "--json")
        data = json.loads(proc.stdout)
        self.assertTrue(data["hits"])

        baseline = self.root / "baseline.json"
        baseline.write_text(json.dumps({
            "hits": [
                {"rule": hit["rule"], "file": hit["file"], "fingerprint": hit["fingerprint"]}
                for hit in data["hits"]
            ]
        }), encoding="utf-8")
        suppressed = run_script("scan_secrets.py", str(self.root), "--json", "--baseline", str(baseline))
        suppressed_data = json.loads(suppressed.stdout)
        self.assertEqual(suppressed_data["hits"], [])
        self.assertEqual(suppressed_data["baseline_suppressed"], len(data["hits"]))
        self.assertEqual(
            run_script("scan_secrets.py", str(self.root), "--baseline", str(baseline), "--fail-on-hit").returncode,
            0,
        )

        excluded = run_script("scan_secrets.py", str(self.root), "--json", "--exclude", "app.py")
        self.assertEqual(json.loads(excluded.stdout)["hits"], [])

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
        self.assertNotIn("SuperSecret123", proc.stdout)

        strict = run_script("self_check.py", str(self.root), "--skip-deps", "--strict")
        self.assertEqual(strict.returncode, 1, strict.stdout + strict.stderr)

    def test_self_check_clean_fixture_passes_strict(self) -> None:
        self.make_clean_fixture()
        proc = run_script("self_check.py", str(self.root), "--json", "--skip-deps", "--strict")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["summary"]["fail"], 0)

    def test_self_check_env_secret_fails(self) -> None:
        (self.root / "app.py").write_text("print('ok')\n", encoding="utf-8")
        (self.root / ".env").write_text("DB_PASSWORD=ProdSecret123\n", encoding="utf-8")
        proc = run_script("self_check.py", str(self.root), "--json", "--skip-deps", "--strict")
        self.assertEqual(proc.returncode, 1)
        checks = {item["check"]: item for item in json.loads(proc.stdout)["checks"]}
        self.assertEqual(checks["secrets-hits"]["level"], "FAIL")

    def test_self_check_debug_in_test_path_does_not_mask_production(self) -> None:
        (self.root / "app.py").write_text("DEBUG = True\n", encoding="utf-8")
        tests = self.root / "tests"
        tests.mkdir()
        (tests / "fixture.yaml").write_text("debug: true\n", encoding="utf-8")
        proc = run_script("self_check.py", str(self.root), "--json", "--skip-deps", "--strict")
        self.assertEqual(proc.returncode, 1)
        checks = {item["check"]: item for item in json.loads(proc.stdout)["checks"]}
        self.assertEqual(checks["debug"]["level"], "FAIL")

    def test_self_check_finds_nested_compose(self) -> None:
        (self.root / "app.py").write_text("print('ok')\n", encoding="utf-8")
        deploy = self.root / "deploy"
        deploy.mkdir()
        (deploy / "docker-compose.yml").write_text(
            "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: postgres\n",
            encoding="utf-8",
        )
        proc = run_script("self_check.py", str(self.root), "--json", "--skip-deps", "--strict")
        self.assertEqual(proc.returncode, 1)
        checks = {item["check"]: item for item in json.loads(proc.stdout)["checks"]}
        self.assertEqual(checks["deployment-compose"]["level"], "FAIL")

    def test_scan_secrets_rejects_missing_target(self) -> None:
        proc = run_script("scan_secrets.py", str(self.root / "does-not-exist"))
        self.assertEqual(proc.returncode, 1)


if __name__ == "__main__":
    unittest.main()
