#!/usr/bin/env python3
"""audit_doctor.py — 检查 security-audit 技能自身的文档/脚本一致性。

用法:
    python scripts/audit_doctor.py [--json]

检查:
    1. 必需文件是否存在（SKILL、references、scripts、tests）。
    2. VERSION / SKILL / README / 中文手册 / 脚本常量是否一致。
    3. 三档名称（quick / comprehensive-low / comprehensive-high）是否已写入文档。
    4. high-only 清单 H1–H8 是否出现在 SKILL。
    5. Python 与 bash 密钥扫描规则名是否一致。

只读，不联网；用于改完技能后的自查与 CI。退出码 1 表示存在 FAIL。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

VERSION = "alpha1.7"
ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

REQUIRED_FILES = [
    "scripts/dependency_audit.py",
    "scripts/audit_guidance.py",
    "tests/test_v17.py",
    "references/controller-v17.md",
    "references/controller-v16.md",
    "scripts/audit_contracts.py",
    "scripts/config_analysis.py",
    "tests/test_v16.py",
    "tests/evidence_helpers.py",
    "scripts/audit_control.py",
    "scripts/audit_profiles.py",
    "scripts/audit_worker.py",
    "references/controller.md",
    "tests/test_control.py",
    "scripts/audit_history.py",
    "scripts/audit_report.py",
    "references/report-format.md",
    "assets/quick-report.json",
    "assets/comprehensive-report.json",
    "tests/test_v14.py",
    "SKILL.md",
    "README.md",
    "VERSION",
    "CHANGELOG.md",
    "references/server-vulns.md",
    "references/api-audit.md",
    "references/secrets-hijack.md",
    "references/advanced-risks.md",
    "references/vuln-intel.md",
    "references/attack-testing.md",
    "references/risk-standards.md",
    "references/structure-optimization.md",
    "references/performance.md",
    "references/audit-prompts.md",
    "references/self-review.md",
    "scripts/scan_secrets.py",
    "scripts/scan_secrets.sh",
    "scripts/self_check.py",
    "scripts/self_check.sh",
    "scripts/audit_depth.py",
    "scripts/audit_doctor.py",
    "tests/test_smoke.py",
    "tests/test_depth.py",
    "tests/test_doctor.py",
    "tests/test_deps.py",
]

MODE_NAMES = ("quick", "comprehensive-low", "comprehensive-high")
HIGH_ONLY_IDS = tuple(f"H{i}" for i in range(1, 9))


def _read(rel: str) -> str:
    path = ROOT / rel
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _version_from(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1).strip() if match else None


def check_required_files() -> list[dict]:
    missing = [rel for rel in REQUIRED_FILES if not (ROOT / rel).is_file()]
    if missing:
        return [{"level": "FAIL", "check": "required-files",
                 "message": f"缺少 {len(missing)} 个必需文件", "details": missing}]
    return [{"level": "PASS", "check": "required-files",
             "message": f"{len(REQUIRED_FILES)} 个必需文件齐全", "details": []}]


def check_versions() -> list[dict]:
    expected = _read("VERSION").strip()
    findings: list[str] = []
    if not expected:
        return [{"level": "FAIL", "check": "version",
                 "message": "VERSION 文件为空或不可读", "details": []}]

    candidates = {
        "SKILL.md": _version_from(r"Current version:\s*\*\*([^*]+)\*\*", _read("SKILL.md")),
        "README.md": _version_from(r"Current version:\s*\*\*([^*]+)\*\*", _read("README.md")),
        ".chinese/SKILL.md": _version_from(r"当前版本[：:]\s*\*\*([^*]+)\*\*", _read(".chinese/SKILL.md")),
        ".chinese/VERSION": _read(".chinese/VERSION").strip() or None,
        "scripts/scan_secrets.py": _version_from(r'VERSION\s*=\s*"([^"]+)"', _read("scripts/scan_secrets.py")),
        "scripts/self_check.py": _version_from(r'VERSION\s*=\s*"([^"]+)"', _read("scripts/self_check.py")),
        "scripts/audit_depth.py": _version_from(r'VERSION\s*=\s*"([^"]+)"', _read("scripts/audit_depth.py")),
        "scripts/audit_doctor.py": _version_from(r'VERSION\s*=\s*"([^"]+)"', _read("scripts/audit_doctor.py")),
    }
    for rel, value in candidates.items():
        if value is None:
            findings.append(f"{rel}: 未找到版本号")
        elif value != expected:
            findings.append(f"{rel}: {value} != {expected}")

    if findings:
        return [{"level": "FAIL", "check": "version",
                 "message": f"版本号不一致（期望 {expected}）", "details": findings}]
    return [{"level": "PASS", "check": "version",
             "message": f"版本号一致：{expected}", "details": []}]


def check_depth_docs() -> list[dict]:
    results: list[dict] = []
    docs = {
        "SKILL.md": _read("SKILL.md"),
        "README.md": _read("README.md"),
        ".chinese/SKILL.md": _read(".chinese/SKILL.md"),
        ".chinese/README.md": _read(".chinese/README.md"),
    }
    for rel, text in docs.items():
        missing = [name for name in MODE_NAMES if name not in text]
        if missing:
            results.append({"level": "FAIL", "check": "depth-docs",
                            "message": f"{rel} 缺少档位名称", "details": missing})
        else:
            results.append({"level": "PASS", "check": "depth-docs",
                            "message": f"{rel} 已包含三档名称", "details": []})

    skill = docs["SKILL.md"]
    missing_ids = [item for item in HIGH_ONLY_IDS if not re.search(rf"\b{item}\b", skill)]
    if missing_ids:
        results.append({"level": "FAIL", "check": "high-only",
                        "message": "SKILL.md 缺少 high-only 条目", "details": missing_ids})
    else:
        results.append({"level": "PASS", "check": "high-only",
                        "message": "SKILL.md 已包含 H1–H8", "details": []})

    for rel, name in (("SKILL.md", "audit_depth.py"), ("SKILL.md", "audit_doctor.py"),
                      ("README.md", "audit_depth.py")):
        if name not in docs[rel]:
            results.append({"level": "WARN", "check": "tool-docs",
                            "message": f"{rel} 未提到 {name}", "details": []})
    return results


def check_rule_parity() -> list[dict]:
    try:
        sys.path.insert(0, str(SCRIPTS))
        import scan_secrets  # type: ignore
    except Exception as exc:  # pragma: no cover - defensive
        return [{"level": "FAIL", "check": "rule-parity",
                 "message": f"无法导入 scan_secrets: {exc}", "details": []}]

    py_rules = {item[0] for item in scan_secrets.RULES}
    bash_text = _read("scripts/scan_secrets.sh")
    bash_rules = set(re.findall(r'^\s*"([a-z0-9-]+)=', bash_text, re.M))
    missing_in_bash = sorted(py_rules - bash_rules)
    missing_in_py = sorted(bash_rules - py_rules)
    if missing_in_bash or missing_in_py:
        return [{"level": "FAIL", "check": "rule-parity",
                 "message": "Python / bash 密钥规则名不一致",
                 "details": [f"bash 缺少: {', '.join(missing_in_bash) or '-'}",
                             f"Python 缺少: {', '.join(missing_in_py) or '-'}"]}]
    return [{"level": "PASS", "check": "rule-parity",
             "message": f"{len(py_rules)} 条规则名一致", "details": []}]


def run_checks() -> list[dict]:
    checks: list[dict] = []
    checks.extend(check_required_files())
    checks.extend(check_versions())
    checks.extend(check_depth_docs())
    checks.extend(check_rule_parity())
    return checks


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

    parser = argparse.ArgumentParser(description="检查技能自身的一致性")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)

    checks = run_checks()
    fails = sum(1 for item in checks if item["level"] == "FAIL")
    warns = sum(1 for item in checks if item["level"] == "WARN")

    if args.json:
        print(json.dumps({"tool": "audit_doctor", "version": VERSION,
                          "checks": checks,
                          "summary": {"fail": fails, "warn": warns,
                                      "pass": len(checks) - fails - warns}},
                         ensure_ascii=False, indent=2))
    else:
        print(f"== audit_doctor: {ROOT} ==")
        for item in checks:
            print(f"[{item['level']}] {item['message']}")
            for line in item["details"]:
                print(f"  - {line}")
        print(f"== 汇总: FAIL={fails} WARN={warns} ==")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
