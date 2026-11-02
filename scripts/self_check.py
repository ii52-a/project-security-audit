#!/usr/bin/env python3
"""self_check.py — 跨平台发布前快速自检。

用法:
    python scripts/self_check.py [项目目录] [--strict] [--json] [--skip-deps] [--timeout 120]

检查:
  1. 密钥/凭据扫描（复用 scan_secrets.py；默认脱敏）
  2. 依赖漏洞审计（npm / pip-audit / govulncheck / cargo / composer；高危 FAIL）
  3. git 卫生（敏感文件是否被跟踪、.gitignore、近 200 条历史）
  4. 调试开关（debug=true / debug: true，含 .env；按路径区分生产/测试）
  5. 危险部署默认值（递归 compose 弱密码、nginx autoindex）

默认只报告、退出码 0；--strict 时 FAIL 返回 1，WARN 返回 2。
脚本只读，不修改项目文件。结果需人工确认。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    from scan_secrets import VERSION as SCAN_VERSION
    from scan_secrets import scan as scan_secrets
except ImportError:  # pragma: no cover - 允许从其他目录导入
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from scan_secrets import VERSION as SCAN_VERSION
    from scan_secrets import scan as scan_secrets

VERSION = "alpha1.5"

EXCLUDE_DIRS = {
    ".git", "node_modules", "dist", "build", "vendor", "__pycache__",
    ".next", "coverage", "target", "bin", "obj", "venv", ".venv",
    "wwwroot", ".idea", ".vscode", "Pods", "DerivedData",
}

CODE_SUFFIXES = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs",
    ".java", ".php", ".go", ".rb", ".cs", ".vue", ".svelte",
    ".yaml", ".yml", ".toml", ".ini", ".conf", ".properties", ".env",
}

DEBUG_RE = re.compile(
    r"(?:debug\s*[:=]\s*true|app\.run\s*\([^)]*debug\s*=\s*true|DEBUG\s*[:=]\s*true)",
    re.I,
)

TEST_PATH_RE = re.compile(r"(^|/)(tests?|spec|specs|__tests__|fixtures?)/", re.I)

WEAK_COMPOSE_RE = re.compile(
    r"(?:MYSQL|POSTGRES|MONGO|REDIS)_(?:ROOT_)?PASSWORD\s*:\s*[\"']?(?:root|123456|password|admin|postgres)[\"']?\s*$",
    re.I,
)

SENSITIVE_TRACKED_RE = re.compile(
    r"(?:^|/)\.env(?:\..*)?$|\.pem$|\.key$|\.p12$|\.pfx$|(?:^|/)id_rsa|(?:^|/)credentials",
    re.I,
)


class Report:
    def __init__(self, target: Path):
        self.target = target
        self.checks: list[dict] = []
        self.pass_count = 0
        self.warn_count = 0
        self.fail_count = 0

    def add(self, level: str, check: str, message: str, details: list[str] | None = None) -> None:
        if level == "PASS":
            self.pass_count += 1
        elif level == "WARN":
            self.warn_count += 1
        else:
            self.fail_count += 1
        self.checks.append(
            {"level": level, "check": check, "message": message, "details": details or []}
        )

    def as_dict(self) -> dict:
        return {
            "tool": "self_check",
            "version": VERSION,
            "scan_secrets_version": SCAN_VERSION,
            "target": str(self.target),
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "checks": self.checks,
            "summary": {
                "pass": self.pass_count,
                "warn": self.warn_count,
                "fail": self.fail_count,
            },
        }


def run(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
    if cmd and cmd[0].lower().endswith((".cmd", ".bat")):
        cmd = [os.environ.get("COMSPEC", "cmd.exe"), "/c", *cmd]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, output.strip()
    except FileNotFoundError:
        return 127, f"命令不可用: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"命令超时（>{timeout}s）: {' '.join(cmd)}"
    except OSError as exc:
        return 126, f"命令执行失败: {exc}"


def _tail(output: str, lines: int = 12) -> str:
    return "[RAW TOOL OUTPUT OMITTED: may contain credentials; inspect locally]"


def _json_from_output(output: str):
    """Extract the first JSON object/array from tool output that may have banners."""
    start_obj = output.find("{")
    start_arr = output.find("[")
    starts = [pos for pos in (start_obj, start_arr) if pos >= 0]
    if not starts:
        return None
    start = min(starts)
    decoder = json.JSONDecoder()
    try:
        data, _ = decoder.raw_decode(output[start:])
        return data
    except json.JSONDecodeError:
        return None


def check_secrets(report: Report, target: Path) -> None:
    check = "secrets-hits"
    try:
        result = scan_secrets(target)
    except Exception as exc:  # pragma: no cover
        report.add("FAIL", check, f"密钥扫描失败: {exc}")
        return

    hits = result["hits"]
    sensitive = result["sensitive_files"]
    if any(x['reason'] == 'read error' for x in result.get('skipped', [])):
        report.add('WARN', 'secrets-coverage', 'Unreadable files: secret scan incomplete')
    if hits:
        details = [
            f"{h['file']}:{h['line']} [{h['rule']}] {h['snippet']}" for h in hits[:20]
        ]
        if len(hits) > 20:
            details.append(f"... 其余 {len(hits) - 20} 处省略")
        report.add("FAIL", check, f"密钥扫描命中 {len(hits)} 处候选（逐条人工确认后定级；已脱敏）", details)
    else:
        report.add("PASS", check, "密钥扫描无正则命中（仍需人工补查日志/前端产物/git 历史）")

    if sensitive:
        details = sensitive[:10]
        if len(sensitive) > 10:
            details.append(f"... 其余 {len(sensitive) - 10} 个省略")
        report.add("WARN", "secrets-files", f"发现 {len(sensitive)} 个疑似敏感文件（确认是否被忽略/是否含真值）", details)


def _dep_npm(target: Path, timeout: int) -> tuple[str, str, list[str]]:
    npm = shutil.which("npm")
    if not npm:
        return "WARN", "有 package-lock.json 但本机无 npm，跳过（NOT EXECUTED）", []
    code, output = run([npm, "audit", "--json", "--omit=dev"], target, timeout)
    data = _json_from_output(output)
    if isinstance(data, dict) and not data.get("error") and ("advisories" in data or isinstance(data.get("metadata"), dict)):
        vulns = (data.get("metadata") or {}).get("vulnerabilities") or {}
        high = int(vulns.get("high", 0) or 0) + int(vulns.get("critical", 0) or 0)
        total = int(vulns.get("total", 0) or 0)
        if not vulns:
            advisories = data.get("advisories") or {}
            if isinstance(advisories, dict):
                items = [item for item in advisories.values() if isinstance(item, dict)]
                high = sum(1 for item in items if str(item.get("severity", "")).lower() in ("high", "critical"))
                total = len(items)
        if high:
            return "FAIL", f"npm audit 发现 {high} 个 high/critical 漏洞（退出码 {code}）", [_tail(output)]
        if total:
            return "WARN", f"npm audit 发现 {total} 个低/中危漏洞（退出码 {code}），需人工判断", [_tail(output)]
        if code == 0 and (vulns or "advisories" in data):
            return "PASS", "npm audit 未发现漏洞", []
    if code == 0:
        return "WARN", "npm audit 输出无法验证（PARSE ERROR）", []
    return "WARN", f"npm audit 退出码 {code}，无法解析 JSON，需人工判断", [_tail(output)]


def _dep_pip(target: Path, timeout: int) -> tuple[str, str, list[str]]:
    pip_audit = shutil.which("pip-audit")
    if not pip_audit:
        return "WARN", "有 requirements.txt 但未装 pip-audit（NOT EXECUTED）", []
    code, output = run([pip_audit, "-r", "requirements.txt", "--format", "json"], target, timeout)
    data = _json_from_output(output)
    vulnerable = 0
    if isinstance(data, dict):
        data = data.get("dependencies")
    if isinstance(data, list):
        vulnerable = sum(1 for item in data if isinstance(item, dict) and item.get("vulns"))
    if vulnerable:
        return "FAIL", f"pip-audit 发现 {vulnerable} 个存在已知漏洞的依赖", [_tail(output)]
    if code == 0 and isinstance(data, list) and all(isinstance(x, dict) and isinstance(x.get("vulns"), list) for x in data):
        return "PASS", "pip-audit 未发现已知漏洞", []
    return "WARN", f"pip-audit 退出码 {code}，需人工判断", [_tail(output)]


def _dep_govuln(target: Path, timeout: int) -> tuple[str, str, list[str]]:
    govulncheck = shutil.which("govulncheck")
    if not govulncheck:
        return "WARN", "有 go.mod 但未装 govulncheck（NOT EXECUTED）", []
    code, output = run([govulncheck, "-json", "./..."], target, timeout)
    findings = output.count('"finding"')
    if findings:
        return "FAIL", f"govulncheck 发现 {findings} 条可达漏洞", [_tail(output)]
    if code == 0 and isinstance(_json_from_output(output), dict) and "config" in _json_from_output(output):
        return "PASS", "govulncheck 未发现可达漏洞", []
    return "WARN", f"govulncheck 退出码 {code}，需人工判断", [_tail(output)]


def _dep_cargo(target: Path, timeout: int) -> tuple[str, str, list[str]]:
    cargo = shutil.which("cargo")
    if not cargo:
        return "WARN", "有 Cargo.toml 但未装 cargo/cargo-audit（NOT EXECUTED）", []
    code, output = run([cargo, "audit", "--json"], target, timeout)
    data = _json_from_output(output)
    found = 0
    if isinstance(data, dict):
        vulns = data.get("vulnerabilities") or {}
        if isinstance(vulns, dict):
            found = int(vulns.get("count", 0) or 0) if vulns.get("found") else 0
            if isinstance(vulns.get("list"), list):
                found = len(vulns["list"])
    if found:
        return "FAIL", f"cargo audit 发现 {found} 个漏洞", [_tail(output)]
    if code == 0 and isinstance(data, dict) and isinstance(data.get("vulnerabilities"), dict) and "list" in data["vulnerabilities"]:
        return "PASS", "cargo audit 未发现漏洞", []
    return "WARN", f"cargo audit 退出码 {code}，需人工判断", [_tail(output)]


def _dep_composer(target: Path, timeout: int) -> tuple[str, str, list[str]]:
    composer = shutil.which("composer")
    if not composer:
        return "WARN", "有 composer.json 但未装 composer（NOT EXECUTED）", []
    code, output = run([composer, "audit", "--format=json"], target, timeout)
    data = _json_from_output(output)
    found = 0
    if isinstance(data, dict):
        advisories = data.get("advisories") or {}
        if isinstance(advisories, dict):
            found = sum(len(items) for items in advisories.values() if isinstance(items, list))
    if found:
        return "FAIL", f"composer audit 发现 {found} 条安全通告", [_tail(output)]
    if code == 0 and isinstance(data, dict) and isinstance(data.get("advisories"), (dict, list)):
        return "PASS", "composer audit 未发现安全通告", []
    return "WARN", f"composer audit 退出码 {code}，需人工判断", [_tail(output)]


def _safe_dependency(check, target, timeout):
    try:
        return check(target, timeout)
    except (ValueError, TypeError, AttributeError, KeyError):
        return 'WARN', 'Dependency tool output malformed (PARSE ERROR)', []


def check_dependencies(report: Report, target: Path, timeout: int, skip: bool) -> None:
    if skip:
        report.add("WARN", "dependencies", "已通过 --skip-deps 跳过依赖审计")
        return

    detectors = []
    if (target / "package-lock.json").exists() or (target / "npm-shrinkwrap.json").exists():
        detectors.append(_safe_dependency(_dep_npm, target, timeout))
    if (target / "requirements.txt").exists():
        detectors.append(_safe_dependency(_dep_pip, target, timeout))
    if (target / "go.mod").exists():
        detectors.append(_safe_dependency(_dep_govuln, target, timeout))
    if (target / "Cargo.toml").exists():
        detectors.append(_safe_dependency(_dep_cargo, target, timeout))
    if (target / "composer.json").exists():
        detectors.append(_safe_dependency(_dep_composer, target, timeout))

    if not detectors:
        report.add("WARN", "dependencies",
                   "未识别依赖清单（package-lock/requirements/go.mod/Cargo.toml/composer.json），依赖审计跳过")
        return

    rank = {"PASS": 0, "WARN": 1, "FAIL": 2}
    worst = max((item[0] for item in detectors), key=lambda level: rank.get(level, 1))
    for index, (level, message, lines) in enumerate(detectors, 1):
        # Keep each tool result visible; aggregate WARN is never a clean check.
        report.add(level, 'dependency-tool-' + str(index), message, lines)
    message = "；".join(item[1] for item in detectors)
    details: list[str] = []
    for _level, _message, lines in detectors:
        details.extend(lines)
    report.add(worst, "dependencies", message, details[:20])


def check_git(report: Report, target: Path, history_limit: int = 200) -> None:
    git = shutil.which("git")
    if not git:
        report.add("WARN", "git-repo", "本机无 git，git 卫生检查跳过")
        return
    code, _ = run([git, "-C", str(target), "rev-parse", "--is-inside-work-tree"], target, 30)
    if code != 0:
        report.add("WARN", "git-repo", "非 git 仓库，git 卫生检查跳过")
        return

    code, tracked = run([git, "-C", str(target), "ls-files", "--", "."], target, 60)
    if code != 0:
        report.add("WARN", "git-tracked", "git ls-files 执行失败，git 卫生检查不完整")
        return
    bad = [line for line in tracked.splitlines() if SENSITIVE_TRACKED_RE.search(line)]
    if bad:
        report.add("FAIL", "git-tracked", f"敏感文件已被 git 跟踪: {', '.join(bad[:10])}")
    else:
        report.add("PASS", "git-tracked", "无敏感文件被 git 跟踪")

    gitignore = target / ".gitignore"
    if not gitignore.exists():
        report.add("WARN", "git-gitignore", "无 .gitignore")
    else:
        text = gitignore.read_text(encoding="utf-8", errors="replace")
        if re.search(r"^\.env|^/?\.env$|\.env\b", text, re.M):
            report.add("PASS", "git-gitignore", ".gitignore 覆盖 .env")
        else:
            report.add("WARN", "git-gitignore", ".gitignore 未显式忽略 .env")

    if history_limit == 0:
        return  # Controller runs its separately budgeted content-history check.
    code, history = run(
        [git, "-C", str(target), "log", "--oneline", '-' + str(history_limit), "--diff-filter=A",
         "--relative", "--", "*.env", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*"],
        target,
        60,
    )
    if code == 0 and history.strip():
        report.add("FAIL", "git-history", "git 历史近 200 条中添加过疑似敏感文件（视为已泄露，需轮换）")
    elif code == 0:
        report.add("PASS", "git-history", "git 历史近 200 条未见敏感文件新增记录")
    else:
        report.add("WARN", "git-history", "git 历史检查执行失败")


def iter_debug_files(target: Path):
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".git"))
        for name in sorted(files):
            path = Path(root) / name
            if path.is_symlink() or not path.is_file():
                continue
            if path.suffix.lower() not in CODE_SUFFIXES and not name.startswith(".env"):
                continue
            try:
                if path.stat().st_size > 2 * 1024 * 1024:
                    continue
            except OSError:
                continue
            yield path


def check_debug(report: Report, target: Path) -> None:
    check = "debug"
    hits: list[str] = []
    for path in iter_debug_files(target):
        try:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if DEBUG_RE.search(line):
                rel = path.relative_to(target).as_posix()
                hits.append(f"{rel}:{lineno}: [SOURCE OMITTED]")
    if not hits:
        report.add("PASS", check, "未见 debug=true / debug: true")
        return

    bad = [hit for hit in hits if not TEST_PATH_RE.search(hit)]
    details = (bad if bad else hits)[:10]
    if len(hits) > 10:
        details.append(f"... 其余 {len(hits) - 10} 处省略")
    if bad:
        report.add("FAIL", check, "源码/配置中发现 debug 开关（非测试路径；若属生产配置即中招）", details)
    else:
        report.add("WARN", check, "仅在测试/fixture 路径发现 debug 开关，逐条确认是否生产配置", details)


def _iter_compose_files(target: Path):
    seen: set[Path] = set()
    for root, dirs, files in os.walk(target):
        rel = Path(root).relative_to(target)
        if len(rel.parts) > 4:
            dirs[:] = []
            continue
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".git"))
        for name in sorted(files):
            if re.fullmatch(r"(?:docker-compose|compose)[^/]*\.ya?ml", name, re.I):
                path = Path(root) / name
                if path not in seen:
                    seen.add(path)
                    yield path


def check_deployment(report: Report, target: Path) -> None:
    compose_files = list(_iter_compose_files(target))

    weak: list[str] = []
    for path in compose_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if WEAK_COMPOSE_RE.search(line):
                weak.append(f"{path.relative_to(target).as_posix()}:{lineno}: [SOURCE OMITTED]")
    if weak:
        report.add("FAIL", "deployment-compose", "docker-compose 使用常见弱默认密码", weak[:10])
    elif compose_files:
        report.add("PASS", "deployment-compose", "docker-compose 未见常见弱默认密码")
    else:
        report.add("PASS", "deployment-compose", "无 docker-compose 文件")

    nginx_files: list[Path] = []
    for root, dirs, files in os.walk(target):
        rel = Path(root).relative_to(target)
        if len(rel.parts) > 4:
            dirs[:] = []
            continue
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".git"))
        for name in sorted(files):
            if not name.endswith(".conf"):
                continue
            path = Path(root) / name
            if "nginx" not in str(path).lower():
                continue
            nginx_files.append(path)
            if len(nginx_files) >= 20:
                break
        if len(nginx_files) >= 20:
            break

    autoindex: list[str] = []
    for path in nginx_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if re.search(r"autoindex\s+on", line, re.I):
                autoindex.append(f"{path.relative_to(target).as_posix()}:{lineno}")
    if autoindex:
        report.add("WARN", "deployment-nginx", "nginx 开启 autoindex（目录可列表）", autoindex[:10])
    else:
        report.add("PASS", "deployment-nginx", "nginx autoindex 未开启或无 nginx 配置")


def print_human(report: Report) -> None:
    print(f"== self_check: {report.target}  ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ==")
    for item in report.checks:
        print(f"[{item['level']}] {item['message']}")
        for line in item["details"]:
            print(line)
    print(f"== 汇总: PASS={report.pass_count} WARN={report.warn_count} FAIL={report.fail_count} ==")
    print("说明: FAIL=发版前必须处置; WARN=需人工判定; 密钥/竞态等深度问题请运行完整安全审核（十阶段）")


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = argparse.ArgumentParser(description="发布前快速安全自检")
    parser.add_argument("target", nargs="?", default=".", help="项目目录（默认当前目录）")
    parser.add_argument("--strict", action="store_true", help="FAIL 返回1，WARN/不完整返回2")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--skip-deps", action="store_true", help="跳过依赖审计（离线/测试用）")
    parser.add_argument("--timeout", type=int, default=120, help="单条外部命令超时秒数，默认 120")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)

    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        print(f"错误: {target} 不是目录", file=sys.stderr)
        return 2

    report = Report(target)
    check_secrets(report, target)
    check_dependencies(report, target, args.timeout, args.skip_deps)
    check_git(report, target)
    check_debug(report, target)
    check_deployment(report, target)

    if args.json:
        print(json.dumps(report.as_dict(), ensure_ascii=False, indent=2))
    else:
        print_human(report)

    if args.strict and report.fail_count > 0:
        return 1
    if args.strict and report.warn_count > 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
