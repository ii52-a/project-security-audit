#!/usr/bin/env python3
"""self_check.py — 跨平台发布前快速自检。

用法:
    python scripts/self_check.py [项目目录] [--strict] [--json] [--skip-deps]

检查:
  1. 密钥/凭据扫描（复用 scan_secrets.py）
  2. 依赖漏洞审计（npm / pip-audit / govulncheck / cargo / composer）
  3. git 卫生（敏感文件是否被跟踪、.gitignore、近 200 条历史）
  4. 调试开关（debug=true / debug: true，含 .env）
  5. 危险部署默认值（compose 弱密码、nginx autoindex）

默认只报告、退出码 0；--strict 时存在 FAIL 返回 1。
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

VERSION = "alpha1.1"

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


def check_secrets(report: Report, target: Path) -> None:
    check = "secrets-hits"
    try:
        result = scan_secrets(target)
    except Exception as exc:  # pragma: no cover
        report.add("FAIL", check, f"密钥扫描失败: {exc}")
        return

    hits = result["hits"]
    sensitive = result["sensitive_files"]
    if hits:
        details = [
            f"{h['file']}:{h['line']} [{h['rule']}] {h['snippet']}" for h in hits[:20]
        ]
        if len(hits) > 20:
            details.append(f"... 其余 {len(hits) - 20} 处省略")
        report.add("FAIL", check, f"密钥扫描命中 {len(hits)} 处候选（逐条人工确认后定级）", details)
    else:
        report.add("PASS", check, "密钥扫描无正则命中（仍需人工补查日志/前端产物/git 历史）")

    if sensitive:
        details = sensitive[:10]
        if len(sensitive) > 10:
            details.append(f"... 其余 {len(sensitive) - 10} 个省略")
        report.add("WARN", "secrets-files", f"发现 {len(sensitive)} 个疑似敏感文件（确认是否被忽略/是否含真值）", details)


def check_dependencies(report: Report, target: Path, timeout: int, skip: bool) -> None:
    check = "dependencies"
    if skip:
        report.add("WARN", check, "已通过 --skip-deps 跳过依赖审计")
        return

    if (target / "package-lock.json").exists() or (target / "npm-shrinkwrap.json").exists():
        npm = shutil.which("npm")
        if not npm:
            report.add("WARN", check, "有 package-lock.json 但本机无 npm，跳过")
            return
        code, output = run([npm, "audit", "--omit=dev"], target, timeout)
        tail = "\n".join(output.splitlines()[-8:])
        report.add("WARN", check, f"已运行 npm audit（退出码 {code}），需人工判断 high/critical", [tail])
        return

    if (target / "requirements.txt").exists():
        pip_audit = shutil.which("pip-audit")
        if not pip_audit:
            report.add("WARN", check, "有 requirements.txt 但未装 pip-audit（pip install pip-audit）")
            return
        code, output = run([pip_audit, "-r", "requirements.txt"], target, timeout)
        tail = "\n".join(output.splitlines()[-8:])
        report.add("WARN", check, f"已运行 pip-audit（退出码 {code}），按输出判定", [tail])
        return

    if (target / "go.mod").exists():
        govulncheck = shutil.which("govulncheck")
        if not govulncheck:
            report.add("WARN", check, "有 go.mod 但未装 govulncheck")
            return
        code, output = run([govulncheck, "./..."], target, timeout)
        tail = "\n".join(output.splitlines()[-8:])
        report.add("WARN", check, f"已运行 govulncheck（退出码 {code}），按输出判定", [tail])
        return

    if (target / "Cargo.toml").exists():
        cargo = shutil.which("cargo")
        if not cargo:
            report.add("WARN", check, "有 Cargo.toml 但未装 cargo")
            return
        code, output = run([cargo, "audit"], target, timeout)
        tail = "\n".join(output.splitlines()[-8:])
        report.add("WARN", check, f"已运行 cargo audit（退出码 {code}），按输出判定", [tail])
        return

    report.add("WARN", check, "未识别依赖清单（package-lock/requirements/go.mod/Cargo.toml），依赖审计跳过")


def check_git(report: Report, target: Path) -> None:
    git = shutil.which("git")
    if not git:
        report.add("WARN", "git-repo", "本机无 git，git 卫生检查跳过")
        return
    code, _ = run([git, "-C", str(target), "rev-parse", "--is-inside-work-tree"], target, 30)
    if code != 0:
        report.add("WARN", "git-repo", "非 git 仓库，git 卫生检查跳过")
        return

    code, tracked = run([git, "-C", str(target), "ls-files"], target, 60)
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

    code, history = run(
        [git, "-C", str(target), "log", "--oneline", "-200", "--diff-filter=A",
         "--", "*.env", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*"],
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
                hits.append(f"{rel}:{lineno}: {line.strip()[:160]}")
    if not hits:
        report.add("PASS", check, "未见 debug=true / debug: true")
        return
    details = hits[:10]
    if len(hits) > 10:
        details.append(f"... 其余 {len(hits) - 10} 处省略")
    if any(re.search(r"(^|/)(tests?|spec|__tests__|fixtures?)/", h) for h in hits):
        report.add("WARN", check, "发现 debug 开关（含测试/fixture 路径，逐条确认是否生产配置）", details)
    else:
        report.add("FAIL", check, "源码/配置中发现 debug 开关（若属生产配置即中招）", details)


def check_deployment(report: Report, target: Path) -> None:
    compose_files: list[Path] = []
    for pattern in ("docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml"):
        compose_files.extend(target.glob(pattern))
    compose_files = sorted({p for p in compose_files if p.is_file()})

    weak: list[str] = []
    for path in compose_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if WEAK_COMPOSE_RE.search(line):
                weak.append(f"{path.name}:{lineno}: {line.strip()[:160]}")
    if weak:
        report.add("FAIL", "deployment-compose", "docker-compose 使用常见弱默认密码", weak[:10])
    elif compose_files:
        report.add("PASS", "deployment-compose", "docker-compose 未见常见弱默认密码")
    else:
        report.add("PASS", "deployment-compose", "无 docker-compose 文件")

    nginx_files: list[Path] = []
    for path in target.rglob("*.conf"):
        if "nginx" in str(path).lower() and path.is_file():
            nginx_files.append(path)
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
    parser.add_argument("--strict", action="store_true", help="存在 FAIL 时返回退出码 1")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--skip-deps", action="store_true", help="跳过依赖审计（离线/测试用）")
    parser.add_argument("--timeout", type=int, default=120, help="单条外部命令超时秒数，默认 120")
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
