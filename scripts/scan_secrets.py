#!/usr/bin/env python3
"""scan_secrets.py — 跨平台扫描疑似硬编码密钥/凭据。

用法:
    python scripts/scan_secrets.py <目标目录> [--json] [--max-size-mb 2]

输出与 scan_secrets.sh 保持兼容（"文件:行号: 片段 | [规则名]"），
另外支持 --json 供 self_check.py / CI 使用。

结果仅供人工确认，存在误报与漏报。脚本只读，不修改目标文件。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

VERSION = "alpha1.1"

EXCLUDE_DIRS = {
    ".git", "node_modules", "dist", "build", "vendor", "__pycache__",
    ".next", "coverage", "target", "bin", "obj", "venv", ".venv",
    "wwwroot", ".idea", ".vscode", "Pods", "DerivedData", ".mypy_cache",
    ".pytest_cache", ".ruff_cache",
}

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mov", ".avi", ".mkv", ".mp3", ".wav",
    ".zip", ".gz", ".tgz", ".tar", ".rar", ".7z",
    ".jar", ".war", ".pdf", ".map", ".lock",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".pyc", ".pyo",
    ".psd", ".ai", ".sketch",
}

# (规则名, 正则, 说明)
RULES: list[tuple[str, re.Pattern[str], str]] = [
    ("aws-aksk", re.compile(r"AKIA[0-9A-Z]{16}", re.I), "AWS Access Key"),
    ("aliyun-aksk", re.compile(r"LTAI[0-9A-Za-z]{12,24}", re.I), "阿里云 AccessKey"),
    ("volc-aksk", re.compile(r"AKLT[0-9A-Za-z]{16,40}", re.I), "火山引擎 AccessKey"),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I), "私钥文件内容"),
    ("db-url", re.compile(r"(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\"'\s]*:[^\"'\s]*@", re.I), "带密码的数据库连接串"),
    ("jwt-secret", re.compile(r"(?:jwt[_-]?(?:secret|key)|token[_-]?secret|signing[_-]?key)[\"'\s]*[:=][\"'\s]*[A-Za-z0-9+/=_-]{8,}", re.I), "JWT/签名 secret"),
    ("generic-secret", re.compile(r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|client[_-]?secret|app[_-]?secret)[\"'\s]*[:=][\"'\s]*[\"']?[A-Za-z0-9+/=_-]{16,}", re.I), "通用 API key/secret"),
    ("sk-live", re.compile(r"sk_(?:live|test)_[0-9A-Za-z]{16,}", re.I), "Stripe live/test key"),
    ("bearer-basic", re.compile(r"Authorization[\"'\s:=]+[\"']?Basic [A-Za-z0-9+/=]{16,}", re.I), "Basic Authorization"),
    ("password-literal", re.compile(r"(?:password|passwd|pwd)[\"'\s]*[:=][\"'\s]*[\"'][^\"']{4,}[\"']", re.I), "字面量密码"),
    ("pypirc-password", re.compile(r"^\s*password\s*=\s*\S{4,}", re.I), "pypirc 明文密码"),
    ("docker-auth", re.compile(r"\"auth\"\s*:\s*\"[A-Za-z0-9+/=]{20,}\"", re.I), "Docker config auth"),
    ("slack-giphy", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}", re.I), "Slack token"),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", re.I), "Slack Webhook"),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}", re.I), "Google API key"),
    ("github-token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}", re.I), "GitHub token"),
    ("tencent-aksk", re.compile(r"AKID[A-Za-z0-9]{32,}", re.I), "腾讯云 SecretId"),
    ("gitlab-pat", re.compile(r"glpat-[0-9A-Za-z_-]{20,}", re.I), "GitLab PAT"),
    ("npm-token", re.compile(r"npm_[A-Za-z0-9]{30,}", re.I), "npm token"),
    ("sendgrid-key", re.compile(r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}", re.I), "SendGrid key"),
    ("telegram-bot", re.compile(r"[0-9]{8,10}:AA[A-Za-z0-9_-]{33}", re.I), "Telegram bot token"),
    ("llm-apikey", re.compile(r"sk-(?:proj-|ant-)?[A-Za-z0-9_=-]{24,}", re.I), "LLM API key"),
    ("azure-conn", re.compile(r"AccountKey=[A-Za-z0-9+/=]{40,}", re.I), "Azure Storage AccountKey"),
    ("wechat-mchkey", re.compile(r"(?:mch[_-]?key|partner[_-]?key)[\"'\s]*[:=][\"'\s]*[0-9A-Za-z]{32}", re.I), "微信支付商户密钥"),
    ("insecure-tls", re.compile(r"(?:rejectUnauthorized[\"'\s]*[:=][\"'\s]*false|verify[\"'\s]*=[\"'\s]*False|InsecureSkipVerify[\"'\s]*:[\"'\s]*true)", re.I), "关闭 TLS 证书校验"),
]

SENSITIVE_NAME_RE = re.compile(
    r"(?:^\.env(?:\..*)?$|\.pem$|\.key$|\.p12$|\.pfx$|^id_rsa.*$|^credentials.*$|\.sql$|\.bak$|\.dump$|^\.npmrc$|^\.pypirc$)",
    re.I,
)


def iter_files(target: Path, max_bytes: int):
    """遍历目标目录，跳过排除目录、二进制扩展名和超大文件。"""
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".git"))
        for name in sorted(files):
            path = Path(root) / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                if path.suffix.lower() in BINARY_EXTS:
                    continue
                if path.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            yield path


def is_binary(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:8192]
    except OSError:
        return True
    return b"\x00" in chunk


def scan_file(path: Path, target: Path) -> list[dict]:
    hits: list[dict] = []
    if is_binary(path):
        return hits
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return hits
    rel = path.relative_to(target).as_posix()
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        for rule, regex, _desc in RULES:
            if regex.search(line):
                snippet = line.strip()[:160]
                hits.append({"file": rel, "line": lineno, "rule": rule, "snippet": snippet})
    return hits


def find_sensitive_files(target: Path) -> list[str]:
    found: list[str] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".git"))
        for name in sorted(files):
            if SENSITIVE_NAME_RE.search(name):
                found.append((Path(root) / name).relative_to(target).as_posix())
    return found


def scan(target: Path, max_size_mb: float = 2.0) -> dict:
    max_bytes = int(max_size_mb * 1024 * 1024)
    hits: list[dict] = []
    files_scanned = 0
    for path in iter_files(target, max_bytes):
        files_scanned += 1
        hits.extend(scan_file(path, target))
    return {
        "tool": "scan_secrets",
        "version": VERSION,
        "target": str(target),
        "max_size_mb": max_size_mb,
        "hits": hits,
        "sensitive_files": find_sensitive_files(target),
        "stats": {"files_scanned": files_scanned, "hit_count": len(hits)},
    }


def print_human(result: dict) -> None:
    print(f"== scan_secrets: {result['target']} ==")
    for hit in result["hits"]:
        print(f"{hit['file']}:{hit['line']}: {hit['snippet']} | [{hit['rule']}]")
    print("== 疑似敏感文件 ==")
    for name in result["sensitive_files"]:
        print(name)
    if not result["hits"]:
        print("(正则未命中候选点——仍需按 references/secrets-hijack.md 人工补查日志、前端产物与 git 历史)")
    print(f"== 汇总: 规则命中 {len(result['hits'])} 处 / 扫描 {result['stats']['files_scanned']} 个文件 ==")


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = argparse.ArgumentParser(description="扫描疑似硬编码密钥/凭据")
    parser.add_argument("target", nargs="?", default=".", help="目标目录（默认当前目录）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--max-size-mb", type=float, default=2.0, help="单文件大小上限，默认 2MB")
    args = parser.parse_args(argv)

    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        print(f"错误: {target} 不是目录", file=sys.stderr)
        return 1

    try:
        result = scan(target, args.max_size_mb)
    except Exception as exc:  # pragma: no cover - 防御性兜底
        print(f"错误: 扫描失败: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_human(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
