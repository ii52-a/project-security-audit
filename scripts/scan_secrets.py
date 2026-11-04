#!/usr/bin/env python3
"""scan_secrets.py — 跨平台扫描疑似硬编码密钥/凭据。

用法:
    python scripts/scan_secrets.py <目标目录> [--json] [--reveal]
        [--max-size-mb 2] [--exclude GLOB]... [--baseline FILE] [--fail-on-hit]

输出默认完整脱敏，避免密钥进入终端/CI 日志；
--reveal 才输出原文，且不应在 CI 中使用。结果仅供人工确认，存在误报与漏报。
脚本只读，不修改目标文件。
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import sys
from pathlib import Path

VERSION = "alpha1.7"

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
    ("password-literal", re.compile(r"(?<!-)(?:password|passwd|pwd)[\"'\s]*[:=][\"'\s]*[\"'][^\"']{4,}[\"']", re.I), "字面量密码"),
    ("pypirc-password", re.compile(r"^\s*password\s*=\s*\S{4,}", re.I), "pypirc 明文密码"),
    ("dotenv-secret", re.compile(r"^\s*(?:export\s+)?[A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|CREDENTIAL)[A-Za-z0-9_]*\s*=\s*[^\s#]{8,}", re.I), ".env 敏感键值"),
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

# 只对特定文件名生效的规则（fnmatch）。
RULE_SCOPE = {
    "pypirc-password": ".pypirc",
    "dotenv-secret": ".env*",
}

SENSITIVE_NAME_RE = re.compile(
    r"(?:^\.env(?:\..*)?$|\.pem$|\.key$|\.p12$|\.pfx$|^id_rsa.*$|^credentials.*$|\.sql$|\.bak$|\.dump$|^\.npmrc$|^\.pypirc$)",
    re.I,
)

PLACEHOLDER_RE = re.compile(
    r"(?:example|sample|dummy|placeholder|changeme|change[_-]?me|redacted|"
    r"not[_-]?real|fake|xxxx|<[^>]+>|your[_-])",
    re.I,
)


def redact_secret(value: str) -> str:
    """Keep at most four leading and four trailing characters."""
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:4]}****{value[-4:]}"


def redact_match_text(raw: str) -> str:
    """Redact the value after an assignment separator while keeping the key name."""
    if "://" in raw:
        return redact_secret(raw)
    match = re.match(r"^([^:=]{1,80}[:=])(\s*)(.+)$", raw, re.S)
    if match:
        return f"{match.group(1)}{match.group(2)}{redact_secret(match.group(3))}"
    return redact_secret(raw)


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def is_placeholder(value: str) -> bool:
    # Match an entire assigned value, never a substring in a plausible real secret.
    assigned = re.split(r'[:=]', value, maxsplit=1)[-1].strip().strip('\"\'')
    return bool(PLACEHOLDER_RE.fullmatch(assigned))


def iter_files(target: Path, max_bytes: int, excludes: list[str] | None = None, skipped=None):
    """遍历目标目录，跳过排除目录、二进制扩展名和超大文件。"""
    excludes = excludes or []
    skipped = skipped if skipped is not None else []
    for root, dirs, files in os.walk(target):
        for d in dirs:
            if d in EXCLUDE_DIRS or d == ".git" or (Path(root) / d).is_symlink():
                skipped.append({"path": (Path(root) / d).relative_to(target).as_posix(), "reason": "excluded directory or symlink"})
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDE_DIRS and d != ".git" and not (Path(root) / d).is_symlink())
        for name in sorted(files):
            path = Path(root) / name
            rel = path.relative_to(target).as_posix()
            if any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern)
                   for pattern in excludes):
                skipped.append({"path": rel, "reason": "excluded, unsupported, oversized or unreadable"})
                continue
            try:
                if path.is_symlink() or not path.is_file():
                    skipped.append({"path": rel, "reason": "excluded, unsupported, oversized or unreadable"})
                    continue
                if path.suffix.lower() in BINARY_EXTS:
                    skipped.append({"path": rel, "reason": "excluded, unsupported, oversized or unreadable"})
                    continue
                if path.stat().st_size > max_bytes:
                    skipped.append({"path": rel, "reason": "excluded, unsupported, oversized or unreadable"})
                    continue
            except OSError:
                skipped.append({"path": rel, "reason": "excluded, unsupported, oversized or unreadable"})
                continue
            yield path


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith((b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff')):
        return raw.decode('utf-32')
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        return raw.decode('utf-16')
    if b'\x00' in raw[:8192]:
        raise UnicodeError('binary content')
    return raw.decode('utf-8-sig')


def scan_file(path: Path, target: Path, reveal: bool = False, content=None) -> list[dict]:
    hits: list[dict] = []
    text = read_text(path) if content is None else content
    rel = path.relative_to(target).as_posix()
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        for rule, regex, _desc in RULES:
            scope = RULE_SCOPE.get(rule)
            if scope and not fnmatch.fnmatch(path.name, scope):
                continue
            for match in regex.finditer(line):
                raw = match.group(0)
                if is_placeholder(raw):
                    continue
                hits.append({
                    "file": rel, "line": lineno, "column": match.start() + 1,
                    "rule": rule, "snippet": raw if reveal else "[REDACTED]",
                    "fingerprint": fingerprint(raw), "redacted": not reveal,
                })
    return hits


def find_sensitive_files(target: Path) -> list[str]:
    found: list[str] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDE_DIRS and d != ".git")
        for name in sorted(files):
            path = Path(root) / name
            is_docker_config = name == "config.json" and ".docker" in Path(root).parts
            if not SENSITIVE_NAME_RE.search(name) and not is_docker_config:
                continue
            try:
                if path.is_symlink() or not path.is_file():
                    continue
            except OSError:
                continue
            found.append(path.relative_to(target).as_posix())
    return found


def _baseline_entries(baseline) -> list[dict]:
    if isinstance(baseline, dict):
        entries = baseline.get("hits", [])
    elif isinstance(baseline, list):
        entries = baseline
    else:
        entries = []
    return [item for item in entries if isinstance(item, dict)]


def apply_baseline(hits: list[dict], baseline) -> tuple[list[dict], int]:
    entries = _baseline_entries(baseline)
    if not entries:
        return hits, 0

    kept: list[dict] = []
    suppressed = 0
    for hit in hits:
        matched = False
        for item in entries:
            if item.get("rule") != hit["rule"] or item.get("file") != hit["file"]:
                continue
            expected = item.get("fingerprint")
            if expected and expected == hit["fingerprint"]:
                matched = True
                break
        if matched:
            suppressed += 1
        else:
            kept.append(hit)
    return kept, suppressed


def scan(target: Path, max_size_mb: float = 2.0, excludes: list[str] | None = None,
         reveal: bool = False, baseline=None) -> dict:
    max_bytes = int(max_size_mb * 1024 * 1024)
    hits: list[dict] = []
    files_scanned = 0
    skipped = []
    for path in iter_files(target, max_bytes, excludes, skipped):
        try:
            content = read_text(path)
        except UnicodeError:
            skipped.append({'path': path.relative_to(target).as_posix(), 'reason': 'binary or unsupported text encoding'})
            continue
        except OSError:
            skipped.append({'path': path.relative_to(target).as_posix(), 'reason': 'read error'})
            continue
        files_scanned += 1
        hits.extend(scan_file(path, target, reveal=reveal, content=content))
    hits, suppressed = apply_baseline(hits, baseline)
    return {
        "tool": "scan_secrets",
        "version": VERSION,
        "target": str(target),
        "max_size_mb": max_size_mb,
        "reveal": reveal,
        "hits": hits,
        "baseline_suppressed": suppressed,
        "skipped": skipped,
        "coverage": "partial" if skipped or not files_scanned else "complete",
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
    if result.get("baseline_suppressed"):
        print(f"== baseline 抑制 {result['baseline_suppressed']} 处 ==")
    if not result.get("reveal"):
        print("(命中值默认脱敏；确需原文时使用 --reveal，且不要用于 CI 日志)")
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
    parser = argparse.ArgumentParser(description="扫描疑似硬编码密钥/凭据（默认脱敏）")
    parser.add_argument("target", nargs="?", default=".", help="目标目录（默认当前目录）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--reveal", action="store_true", help="输出命中原文（敏感；不要用于 CI）")
    parser.add_argument("--max-size-mb", type=float, default=2.0, help="单文件大小上限，默认 2MB")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="排除相对路径或文件名（可重复）")
    parser.add_argument("--baseline", metavar="FILE", help="baseline JSON，抑制已知误报")
    parser.add_argument("--fail-on-hit", action="store_true", help="命中时退出码 1，适合 CI")
    args = parser.parse_args(argv)

    if args.max_size_mb <= 0:
        print("错误: --max-size-mb 必须大于 0", file=sys.stderr)
        return 2

    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        print(f"错误: {target} 不是目录", file=sys.stderr)
        return 1

    baseline = None
    if args.baseline:
        try:
            baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"错误: 无法读取 baseline: {exc}", file=sys.stderr)
            return 2

    if args.reveal:
        print("警告: --reveal 会输出密钥原文，请勿在 CI 或共享终端使用", file=sys.stderr)

    try:
        result = scan(target, args.max_size_mb, args.exclude, args.reveal, baseline)
    except Exception as exc:  # pragma: no cover - 防御性兜底
        print(f"错误: 扫描失败: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_human(result)
    if args.fail_on_hit and result["hits"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
