#!/usr/bin/env python3
"""audit_depth.py — 体量探测与审核档位推荐（可直接调用）。

用法:
    python scripts/audit_depth.py <项目目录> [--json] [--mode quick|low|high]
    python scripts/audit_depth.py --checklist [--json]

公开 API:
    from audit_depth import measure_project, recommend_depth, HIGH_ONLY_ITEMS

说明:
    - 探测结果是启发式估算：第一方源文件数、非空源码行数、正则估算的接口数、
      由 compose 文件与顶层应用清单估算的服务数。
    - 用于入口处选择 quick / comprehensive-low / comprehensive-high，不构成安全结论。
    - 只读，不修改目标目录。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

VERSION = "alpha1.7"

# 工作量提示阈值；不直接决定审计深度。
LOW_MAX_FILES = 2_000
LOW_MAX_LOC = 200_000
LOW_MAX_INTERFACES = 300
LOW_MAX_SERVICES = 5

# quick 档的提示阈值：超过时提醒“仅覆盖 A 档”。
QUICK_ADVISORY_FILES = 300
QUICK_ADVISORY_LOC = 30_000

EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "jspm_packages",
    "vendor", "third_party", "third-party", "deps", "dist", "build", "target",
    "bin", "obj", "venv", ".venv", "__pycache__", ".next", "coverage",
    ".nyc_output", "Pods", "DerivedData", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".gradle", ".idea", ".vscode", "generated", "gen",
}

SOURCE_SUFFIXES = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".java", ".kt", ".kts", ".scala", ".go", ".rs", ".rb", ".php",
    ".cs", ".fs", ".vb", ".swift", ".m", ".mm", ".dart", ".lua",
    ".ex", ".exs", ".clj", ".cljs", ".vue", ".svelte", ".astro",
}

GENERATED_NAME_RE = re.compile(
    r"(?:\.min\.(?:js|css)$|\.bundle\.js$|\.generated\.|\.g\.dart$|\.pb\.go$|"
    r"_pb2\.py$|\.designer\.cs$|\.map$)",
    re.I,
)

ROUTE_PATTERNS = (
    re.compile(r"\b(?:app|router|server|api)\.(?:get|post|put|patch|delete|all)\s*\(", re.I),
    re.compile(r"@\s*(?:app|router|bp|blueprint|api)\.(?:get|post|put|patch|delete|route)\b", re.I),
    re.compile(r"@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b"),
    re.compile(r"\b(?:r|router|group|v1)\.(?:GET|POST|PUT|PATCH|DELETE|Any)\s*\("),
    re.compile(r"\b(?:get|post|put|patch|delete)\s*\(\s*['\"`][^'\"`]+['\"`]"),
    re.compile(r"@(?:Query|Mutation|Subscription)\b"),
    re.compile(r"\b(?:HandleFunc|Handle)\s*\(\s*['\"]"),
)

APP_MANIFESTS = (
    "package.json", "pyproject.toml", "go.mod", "Cargo.toml", "pom.xml",
    "build.gradle", "build.gradle.kts", "composer.json", "requirements.txt",
)

from audit_profiles import PROFILES
BUDGETS = {name: {"tool_calls": "plan-dependent; no filler calls",
    "time": str(p["time_target_minutes"]) + " min target",
    "dynamic_testing": p["dynamic"]} for name, p in PROFILES.items()}


HIGH_ONLY_ITEMS = (
    {
        "id": "H1",
        "check": "Full interface inventory + authorization matrix (who can call / "
                 "object-level check / output redaction / rate limit)",
        "required": False,
    },
    {
        "id": "H2",
        "check": "Cross-boundary trust: gateway->service identity, MQ, WebSocket, "
                 "GraphQL field authorization, cloud IAM",
        "required": False,
    },
    {
        "id": "H3",
        "check": "Race / idempotency / business-logic / LLM tool-abuse dynamic "
                 "validation (mock or dry-run only)",
        "required": False,
    },
    {
        "id": "H4",
        "check": "Dependency transitive graph + KEV / in-the-wild exploitation check",
        "required": False,
    },
    {
        "id": "H5",
        "check": "Second-pass review with the 12 prompt categories on all critical modules",
        "required": False,
    },
    {
        "id": "H6",
        "check": "Module-level coverage matrix + evidence index + independent "
                 "re-validation of P0/P1 when subagents are available",
        "required": True,
    },
    {
        "id": "H7",
        "check": "Cross-check deployment / CI / supply chain (compose, nginx, CI "
                 "permissions, third-party actions)",
        "required": False,
    },
    {
        "id": "H8",
        "check": "Report-level consistency: findings, scoring, and conclusion are traceable",
        "required": True,
    },
)

MODE_ALIASES = {
    "quick": "quick",
    "low": "comprehensive-low",
    "comprehensive-low": "comprehensive-low",
    "high": "comprehensive-high",
    "comprehensive-high": "comprehensive-high",
}


def _is_binary(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:8192]
    except OSError:
        return True
    return b"\x00" in chunk


def _iter_source_files(target: Path):
    """Yield first-party source files, skipping vendor/generated trees."""
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(
            d for d in dirs
            if d.lower() not in EXCLUDE_DIRS and not d.startswith(".")
        )
        for name in sorted(files):
            path = Path(root) / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                if path.suffix.lower() not in SOURCE_SUFFIXES:
                    continue
                if GENERATED_NAME_RE.search(name):
                    continue
                if path.stat().st_size > 5 * 1024 * 1024:
                    continue
            except OSError:
                continue
            yield path


def _count_interfaces(text: str) -> int:
    hits: set[int] = set()
    for lineno, line in enumerate(text.splitlines(), 1):
        if any(pattern.search(line) for pattern in ROUTE_PATTERNS):
            hits.add(lineno)
    return len(hits)


def _count_compose_services(path: Path) -> int:
    """Count keys directly under a top-level ``services:`` block (YAML heuristic)."""
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return 0
    in_services = False
    count = 0
    for line in text.splitlines():
        if re.match(r"^services:\s*$", line):
            in_services = True
            continue
        if not in_services:
            continue
        if line and not line[0].isspace():
            in_services = False
            continue
        if re.match(r"^  [A-Za-z0-9_.-]+:\s*$", line):
            count += 1
    return count


def _iter_compose_files(target: Path):
    for root, dirs, files in os.walk(target):
        rel = Path(root).relative_to(target)
        if len(rel.parts) > 3:
            dirs[:] = []
            continue
        dirs[:] = sorted(
            d for d in dirs
            if d.lower() not in EXCLUDE_DIRS and not d.startswith(".")
        )
        for name in sorted(files):
            if re.fullmatch(r"(?:docker-compose|compose)[^/]*\.ya?ml", name, re.I):
                yield Path(root) / name


def _count_app_units(target: Path) -> int:
    root_has_manifest = any((target / name).is_file() for name in APP_MANIFESTS)
    count = 1 if root_has_manifest else 0
    try:
        children = sorted(target.iterdir())
    except OSError:
        return count
    for child in children:
        try:
            if not child.is_dir() or child.is_symlink():
                continue
        except OSError:
            continue
        if child.name.lower() in EXCLUDE_DIRS or child.name.startswith("."):
            continue
        if any((child / name).is_file() for name in APP_MANIFESTS):
            count += 1
    return count


def measure_project(target: str | Path) -> dict:
    """Measure a project directory and return a JSON-serializable metrics dict."""
    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(str(root))

    source_files = 0
    source_loc = 0
    interfaces = 0
    unreadable: list[str] = []

    for path in _iter_source_files(root):
        source_files += 1
        if _is_binary(path):
            continue
        try:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            unreadable.append(path.relative_to(root).as_posix())
            continue
        source_loc += sum(1 for line in text.splitlines() if line.strip())
        interfaces += _count_interfaces(text)

    compose_files = list(_iter_compose_files(root))
    compose_services = sum(_count_compose_services(path) for path in compose_files)
    app_units = _count_app_units(root)
    services = max(compose_services, app_units)
    if source_files and services == 0:
        services = 1

    notes = [
        "LOC counts non-empty lines in first-party source files.",
        "Interface count is a regex-based estimate; framework-specific routing can be missed.",
        "Service count is estimated from compose files and top-level app manifests.",
    ]
    if unreadable:
        notes.append(f"{len(unreadable)} source file(s) could not be read; see unreadable_files.")

    return {
        "target": str(root),
        "source_files": source_files,
        "source_loc": source_loc,
        "interfaces_estimate": interfaces,
        "services_estimate": services,
        "compose_files": [path.relative_to(root).as_posix() for path in compose_files],
        "compose_services": compose_services,
        "app_units": app_units,
        "unreadable_files": unreadable,
        "notes": notes,
    }


def _normalize_mode(mode: str | None) -> str | None:
    if mode is None:
        return None
    key = mode.strip().lower()
    if key not in MODE_ALIASES:
        raise ValueError(f"unknown mode: {mode!r} (expected quick/low/high)")
    return MODE_ALIASES[key]


RISK_FACTORS = ("authentication", "payment", "multi-tenant", "sensitive-data", "cross-service", "llm-tools")

def recommend_depth(metrics: dict, requested=None, risks=None) -> dict:
    req = _normalize_mode(requested)
    risks = sorted(set(risks or metrics.get("risk_factors", [])))
    if set(risks) - set(RISK_FACTORS):
        raise ValueError("unknown risk factor")
    workload = any(metrics[k] > limit for k, limit in (
        ("source_files", LOW_MAX_FILES), ("source_loc", LOW_MAX_LOC),
        ("interfaces_estimate", LOW_MAX_INTERFACES), ("services_estimate", LOW_MAX_SERVICES)))
    high = bool(set(risks) & {"payment", "multi-tenant", "cross-service", "llm-tools"}) or len(risks) >= 2
    recommended = "comprehensive-high" if high else "comprehensive-low"
    effective = req or recommended
    reasons = ["declared risk: " + r for r in risks]
    if workload:
        reasons.append("large workload: allocate budget and record sampling; size alone does not force high")
    warning = "Record limited coverage and unresolved risks" if (workload or effective == "quick" or (high and effective != recommended)) else None
    return dict(requested=req, recommended=recommended, effective=effective,
                downgrade_candidate=False, warning=warning, reasons=reasons,
                risk_factors=risks, workload_large=workload, budget=BUDGETS[effective])


def render_high_only_checklist() -> str:
    lines = [
        "| ID | High-only check | Status |",
        "|---|---|---|",
    ]
    for item in HIGH_ONLY_ITEMS:
        required = " (required)" if item["required"] else ""
        lines.append(f"| {item['id']} | {item['check']}{required} | [ ] |")
    return "\n".join(lines)


def evaluate_high_only(statuses: dict) -> dict:
    """Every H item needs evidence or a reasoned N/A; H6/H8 always apply."""
    from audit_contracts import high_errors
    issues = high_errors(statuses)
    completed = [key for key, record in statuses.items() if isinstance(record,dict) and record.get('status')=='done' and not any(i.startswith(key+':') for i in issues)] if isinstance(statuses,dict) else []
    return dict(achieved=not issues, completed=completed, count=len(completed), issues=issues)


def _print_human(metrics: dict, decision: dict) -> None:
    print(f"== audit_depth: {metrics['target']} ==")
    print(
        f"source files: {metrics['source_files']}   "
        f"source LOC: {metrics['source_loc']}   "
        f"interfaces (est.): {metrics['interfaces_estimate']}   "
        f"services (est.): {metrics['services_estimate']}"
    )
    print(f"recommended: {decision['recommended']}")
    if decision["requested"]:
        print(f"requested: {decision['requested']}")
    print(f"effective: {decision['effective']}")
    budget = decision["budget"]
    print(
        f"budget: {budget['tool_calls']} tool calls / {budget['time']} / "
        f"dynamic: {budget['dynamic_testing']}"
    )
    if decision["downgrade_candidate"]:
        print("downgrade candidate: yes (agent decision after H1-H3 check)")
    for reason in decision["reasons"]:
        print(f"- {reason}")
    if decision["warning"]:
        print(f"warning: {decision['warning']}")
    print("notes:")
    for note in metrics["notes"]:
        print(f"- {note}")


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = argparse.ArgumentParser(
        description="体量探测并推荐 quick / comprehensive-low / comprehensive-high"
    )
    parser.add_argument("target", nargs="?", default=".", help="项目目录（默认当前目录）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument(
        "--mode",
        choices=sorted(MODE_ALIASES),
        help="调用方明确选择的档位；保持选择并记录覆盖限制",
    )
    parser.add_argument(
        "--checklist",
        action="store_true",
        help="输出 high-only 复核清单（可直接贴进报告）",
    )
    parser.add_argument(
        "--high-status",
        metavar="FILE",
        help="读取 H1-H8 状态 JSON（done/n/a/skipped），校验是否真正达到 high",
    )
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--risk", action="append", choices=RISK_FACTORS, default=[])
    args = parser.parse_args(argv)

    if args.high_status:
        try:
            statuses = json.loads(Path(args.high_status).read_text(encoding="utf-8-sig"))
            if not isinstance(statuses, dict):
                raise ValueError("expected a JSON object mapping H1..H8 to status")
            result = evaluate_high_only(statuses)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"错误: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps({"tool": "audit_depth", "version": VERSION,
                              "high_only": result}, ensure_ascii=False, indent=2))
        else:
            print(f"high achieved: {'yes' if result['achieved'] else 'no'}")
            print(f"completed: {result['count']} ({', '.join(result['completed']) or '-'})")
            for issue in result["issues"]:
                print(f"- {issue}")
        return 0 if result["achieved"] else 1

    if args.checklist:
        if args.json:
            print(json.dumps({"tool": "audit_depth", "version": VERSION,
                              "high_only": list(HIGH_ONLY_ITEMS)},
                             ensure_ascii=False, indent=2))
        else:
            print(render_high_only_checklist())
        return 0

    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        print(f"错误: {target} 不是目录", file=sys.stderr)
        return 2

    try:
        metrics = measure_project(target)
        decision = recommend_depth(metrics, args.mode, args.risk)
    except (OSError, ValueError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(
            {"tool": "audit_depth", "version": VERSION,
             "metrics": metrics, "recommendation": decision},
            ensure_ascii=False, indent=2,
        ))
    else:
        _print_human(metrics, decision)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
