#!/usr/bin/env bash
# self_check.sh — 项目自审查快速自检（发布前 ≤15 分钟档）
# 用法: bash self_check.sh [项目目录] [--strict]
#   --strict  存在 FAIL 时返回 1（可用于 CI）
# 检查: 密钥硬编码 + 依赖漏洞审计 + git 卫生 + 调试开关 + 危险默认配置
# 输出: 逐项 PASS/WARN/FAIL 汇总。脚本只报告不修改项目文件。结果需人工确认，存在误报漏报。
# 说明: 推荐优先使用跨平台的 self_check.py；本脚本适用于 Linux/macOS/Git Bash。

set -u

TARGET="."
STRICT=0
for arg in "$@"; do
  case "$arg" in
    --strict) STRICT=1 ;;
    -h|--help)
      sed -n '2,9p' "$0"
      exit 0
      ;;
    *) TARGET="$arg" ;;
  esac
done
[ "$TARGET" = "/" ] || TARGET="${TARGET%/}"
[ -d "$TARGET" ] || { echo "错误: $TARGET 不是目录" >&2; exit 1; }
SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0; WARN=0; FAIL=0
say() { # say <级别> <消息>
  case "$1" in
    PASS) PASS=$((PASS+1)); printf '[PASS] %s\n' "$2" ;;
    WARN) WARN=$((WARN+1)); printf '[WARN] %s\n' "$2" ;;
    FAIL) FAIL=$((FAIL+1)); printf '[FAIL] %s\n' "$2" ;;
  esac
}
echo "== self_check: $TARGET  ($(date '+%F %T')) =="

# ── 1. 密钥与硬编码扫描（复用 scan_secrets.sh；默认脱敏）──────────
echo "-- [1/5] 密钥扫描 --"
secret_out=$(bash "$SKILL_DIR/scripts/scan_secrets.sh" "$TARGET" 2>&1)
secret_status=$?
if [ "$secret_status" -ne 0 ]; then
  say FAIL "密钥扫描执行失败（退出码 $secret_status；检查 bash/scan_secrets.sh）"
  printf '%s\n' "$secret_out" | tail -5
else
  secret_hits=$(printf '%s\n' "$secret_out" | grep -c '| \[' || true)
  if [ "$secret_hits" -gt 0 ]; then
    say FAIL "密钥扫描命中 $secret_hits 处候选（逐条人工确认后定级；已脱敏）"
    printf '%s\n' "$secret_out" | grep '| \[' | head -20
  else
    say PASS "密钥扫描无正则命中（仍需人工补查日志/前端产物）"
  fi
  sensitive=$(printf '%s\n' "$secret_out" | awk '
    /^== 疑似敏感文件 ==$/ { in_section=1; next }
    /^== 汇总:/ { in_section=0 }
    in_section && NF { print }
  ' | head -10)
  if [ -n "$sensitive" ]; then
    say WARN "发现疑似敏感文件（确认是否被忽略/是否含真值）:"
    printf '%s\n' "$sensitive"
  fi
fi

# ── 2. 依赖漏洞审计 ────────────────────────────────────────────
echo "-- [2/5] 依赖审计 --"
dep_done=0
if [ -f "$TARGET/package-lock.json" ] || [ -f "$TARGET/npm-shrinkwrap.json" ]; then
  dep_done=1
  if command -v npm >/dev/null 2>&1; then
    dep_out=$(cd "$TARGET" && npm audit --omit=dev --audit-level=high 2>&1); dep_rc=$?
    printf '%s\n' "$dep_out" | tail -5
    if [ "$dep_rc" -eq 0 ]; then
      say PASS "npm audit 未发现 high/critical"
    else
      say FAIL "npm audit 发现 high/critical 或执行失败（退出码 $dep_rc）"
    fi
  else
    say WARN "有 package-lock.json 但本机无 npm，跳过（NOT EXECUTED）"
  fi
fi
if [ -f "$TARGET/requirements.txt" ]; then
  dep_done=1
  if command -v pip-audit >/dev/null 2>&1; then
    dep_out=$(pip-audit -r "$TARGET/requirements.txt" 2>&1); dep_rc=$?
    printf '%s\n' "$dep_out" | tail -5
    if [ "$dep_rc" -eq 0 ]; then
      say PASS "pip-audit 未发现已知漏洞"
    elif [ "$dep_rc" -eq 1 ]; then
      say FAIL "pip-audit 发现存在已知漏洞的依赖"
    else
      say WARN "pip-audit 退出码 $dep_rc，需人工判断"
    fi
  else
    say WARN "有 requirements.txt 但未装 pip-audit（NOT EXECUTED）"
  fi
fi
if [ -f "$TARGET/go.mod" ]; then
  dep_done=1
  if command -v govulncheck >/dev/null 2>&1; then
    dep_out=$(cd "$TARGET" && govulncheck ./... 2>&1); dep_rc=$?
    printf '%s\n' "$dep_out" | tail -5
    if printf '%s\n' "$dep_out" | grep -q "Vulnerability"; then
      say FAIL "govulncheck 发现可达漏洞"
    elif [ "$dep_rc" -eq 0 ]; then
      say PASS "govulncheck 未发现可达漏洞"
    else
      say WARN "govulncheck 退出码 $dep_rc，需人工判断"
    fi
  else
    say WARN "有 go.mod 但未装 govulncheck（NOT EXECUTED）"
  fi
fi
if [ -f "$TARGET/Cargo.toml" ]; then
  dep_done=1
  if command -v cargo >/dev/null 2>&1; then
    dep_out=$(cd "$TARGET" && cargo audit 2>&1); dep_rc=$?
    printf '%s\n' "$dep_out" | tail -5
    if printf '%s\n' "$dep_out" | grep -qiE "vulnerabilit(y|ies) found"; then
      say FAIL "cargo audit 发现漏洞"
    elif [ "$dep_rc" -eq 0 ]; then
      say PASS "cargo audit 未发现漏洞"
    else
      say WARN "cargo audit 退出码 $dep_rc，需人工判断"
    fi
  else
    say WARN "有 Cargo.toml 但未装 cargo-audit（NOT EXECUTED）"
  fi
fi
if [ -f "$TARGET/composer.json" ]; then
  dep_done=1
  if command -v composer >/dev/null 2>&1; then
    dep_out=$(cd "$TARGET" && composer audit 2>&1); dep_rc=$?
    printf '%s\n' "$dep_out" | tail -5
    if printf '%s\n' "$dep_out" | grep -qiE "found [0-9]+ (security )?vulnerabilit"; then
      say FAIL "composer audit 发现安全通告"
    elif [ "$dep_rc" -eq 0 ]; then
      say PASS "composer audit 未发现安全通告"
    else
      say WARN "composer audit 退出码 $dep_rc，需人工判断"
    fi
  else
    say WARN "有 composer.json 但未装 composer（NOT EXECUTED）"
  fi
fi
if [ "$dep_done" -eq 0 ]; then
  say WARN "未识别依赖清单（package-lock/requirements/go.mod/Cargo.toml/composer.json），依赖审计跳过"
fi

# ── 3. git 卫生 ────────────────────────────────────────────────
echo "-- [3/5] git 卫生 --"
if git -C "$TARGET" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  tracked=$(git -C "$TARGET" ls-files -- . | grep -Ei '\.env$|\.env\.|\.pem$|\.key$|\.p12$|\.pfx$|id_rsa|credentials' || true)
  if [ -n "$tracked" ]; then say FAIL "敏感文件已被 git 跟踪: $tracked"; else say PASS "无敏感文件被 git 跟踪"; fi
  if [ -f "$TARGET/.gitignore" ]; then
    grep -qE '^\.env|^/?\.env$|\.env\b' "$TARGET/.gitignore" && say PASS ".gitignore 覆盖 .env" || say WARN ".gitignore 未显式忽略 .env"
  else say WARN "无 .gitignore"; fi
  if git -C "$TARGET" log --oneline -200 --diff-filter=A --relative -- '*.env' '*.pem' '*.key' '*.p12' 2>/dev/null | grep -q .; then
    say FAIL "git 历史近 200 条中添加过疑似敏感文件（视为已泄露，需轮换）"
  else say PASS "git 历史近 200 条未见敏感文件新增记录"; fi
else
  say WARN "非 git 仓库，git 卫生检查跳过"
fi

# ── 4. 调试开关与危险默认值 ─────────────────────────────────────
echo "-- [4/5] 调试开关 --"
debug_hits=$(grep -rnEIi \
  --include='*.py' --include='*.js' --include='*.ts' --include='*.tsx' --include='*.jsx' \
  --include='*.mjs' --include='*.cjs' --include='*.java' --include='*.php' --include='*.go' \
  --include='*.rb' --include='*.cs' --include='*.vue' --include='*.svelte' \
  --include='*.yaml' --include='*.yml' --include='*.toml' --include='*.ini' \
  --include='*.conf' --include='*.properties' --include='.env*' \
  '(debug[[:space:]]*[:=][[:space:]]*true|app\.run\([^)]*debug[[:space:]]*=[[:space:]]*true)' \
  "$TARGET" 2>/dev/null | grep -vE 'node_modules|\.git/|dist/|build/' | head -10 || true)
if [ -n "$debug_hits" ]; then
  debug_bad=$(printf '%s\n' "$debug_hits" | grep -vE '(^|/)(tests?|spec|__tests__|fixtures?)/' || true)
  if [ -n "$debug_bad" ]; then
    say FAIL "源码/配置中发现 debug 开关（非测试路径；若属生产配置即中招），位置:"
    printf '%s\n' "$debug_bad"
  else
    say WARN "仅在测试/fixture 路径发现 debug 开关，逐条确认是否生产配置，位置:"
    printf '%s\n' "$debug_hits"
  fi
else say PASS "未见 debug=true / debug: true"; fi

# ── 5. 危险部署默认值 ──────────────────────────────────────────
echo "-- [5/5] 部署默认值 --"
compose_files=()
while IFS= read -r f; do
  [ -n "$f" ] && compose_files+=("$f")
done < <(find "$TARGET" -maxdepth 4 -type f \( \
  -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' \
  -o -name 'compose*.yml' -o -name 'compose*.yaml' \) \
  ! -path '*/node_modules/*' ! -path '*/.git/*' ! -path '*/dist/*' ! -path '*/build/*' 2>/dev/null)
if [ "${#compose_files[@]}" -gt 0 ]; then
  if grep -nE '(MYSQL|POSTGRES|MONGO|REDIS)_(ROOT_)?PASSWORD[[:space:]]*:[[:space:]]*["'"'"']?(root|123456|password|admin|postgres)["'"'"']?[[:space:]]*$' "${compose_files[@]}" 2>/dev/null; then
    say FAIL "docker-compose 使用常见弱默认密码（上方行）"
  else say PASS "docker-compose 未见常见弱默认密码"; fi
else say PASS "无 docker-compose 文件"; fi

nginx_hits=""
while IFS= read -r conf; do
  [ -z "$conf" ] && continue
  hits=$(grep -n 'autoindex on' "$conf" 2>/dev/null || true)
  [ -n "$hits" ] && nginx_hits="${nginx_hits}${conf}:${hits}"$'\n'
done < <(find "$TARGET" -maxdepth 4 -name '*.conf' -path '*nginx*' -print 2>/dev/null)
if [ -n "$nginx_hits" ]; then
  say WARN "nginx 开启 autoindex（目录可列表）:"
  printf '%s' "$nginx_hits"
else say PASS "nginx autoindex 未开启或无 nginx 配置"; fi

echo "== 汇总: PASS=$PASS WARN=$WARN FAIL=$FAIL =="
echo "说明: FAIL=发版前必须处置; WARN=需人工判定; 密钥/竞态等深度问题请运行完整安全审核（十阶段）"
if [ "$STRICT" -eq 1 ] && [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
