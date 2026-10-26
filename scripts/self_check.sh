#!/usr/bin/env bash
# self_check.sh — 项目自审查快速自检（发布前 ≤15 分钟档）
# 用法: bash self_check.sh [项目目录]   （默认当前目录）
# 检查: 密钥硬编码 + 依赖漏洞审计 + git 卫生 + 调试开关 + 危险默认配置
# 输出: 逐项 PASS/WARN/FAIL 汇总。脚本只报告不修改项目文件。结果需人工确认，存在误报漏报。

set -u
TARGET="${1:-.}"
TARGET="${TARGET%/}"
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

# ── 1. 密钥与硬编码扫描（复用 scan_secrets.sh）──────────────────
echo "-- [1/5] 密钥扫描 --"
secret_hits=$(bash "$SKILL_DIR/scripts/scan_secrets.sh" "$TARGET" | grep -c '| \[' || true)
if [ "$secret_hits" -gt 0 ]; then
  say FAIL "密钥扫描命中 $secret_hits 处候选（逐条人工确认后定级）"
  bash "$SKILL_DIR/scripts/scan_secrets.sh" "$TARGET" | grep '| \[' | head -20
else
  say PASS "密钥扫描无正则命中（仍需人工补查日志/前端产物）"
fi

# ── 2. 依赖漏洞审计 ────────────────────────────────────────────
echo "-- [2/5] 依赖审计 --"
if [ -f "$TARGET/package-lock.json" ]; then
  if command -v npm >/dev/null 2>&1; then
    (cd "$TARGET" && npm audit --omit=dev 2>&1 | tail -5)
    say WARN "已运行 npm audit，上方输出中 0 high/critical 才算通过（脚本不代判）"
  else say WARN "有 package-lock.json 但本机无 npm，跳过"; fi
elif [ -f "$TARGET/requirements.txt" ]; then
  if command -v pip-audit >/dev/null 2>&1; then
    pip-audit -r "$TARGET/requirements.txt" 2>&1 | tail -5
    say WARN "已运行 pip-audit，无输出行才算通过（脚本不代判）"
  else say WARN "有 requirements.txt 但未装 pip-audit（pip install pip-audit）"; fi
elif [ -f "$TARGET/go.mod" ]; then
  if command -v govulncheck >/dev/null 2>&1; then
    (cd "$TARGET" && govulncheck ./... 2>&1 | tail -5)
    say WARN "已运行 govulncheck，按输出判定"
  else say WARN "有 go.mod 但未装 govulncheck"; fi
else
  say WARN "未识别依赖清单（package-lock/requirements/go.mod），依赖审计跳过"
fi

# ── 3. git 卫生 ────────────────────────────────────────────────
echo "-- [3/5] git 卫生 --"
if git -C "$TARGET" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  tracked=$(git -C "$TARGET" ls-files | grep -Ei '\.env$|\.env\.|\.pem$|\.key$|\.p12$|\.pfx$|id_rsa' || true)
  if [ -n "$tracked" ]; then say FAIL "敏感文件已被 git 跟踪: $tracked"; else say PASS "无敏感文件被 git 跟踪"; fi
  if [ -f "$TARGET/.gitignore" ]; then
    grep -qE '^\.env|^/?\.env$|\.env\b' "$TARGET/.gitignore" && say PASS ".gitignore 覆盖 .env" || say WARN ".gitignore 未显式忽略 .env"
  else say WARN "无 .gitignore"; fi
  # 大小写防御：历史里是否出现过疑似密钥提交（只看最近 200 条，深查用完整审核）
  if git -C "$TARGET" log --oneline -200 --diff-filter=A -- '*.env' '*.pem' '*.key' '*.p12' 2>/dev/null | grep -q .; then
    say FAIL "git 历史近 200 条中添加过疑似敏感文件（视为已泄露，需轮换）"
  else say PASS "git 历史近 200 条未见敏感文件新增记录"; fi
else
  say WARN "非 git 仓库，git 卫生检查跳过"
fi

# ── 4. 调试开关与危险默认值 ─────────────────────────────────────
echo "-- [4/5] 调试开关 --"
debug_hits=$(grep -rnEi --include='*.py' --include='*.js' --include='*.ts' --include='*.java' \
  --include='*.php' --include='*.go' \
  '(debug[[:space:]]*=[[:space:]]*true|app\.run\([^)]*debug[[:space:]]*=[[:space:]]*true|DEBUG[[:space:]]*=[[:space:]]*true)' \
  "$TARGET" 2>/dev/null | grep -vE 'node_modules|\.git/|dist/|build/' | head -10 || true)
if [ -n "$debug_hits" ]; then say FAIL "源码中发现 debug=true（若属生产配置即中招），位置:"; printf '%s\n' "$debug_hits"
else say PASS "未见 debug=true"; fi

# ── 5. 危险部署默认值 ──────────────────────────────────────────
echo "-- [5/5] 部署默认值 --"
if [ -f "$TARGET/docker-compose.yml" ] || [ -f "$TARGET/docker-compose.yaml" ] || [ -f "$TARGET/compose.yaml" ]; then
  if grep -nE '(MYSQL|POSTGRES|MONGO|REDIS)_(ROOT_)?PASSWORD[^:]*:\s*("|'"'"')?(root|123456|password|admin|postgres)("|'"'"')?\s*$' "$TARGET"/docker-compose*.y*ml "$TARGET"/compose*.y*ml 2>/dev/null | grep -v node_modules; then
    say FAIL "docker-compose 使用常见弱默认密码（上方行）"
  else say PASS "docker-compose 未见常见弱默认密码"; fi
else say PASS "无 docker-compose 文件"; fi
nginx_conf=$(find "$TARGET" -maxdepth 3 -name '*.conf' -path '*nginx*' 2>/dev/null)
if [ -n "$nginx_conf" ] && grep -n 'autoindex on' $nginx_conf >/dev/null 2>&1; then
  say WARN "nginx 开启 autoindex（目录可列表）: $nginx_conf"
else say PASS "nginx autoindex 未开启或无 nginx 配置"; fi

echo "== 汇总: PASS=$PASS WARN=$WARN FAIL=$FAIL =="
echo "说明: FAIL=发版前必须处置; WARN=需人工判定; 密钥/竞态等深度问题请运行完整安全审核（九阶段）"
exit 0
