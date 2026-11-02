#!/usr/bin/env bash
# scan_secrets.sh — 在目标目录中扫描疑似硬编码密钥/凭据的候选点。
# 用法: bash scan_secrets.sh <目标目录> [--reveal] [--fail-on-hit] [--exclude GLOB]
# 输出: "文件:行号: [REDACTED] | [规则名]"（默认脱敏）；--reveal 才显示原文。
# 结果仅供人工确认，存在误报与漏报。推荐优先使用跨平台的 scan_secrets.py。
# 说明: 本脚本适用于 Linux/macOS/Git Bash；Windows 自带 bash.exe 可能是不可用的 WSL 启动器。

set -u

TARGET=""
REVEAL=0
FAIL_ON_HIT=0
EXCLUDES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --reveal) REVEAL=1 ;;
    --fail-on-hit) FAIL_ON_HIT=1 ;;
    --exclude)
      shift
      [ $# -gt 0 ] && EXCLUDES+=("$1")
      ;;
    -h|--help)
      sed -n '2,7p' "$0"
      exit 0
      ;;
    *)
      TARGET="$1"
      ;;
  esac
  shift
done
TARGET="${TARGET:-.}"
[ -d "$TARGET" ] || { echo "错误: $TARGET 不是目录" >&2; exit 1; }

# 排除目录与文件类型：依赖、版本库、构建产物、媒体与二进制
EXCLUDE_DIRS=(node_modules .git dist build vendor __pycache__ .next coverage target bin obj venv .venv wwwroot .idea .vscode Pods DerivedData .mypy_cache .pytest_cache .ruff_cache)
PRUNE=()
for d in "${EXCLUDE_DIRS[@]}"; do
  PRUNE+=( -path "*/$d" -prune -o )
done
EXTRA_EXCLUDES=()
for ex in "${EXCLUDES[@]+"${EXCLUDES[@]}"}"; do
  EXTRA_EXCLUDES+=( ! -path "$TARGET/$ex" ! -path "*/$ex" )
done

# 正则规则：名称=模式（ERE）
PATTERNS=(
  "aws-aksk=AKIA[0-9A-Z]{16}"
  "aliyun-aksk=LTAI[0-9A-Za-z]{12,24}"
  "volc-aksk=AKLT[0-9A-Za-z]{16,40}"
  "private-key=-----BEGIN [A-Z ]*PRIVATE KEY-----"
  "db-url=(mysql|postgres(ql)?|mongodb(\+srv)?|redis|amqp|mssql)://[^\"'[:space:]]*:[^\"'[:space:]]*@"
  "jwt-secret=(jwt[_-]?(secret|key)|token[_-]?secret|signing[_-]?key)[\"'[:space:]]*[:=][\"'[:space:]]*[A-Za-z0-9+/=_-]{8,}"
  "generic-secret=(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|client[_-]?secret|app[_-]?secret)[\"'[:space:]]*[:=][\"'[:space:]]*[\"']?[A-Za-z0-9+/=_-]{16,}"
  "sk-live=sk_(live|test)_[0-9A-Za-z]{16,}"
  "bearer-basic=Authorization[\"'[:space:]:=]+[\"']?Basic [A-Za-z0-9+/=]{16,}"
  "password-literal=(^|[^-])(password|passwd|pwd)[\"'[:space:]]*[:=][\"'[:space:]]*[\"'][^\"']{4,}[\"']"
  "pypirc-password=^[[:space:]]*password[[:space:]]*=[[:space:]]*[^[:space:]]{4,}"
  "dotenv-secret=^[[:space:]]*(export[[:space:]]+)?[A-Za-z0-9_]*(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|CREDENTIAL)[A-Za-z0-9_]*[[:space:]]*=[[:space:]]*[^[:space:]#]{8,}"
  "docker-auth=\"auth\"[[:space:]]*:[[:space:]]*\"[A-Za-z0-9+/=]{20,}\""
  "slack-giphy=xox[baprs]-[0-9A-Za-z-]{10,}"
  "slack-webhook=https://hooks\.slack\.com/services/[A-Za-z0-9/]+"
  "google-api-key=AIza[0-9A-Za-z_-]{35}"
  "github-token=gh[pousr]_[0-9A-Za-z]{36,}"
  "tencent-aksk=AKID[A-Za-z0-9]{32,}"
  "gitlab-pat=glpat-[0-9A-Za-z_-]{20,}"
  "npm-token=npm_[A-Za-z0-9]{30,}"
  "sendgrid-key=SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"
  "telegram-bot=[0-9]{8,10}:AA[A-Za-z0-9_-]{33}"
  "llm-apikey=sk-(proj-|ant-)?[A-Za-z0-9_=-]{24,}"
  "azure-conn=AccountKey=[A-Za-z0-9+/=]{40,}"
  "wechat-mchkey=(mch[_-]?key|partner[_-]?key)[\"'[:space:]]*[:=][\"'[:space:]]*[0-9A-Za-z]{32}"
  "insecure-tls=(rejectUnauthorized[\"'[:space:]]*[:=][\"'[:space:]]*false|verify[\"'[:space:]]*=[\"'[:space:]]*False|InsecureSkipVerify[\"'[:space:]]*:[\"'[:space:]]*true)"
)

echo "== scan_secrets: $TARGET =="
found=0
hits=0
for entry in "${PATTERNS[@]}"; do
  name="${entry%%=*}"
  regex="${entry#*=}"

  FILE_FILTER=()
  case "$name" in
    pypirc-password) FILE_FILTER=( -name '.pypirc' ) ;;
    dotenv-secret) FILE_FILTER=( \( -name '.env' -o -name '.env.*' \) ) ;;
  esac

  FIND_ARGS=( "$TARGET" "${PRUNE[@]}" -type f -size -2M )
  if [ "${#FILE_FILTER[@]}" -gt 0 ]; then
    FIND_ARGS+=( "${FILE_FILTER[@]}" )
  fi
  FIND_ARGS+=(
    ! -name '*.png' ! -name '*.jpg' ! -name '*.jpeg' ! -name '*.gif'
    ! -name '*.ico' ! -name '*.woff*' ! -name '*.ttf' ! -name '*.eot'
    ! -name '*.mp4' ! -name '*.zip' ! -name '*.gz' ! -name '*.tar'
    ! -name '*.jar' ! -name '*.pdf' ! -name '*.map' ! -name '*.lock'
    "${EXTRA_EXCLUDES[@]+"${EXTRA_EXCLUDES[@]}"}"
    -print0
  )

  # shellcheck disable=SC2046
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    found=1
    hits=$((hits+1))
    if [ "$REVEAL" -eq 1 ]; then
      printf '%s | [%s]\n' "$(printf '%s' "$hit" | cut -c1-160)" "$name"
    else
      prefix=$(printf '%s' "$hit" | cut -d: -f1,2)
      printf '%s: [REDACTED] | [%s]\n' "$prefix" "$name"
    fi
  done < <(
    find "${FIND_ARGS[@]}" 2>/dev/null |
    xargs -0 grep -InEi -e "$regex" 2>/dev/null
  )
done

# 附加检查：可能的密钥/凭据文件本身
echo "== 疑似敏感文件 =="
find "$TARGET" "${PRUNE[@]}" -type f \( \
  -name '*.env' -o -name '*.env.*' -o -name '*.pem' -o -name '*.key' \
  -o -name '*.p12' -o -name '*.pfx' -o -name 'id_rsa*' -o -name 'credentials*' \
  -o -name '.npmrc' -o -name '.pypirc' -o -name '*.sql' -o -name '*.bak' -o -name '*.dump' \
  -o \( -name 'config.json' -path '*/.docker/*' \) \) -print 2>/dev/null

echo "== 汇总: 规则命中 $hits 处 =="
[ "$found" -eq 0 ] && echo "(正则未命中候选点——仍需按 references/secrets-hijack.md 人工补查日志、前端产物与 git 历史)"
[ "$REVEAL" -eq 0 ] && echo "(命中值默认脱敏；确需原文时使用 --reveal，且不要用于 CI 日志)"
if [ "$FAIL_ON_HIT" -eq 1 ] && [ "$found" -eq 1 ]; then
  exit 1
fi
exit 0
