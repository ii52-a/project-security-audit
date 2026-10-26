#!/usr/bin/env bash
# scan_secrets.sh — 在目标目录中扫描疑似硬编码密钥/凭据的候选点。
# 用法: bash scan_secrets.sh <目标目录>
# 输出: "文件:行号: [规则名] 匹配行(截断)" 列表。结果仅供人工确认，存在误报与漏报。

set -u
TARGET="${1:?用法: scan_secrets.sh <目标目录>}"
[ -d "$TARGET" ] || { echo "错误: $TARGET 不是目录" >&2; exit 1; }

# 排除目录与文件类型：依赖、版本库、构建产物、媒体与二进制
EXCLUDE_DIRS=(node_modules .git dist build vendor __pycache__ .next coverage target bin obj venv .venv wwwroot)
PRUNE=()
for d in "${EXCLUDE_DIRS[@]}"; do
  PRUNE+=( -path "*/$d" -prune -o )
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
  "bearer-b64=Authorization[\"'[:space:]:=]+[\"']?Basic [A-Za-z0-9+/=]{16,}"
  "password-literal=(password|passwd|pwd)[\"'[:space:]]*[:=][\"'[:space:]]*[\"'][^\"']{4,}[\"']"
  "slack/giphy=xox[baprs]-[0-9A-Za-z-]{10,}"
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
for entry in "${PATTERNS[@]}"; do
  name="${entry%%=*}"
  regex="${entry#*=}"
  # shellcheck disable=SC2046
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    found=1
    printf '%s | [%s]\n' "$(printf '%s' "$hit" | cut -c1-160)" "$name"
  done < <(
    find "$TARGET" "${PRUNE[@]}" -type f -size -2M \
      ! -name '*.png' ! -name '*.jpg' ! -name '*.jpeg' ! -name '*.gif' \
      ! -name '*.ico' ! -name '*.woff*' ! -name '*.ttf' ! -name '*.eot' \
      ! -name '*.mp4' ! -name '*.zip' ! -name '*.gz' ! -name '*.tar' \
      ! -name '*.jar' ! -name '*.pdf' ! -name '*.map' ! -name '*.lock' \
      -print0 2>/dev/null |
    xargs -0 grep -InEi "$regex" 2>/dev/null
  )
done

# 附加检查：可能的密钥/凭据文件本身
echo "== 疑似敏感文件 =="
find "$TARGET" "${PRUNE[@]}" -type f \( \
  -name '*.env' -o -name '*.env.*' -o -name '*.pem' -o -name '*.key' \
  -o -name '*.p12' -o -name '*.pfx' -o -name 'id_rsa*' -o -name 'credentials*' \
  -o -name '*.sql' -o -name '*.bak' -o -name '*.dump' \) -print 2>/dev/null

[ "$found" -eq 0 ] && echo "(正则未命中候选点——仍需按 references/secrets-hijack.md 人工补查日志、前端产物与 git 历史)"
exit 0
