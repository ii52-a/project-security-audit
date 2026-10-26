# Changelog

## alpha1.1

### 安全与一致性修复

- 统一为“十阶段”（阶段 1–9 主流程 + 阶段 10 复核轮），修正主文件、自审查与脚本中的“九阶段”表述。
- 统一“动态未复现”的降级规则：最多降半级，且仅当攻击确实覆盖对应路径；删除“降一级”的冲突说法。
- 明确总体结论判定顺序：先看“不可上线”硬红线（P0≥3、已泄露凭据、认证缺失），再“修复后上线”，最后“可上线”；A/B/C/D 只表示分数等级。
- 修复登录限流测试与“≤6 次错误密码”红线的冲突：限流探测改用一次性账号、最多 12 次、放在所有会话测试之后。
- 增加 LLM 工具滥用测试的硬约束：只允许 mock/dry-run/一次性测试租户，禁止真实删除、群发、支付。
- 增加报告证据脱敏规则（密钥、token、Cookie、PII、内网地址），默认报告目录改为 `security-reports/`，不再写项目根目录。
- 报告模板增加“审核范围与未覆盖项”、附录 A（接口清单）、附录 B（证据脱敏说明）。
- 漏洞情报搜索的年份/年月改为占位符，避免示例过期；API 接口清单明确写入附录 A。
- 修复预提交钩子漏掉 `.env.local`、`.p12`、`.pfx`、`id_rsa` 的问题。

### 跨平台与工具

- 新增 `scripts/scan_secrets.py`、`scripts/self_check.py`：Python 3.9+ 跨平台实现，Windows/Linux/macOS 通用。
- `self_check.py` 支持 `--json`、`--strict`、`--skip-deps`；扫描器失败不再误报 PASS。
- bash 版 `self_check.sh` 增加 `--strict`、扫描失败处理、敏感文件提示、`.env` / YAML `debug: true` / `.tsx` 等覆盖。
- `scan_secrets.sh` 与 Python 版规则对齐，新增 `.pypirc`、Docker `auth`、Slack Webhook 规则。
- 动态测试模板改为多数据库时间盲注（MySQL/PostgreSQL/SQL Server）、UUID/数字 ID 兼容、跨平台临时目录与 base64 写法。

### 工程质量

- 新增 `tests/test_smoke.py`：临时夹具覆盖密钥扫描、调试开关、弱默认密码、敏感文件与 `--strict` 退出码。
- 新增 GitHub Actions CI：Ubuntu/Windows × Python 3.9/3.12，运行回归测试与 bash 语法检查。
- 新增 `.gitattributes`、`.gitignore`、`README.md`、`VERSION`、`CHANGELOG.md`。

## alpha1.0

- 初始版本：十阶段安全审核流程、11 个参考文件、2 个 bash 脚本。
- 包含密钥扫描、服务器/接口/进阶风险清单、漏洞情报核对、AI 自攻击授权门与红线、P0–P3 五维评分、报告模板、A/B/C 自审查节奏。
