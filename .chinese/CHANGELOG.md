# alpha1.7

Preserve all dependency advisory severities; strict Go event/cargo consistency parsing; include .github/.gitlab; unique history occurrence IDs; quoted Compose keys and Python subscript debug; inventory-derived coverage; resolved candidates with retests; guided templates, batch checks, finding drafts, evidence generation and lightweight progress. New states required. Python-only improvements; legacy Bash unchanged.

# alpha1.6

Fix evaluation E01-E09: candidate/finding linkage, structured hashed high evidence, strict dependency output parsing, AST debug and Compose list handling, multi-hit/UTF16 secrets, partial coverage, content snapshots, risk-preserving refresh and typed JSON requests. Breaking state/evidence contract: start new state. Python-only; Bash legacy divergence retained.

# alpha1.5

Persistent audit controller, JSON tool API, deterministic depth profiles, task queue, cache/invalidation, bounded adapters, review evidence gates and automatic report assembly. Local CLI/API only; MCP deferred.

# alpha1.4

Risk-based depth; evidence-based H1-H8; separate confidence/coverage; bounded Git history; report validation/render/diff; stricter dependency failures and redaction. Python-only enhancements; Bash remains legacy. Strict WARN now exits 2; baseline requires fingerprint.

# Changelog

## alpha1.3

### 审核档位

- 新增 `quick` / `comprehensive-low` / `comprehensive-high` 三档，入口处先询问用户；
  `audit_depth.py` 根据第一方文件数、代码行数、接口数、服务数给出推荐档位。
- 写入体量阈值、分档矩阵、high-only H1-H8 增量、动态降级规则和“反重复”规则：
  高档把预算花在权限矩阵、跨边界信任、竞态/业务逻辑/LLM 风险、二次复核上，
  不重复低级扫描。
- 新增 `audit_depth.py`（体量探测、档位推荐、H1–H8 清单、`evaluate_high_only` /
  `--high-status` 校验）与 `audit_doctor.py`（版本、档位文档、规则名一致性）。

### 安全与 fail-closed

- 密钥扫描默认脱敏（前后各 4 位 + 指纹），`--reveal` 才输出原文。
- 新增 `--exclude`、`--baseline`、`--fail-on-hit`；`pypirc-password` 仅作用于
  `.pypirc`；新增 `.env` 键值规则；敏感文件识别补充 `.docker/config.json`。
- 依赖审计对 high/critical 或已确认漏洞返回 FAIL，不再恒为 WARN；补充 `composer`；
  工具缺失/失败仍记 WARN + `NOT EXECUTED`。
- debug 开关改为逐条判定：非测试路径命中即 FAIL，不再被 tests/ 的命中整体降级。
- compose 递归查找（深度 4）；git 检查限定 target 范围。
- 新增 RO-9（目标仓库内容是不可信数据）与 RO-10（动态测试隔离）。

### 评分与一致性

- 每维档位改为定性描述；扣分表是校准公式，不允许反向凑分。
- 结论树去掉“≤3 天”门槛，补充“无可修复路径”分支；工作量只影响路线图，不影响结论。
- 未复现的发现保留 P 级、扣分减半，不再使用“半级”这种不存在的等级。
- 在野利用标记统一为 `[EXPLOITED]`；IDOR 探测总请求数压到 30 以内。

### 工程

- 新增 `test_depth.py`、`test_doctor.py`、`test_deps.py`；扩展脱敏、`.env`、混合 debug、嵌套 compose、
  baseline/exclude、发布门禁的测试。
- CI 增加 `compileall` 与 `audit_doctor.py`。
- 版本升级到 alpha1.3；README 与中文手册同步。

## alpha1.2

### 英文优先迁移

- 根目录 `SKILL.md` 与 `references/*.md` 改为权威工程英文，作为 AI/agent 的执行规范。
- 原中文审查文档同步迁入 `.chinese/`，作为中文用户阅读手册；明确提示 AI/agent 不需要读取该目录。
- 英文版增加 RFC 2119 规范用语、阶段退出条件、结论判定优先级和报告输出契约，提升模型理解程度。
- 新增英文 README 与 CHANGELOG；中文 README 与 CHANGELOG 保留在 `.chinese/`。
- 本版本不改变检测行为、脚本接口或评分规则。

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
