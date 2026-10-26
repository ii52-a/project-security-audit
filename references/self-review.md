# 项目自审查流程

完整审核（九阶段）成本高，不适合天天跑。本流程定义项目方日常可持续执行的自审查节奏，也作为 skill 的**快速模式**：用户说"自审查/自查/安全自检"时，agent 按 A 档执行并输出轻量报告，不启动九阶段全流程。

## A 档：发布前快速自检（目标 ≤15 分钟）

每次发版前由开发或 agent 执行：

```bash
# 1. 一键自检脚本（密钥扫描 + 依赖审计 + git 卫生 + 调试开关）
bash <skill目录>/scripts/self_check.sh <项目目录>

# 2. 高风险变更复查：自上次审核以来的改动里筛"摸安全边界的"
git diff --stat v<上次发版tag>..HEAD -- '*auth*' '*login*' '*permission*' '*upload*' '*pay*' '*config*'
# 3. 新增接口过"四问"
git diff v<上次发版tag>..HEAD -- '*route*' '*controller*' '*api*'
```

对筛出的每个改动文件回答：**新增/修改的接口挂鉴权了吗？外部输入进危险 sink 了吗？改了配置默认值吗？动过密钥/凭据吗？** 任一答不好 → 触发完整审核。

### A 档检查清单（脚本之外的人工项）

| # | 检查项 | 判定 |
|---|---|---|
| A1 | `self_check.sh` 无 P0 命中 | 有命中即中止发版，先处置 |
| A2 | 新增依赖过 CVE 查询（按 vuln-intel.md 第 3 节查一遍） | 无未处置高危 |
| A3 | 环境变量有新增吗？`.env.example` 同步了吗？ | 一致 |
| A4 | 数据库变更脚本里有没有删列/改权限？ | 有则单独评审 |
| A5 | 日志新增语句没有打印敏感字段 | 逐条目检 diff |

输出：轻量报告（`self-review-<日期>.md`）——五项判定结果 + 风险变更清单 + 是否放行结论。

## B 档：迭代内安全卡点（每个开发迭代）

- 新增第三方包：安装前查维护活跃度与已知 CVE，`postinstall` 脚本过目。
- 新增接口：按 [api-audit.md](api-audit.md) 第 2–6 节四问自查（谁能调/输入校验/输出脱敏/限流）。
- 提交前密钥拦截：见下方 pre-commit 集成。
- 涉及资金/库存/权限的改动：reviewer 强制一人，重点看竞态（"先查后写"是否原子）。

### pre-commit 集成（一次配置，永久生效）

```yaml
# .pre-commit-config.yaml 示例
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks
  - repo: local
    hooks:
      - id: no-env-committed
        name: forbid committing .env/.pem/.key
        entry: bash -c 'git diff --cached --name-only | grep -E "\.env$|\.pem$|\.key$" && exit 1 || exit 0'
        language: system
```

## C 档：月度深度复查（≤2 小时）

1. 重跑完整 skill 审核的阶段 2（密钥，含 git 历史增量）、3（服务器）、5（进阶）——不必每次全九阶段。
2. 密钥年龄检查：所有生产凭据轮换周期 ≤90 天，超期列清单。
3. 权限最小化复查：云 IAM、数据库账号、服务器用户有无"临时开大忘了收"的。
4. 复查上次完整审核报告：P0/P1 是否清零、P2 有无滚动修复。
5. 漏洞情报增量：按 [vuln-intel.md](vuln-intel.md) 对核心组件重搜近 30 天新 CVE。

## 自查发现异常时的升级路径

A/B 档自查**只发现问题，不深挖利用**：发现疑似可利用漏洞（注入、越权、密钥泄露）→ 停止自查，报告并建议触发完整九阶段审核（含自攻击验证）来确认影响面。自查的职责是"早发现"，"定性"交给完整审核。

## agent 快速模式执行顺序

用户要求"自审查/自查"时：读本文件 → 依次跑 self_check.sh、git diff 筛查、A 档清单 → 简要核对 vuln-intel 第 3 节（仅新增依赖）→ 输出轻量报告。全程不做攻击测试、不建监听器；发现 P0 级疑似项时明确建议"触发完整安全审核"。
