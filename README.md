# project-security-audit

`security-audit` 是一个用于项目安全审核的 AI skill：静态审查 + AI 自攻击验证 + 漏洞情报核对，输出带评分、P0–P3 分级和修复路线图的报告。

当前版本：**alpha1.1**

## 适用场景

- 项目上线/发版前的安全审核
- 接手陌生项目时的第一轮安全测绘
- 密钥/硬编码、接口越权、依赖 CVE、部署配置检查
- 发布前快速自审查（A 档），以及迭代内/月度复查（B/C 档）
- 需要一份可执行、可复核的安全报告，而不是零散建议

## 目录结构

```text
.
├── SKILL.md                    # 主流程与报告规范（十阶段）
├── VERSION
├── CHANGELOG.md
├── references/
│   ├── server-vulns.md         # 服务器与运行环境漏洞
│   ├── api-audit.md            # 接口审查
│   ├── secrets-hijack.md       # 密钥、硬编码与劫持
│   ├── advanced-risks.md       # 密码学、竞态、LLM、云、供应链等
│   ├── vuln-intel.md           # 近期漏洞情报
│   ├── attack-testing.md       # 授权门、红线与自攻击手册
│   ├── risk-standards.md       # P0–P3、五维评分、结论判定
│   ├── structure-optimization.md
│   ├── performance.md
│   ├── audit-prompts.md        # 12 类复核提示词
│   └── self-review.md          # 快速自审查 A/B/C 档
├── scripts/
│   ├── scan_secrets.py         # 跨平台密钥/凭据扫描（首选）
│   ├── self_check.py           # 跨平台发布前自检（首选，支持 --strict）
│   ├── scan_secrets.sh         # bash 备选
│   └── self_check.sh           # bash 备选
├── tests/
│   └── test_smoke.py           # Python 回归测试（临时夹具，不含真实密钥）
└── .github/workflows/ci.yml    # Linux/Windows + Python 3.9/3.12 CI
```

## 使用方式

把整个 `security-audit/` 目录放进项目的 `.agents/skills/` 下，或在支持 skill 的 agent 中加载 `SKILL.md`。

常用触发语：

- “对这个项目做一次完整安全审核”
- “上线前帮我检查一下”
- “扫描一下有没有硬编码密钥”
- “模拟攻击者打一遍这个项目”
- “做一次发布前自审查”

完整审核默认按 `SKILL.md` 的阶段 1–10 执行；只做发布前快速自检时，走 `references/self-review.md` 的 A 档。

## 快速开始

```bash
# 发布前自检（有 FAIL 时返回非零，适合 CI）
python scripts/self_check.py <项目目录> --strict

# 只跑密钥扫描（JSON 便于二次处理）
python scripts/scan_secrets.py <项目目录> --json

# 修改脚本后跑回归
python -m unittest discover -s tests -v
```

Windows、Linux、macOS 均可直接运行 Python 脚本。bash 版需要 Linux/macOS 或 Git Bash；Windows 系统自带的 `bash.exe` 可能是 WSL 启动器，不应当作可用 shell。

## 依赖

- 静态审核与快速自检：Python 3.9+
- bash 备选脚本：bash 4+、`grep`、`find`
- 完整动态测试：`curl`（命令模板以 bash 语法给出，Windows 用 Git Bash 或等价改写）
- 依赖审计（可选）：`npm`、`pip-audit`、`govulncheck`、`cargo`、`composer`
- 动态测试仅在用户明确授权的本地/测试环境执行

## 安全边界

- 静态审查不修改、不删除项目文件
- 动态攻击测试必须同时满足：授权明确、环境隔离、红线之内
- 禁止破坏性 payload、拒绝服务式压测、攻击第三方、触碰真实用户数据
- LLM 工具滥用测试只允许 mock/dry-run/一次性测试租户，禁止真实删除、群发、支付
- 报告默认写入 `security-reports/`，并做密钥/PII 脱敏；原始证据不提交 git

## 版本

- **alpha1.1** — 修复一致性与安全问题；新增跨平台 Python 工具、回归测试与 CI；报告增加脱敏、覆盖边界和附录规范。
- **alpha1.0** — 初始版本：十阶段审核流程、11 个参考文件、2 个 bash 脚本、完整报告模板与 A/B/C 自审查节奏。
