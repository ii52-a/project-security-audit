---
name: security-audit
description: 对项目目录进行全面安全审核、评估与自攻击测试。当用户要求安全审核、安全审计、安全评估、漏洞扫描、渗透测试、攻击测试、自攻击/红队演练、检查密钥/密码泄露、硬编码检查、接口安全审查、项目风险评估、近期漏洞/CVE 情报核查、项目自审查/自查/安全自检、结构评估或性能分析时使用本 skill——即使用户没有明确说"安全"两个字（例如"帮我看看这个项目有没有问题"、"上线前检查一下"、"模拟攻击者打一遍这个项目"、"最近有什么新漏洞会影响我们"）。
---

# 项目安全审核 (Security Audit)

对指定目录执行结构化的安全审核，包含静态审查 + AI 自攻击动态验证，输出一份带评分、风险分级和可执行修复建议的报告。

## 总原则

- **只读审核（静态）**：静态审查阶段不修改、不删除项目文件。修复建议只写在报告中。
- **证据优先**：每个发现必须附带 `文件路径:行号` 和问题代码摘录（静态）或请求/响应记录（动态），禁止无证据的猜测。无法确认的项标记为"需人工复核"。
- **宁全勿漏**：按检查清单逐项过，没发现问题的项也要在报告"已检查无异常"中体现，让读者知道检查覆盖面。
- **区分严重度**：按 P0–P3 分级（标准见 [references/risk-standards.md](references/risk-standards.md)）。
- **自攻击三前提**：动态攻击测试仅在同时满足以下条件时执行——①授权明确（用户自有的本地/测试环境，用户已同意攻击测试）；②环境隔离（不含真实用户数据、不连生产数据库）；③红线之内（禁破坏性 payload、禁拒绝服务式压测、禁超量请求，详见 attack-testing.md）。任一条件不满足则跳过动态测试，只做静态审核并在报告注明原因。

## 审核工作流（九阶段）

### 阶段 1：项目测绘（Recon）

1. 列出目标目录结构（树状，深度 3–4 层），识别技术栈（框架、语言、构建工具、部署配置）。
2. 定位关键文件：入口文件、路由/接口定义、配置文件（`.env`、`config.*`、`docker-compose.yml`、`nginx.conf` 等）、依赖清单、CI/CD 配置、Dockerfile。
3. 识别对外暴露面：监听端口、Web 服务、API 路由、静态资源目录、管理后台。
4. 把测绘结果写进报告的"项目概况"，后续阶段都依赖它。

### 阶段 2：密钥与硬编码扫描

1. 运行 `bash scripts/scan_secrets.sh <目标目录>`，得到候选泄露点列表（正则覆盖各云厂商 AK/SK、私钥、连接串、JWT secret、各平台 token 等 22 类规则）。
2. **逐条人工确认**脚本结果——正则有误报（示例代码、测试 fixture、占位符 `xxx`），也检查脚本扫不到的模式：日志打印敏感信息、前端产物里的内网地址、错误堆栈暴露路径。
3. 同时检查 `.gitignore` 覆盖、git 历史泄露（已提交即视为泄露，需轮换）。
4. 详细检查项见 [references/secrets-hijack.md](references/secrets-hijack.md)。

### 阶段 3：服务器与运行环境漏洞

按 [references/server-vulns.md](references/server-vulns.md) 检查：注入类、认证/会话、授权、文件处理、SSRF/CSRF、安全响应头、TLS、容器与部署配置、依赖漏洞。

### 阶段 4：项目接口审查

1. 枚举全部接口（路由、RPC、WebSocket 事件、定时任务、CLI 入口），生成接口清单。
2. 对每个接口回答四个问题：**谁能调？输入校验了吗？输出脱敏了吗？有频率限制吗？**
3. 按 [references/api-audit.md](references/api-audit.md) 逐项检查认证、越权、输入输出处理、CORS、文件上传下载、限流防刷、回调验签。此阶段产出的"疑似漏洞清单"是阶段 7 攻击假设的主要来源。

### 阶段 5：进阶风险扫描

按 [references/advanced-risks.md](references/advanced-risks.md) 检查常规清单覆盖不到的深度维度：密码学误用、竞态与并发缺陷、LLM/AI 应用特有风险（提示注入、工具滥用、智能体越权）、GraphQL/ WebSocket、微服务内部信任、云与 IAM、前端深水区（postMessage/localStorage/source map）、移动端、供应链投毒。

### 阶段 6：近期漏洞情报搜索

按 [references/vuln-intel.md](references/vuln-intel.md)：

1. 从阶段 1 测绘与 lock 文件提取带精确版本的组件清单。
2. 有网先跑自动审计（`npm audit --omit=dev` / `pip-audit` / `govulncheck`），再 Web 搜索补充近期 CVE 与安全通告（优先厂商公告、GitHub Advisory/NVD，标 ⚡ 在野利用项）。
3. 逐条核对"影响版本区间 vs 本项目实际版本 vs 触发条件"，生成情报汇总表；评级映射进主发现表。
4. 受影响且有公开 PoC 的注入/RCE 类漏洞 → 追加为阶段 7 攻击假设（非破坏版 PoC，守红线）。

### 阶段 7：AI 自攻击测试（动态验证）

**先读 [references/attack-testing.md](references/attack-testing.md) 的授权门与红线，通过后再执行。** 流程概要：

1. **授权检查**：确认目标是用户自有的本地/测试环境且用户同意攻击测试；发现生产特征（真实域名、生产数据库、真实用户数据）立即终止动态测试。
2. **环境准备**：在隔离环境启动应用，注册两个测试账号（A/B，用于越权测试），建立基线响应。
3. **攻击假设**：汇总阶段 3–6 的静态疑点与情报命中 + 攻击手册的标准技术，形成带编号的假设清单。
4. **执行攻击**：按手册逐项验证——认证绕过、IDOR 枚举、注入（非破坏 payload + canary 标记）、SSRF 回连（自建监听器拿实锤）、限流探测、竞态复现、mass assignment、开放重定向、CORS 等。每次攻击记录完整请求/响应。
5. **清理现场**：删除 canary 数据与测试账号，停止监听器与服务。
6. 产出三类结论：**已确认**（附动态证据）、**已排除**（静态疑点未复现，从报告中降级或移除）、**无法验证**（注明原因）。

### 阶段 8：风险评估与评分

按 [references/risk-standards.md](references/risk-standards.md)：

1. 把静态、动态与情报发现归入 P0–P3；**动态已验证的发现标记 [已验证]，评级不可下调**；动态未复现的静态疑点标注"未复现"并可降半级。
2. 从攻击面、认证体系、数据保护、依赖健康、运维能力五个维度打分（加权总分 0–100）。
3. 给出总体结论：可上线 / 修复后上线 / 不可上线。

### 阶段 9：结构、优化与性能分析

1. 按 [references/structure-optimization.md](references/structure-optimization.md) 评估项目结构合理性，列出优化条例。
2. 按 [references/performance.md](references/performance.md) 罗列性能问题与优化建议（分析建议，不是漏洞，不与 P 级问题混排）。

### 阶段 10：审查提示词（复核轮）

对高风险模块做第二轮深挖时，直接使用 [references/audit-prompts.md](references/audit-prompts.md) 中的专项审查提示词（12 类，含密码学、竞态、LLM/Agent），逐条代入代码上下文自查，避免第一轮遗漏。

## 快速模式：项目自审查

用户说"自审查 / 自查 / 安全自检 / 发布前检查"而未要求完整审核时，不跑九阶段，走 [references/self-review.md](references/self-review.md) 的快速模式：

1. 运行 `bash scripts/self_check.sh <项目目录>`（密钥扫描 + 依赖审计 + git 卫生 + 调试开关 + 危险部署默认值，输出 PASS/WARN/FAIL 汇总）。
2. `git diff` 筛出自上次发版以来触及 auth/upload/pay/config 的变更，逐文件过四问。
3. 按 A 档人工清单核对，输出轻量报告 `self-review-<日期>.md`。
4. 发现疑似可利用问题**只报告不深挖**，建议触发完整九阶段审核定性。

## 报告格式

最终报告写成 Markdown 文件（默认 `security-audit-report.md`，放在项目根目录或用户指定位置）：

```markdown
# 安全审核报告：<项目名>
- 审核时间 / 审核范围（目录）/ 技术栈 / 是否含动态攻击测试及授权说明
- 总评分：__ / 100（等级：A/B/C/D）
- 总体结论：可上线 / 修复后上线 / 不可上线

## 一、项目概况（结构、暴露面、关键文件）
## 二、近期漏洞情报汇总（搜索日期与来源、组件核对表、评级映射结果）
## 三、漏洞与风险发现（按 P0→P3 排列，已验证项标注 [已验证]）
   每条：[P级] 标题 | 位置(文件:行) 或 接口+请求 | 问题描述 | 利用场景/攻击记录 | 修复建议
## 四、AI 自攻击测试记录
   - 测试环境与授权范围
   - 确认的攻击（技术、接口、请求/响应证据、实际影响）
   - 已排除的静态疑点（未复现项）
   - 未执行项及原因（超红线 / 环境不可用）
## 五、评分明细（五维度得分与依据）
## 六、已检查无异常项（证明覆盖面）
## 七、项目结构评估与优化条例
## 八、性能优化分析
## 九、修复优先级路线图（先修什么、后修什么、预计工作量）+ 后续自审查建议（A/B/C 档节奏）
```

## 严重度定义

| 级别 | 定义 | 示例 |
|---|---|---|
| P0 严重 | 无需特殊条件即可利用，直接导致数据泄露、权限绕过或系统接管 | 硬编码生产密钥、SQL 注入（已验证）、未鉴权的管理接口 |
| P1 高 | 有前置条件但可稳定利用，或泄露影响大 | 水平越权、敏感信息入日志、关闭证书校验 |
| P2 中 | 需特定条件利用或影响有限 | 缺少安全响应头、限流缺失、目录可列表 |
| P3 低 | 加固建议 | 依赖版本偏旧、注释中的内部信息 |

## 参考文件索引

| 文件 | 何时读 |
|---|---|
| [references/server-vulns.md](references/server-vulns.md) | 阶段 3 开始前必读 |
| [references/api-audit.md](references/api-audit.md) | 阶段 4 开始前必读 |
| [references/secrets-hijack.md](references/secrets-hijack.md) | 阶段 2 开始前必读 |
| [references/advanced-risks.md](references/advanced-risks.md) | 阶段 5 开始前必读 |
| [references/vuln-intel.md](references/vuln-intel.md) | 阶段 6 开始前必读 |
| [references/attack-testing.md](references/attack-testing.md) | 阶段 7 开始前必读（授权门+红线） |
| [references/risk-standards.md](references/risk-standards.md) | 阶段 8 开始前必读 |
| [references/structure-optimization.md](references/structure-optimization.md) | 阶段 9 开始前必读 |
| [references/performance.md](references/performance.md) | 阶段 9 开始前必读 |
| [references/audit-prompts.md](references/audit-prompts.md) | 阶段 10 / 高风险模块复核时读取 |
| [references/self-review.md](references/self-review.md) | 快速模式（自审查）时必读 |
| [scripts/scan_secrets.sh](scripts/scan_secrets.sh) | 阶段 2 运行 |
| [scripts/self_check.sh](scripts/self_check.sh) | 快速模式运行 |
