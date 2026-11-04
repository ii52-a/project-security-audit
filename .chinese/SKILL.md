# 安全审计技能

当前版本：**alpha1.7**

英文 SKILL.md 为执行规范，本文件为中文阅读手册。

## alpha1.7：优先调用审计控制器

新审计推荐通过 `scripts/audit_control.py` 提交 JSON 请求，流程为：
start 建立任务 → run_pending 批量执行待检查工具 → next_action 获取下一项及请求模板
→ record_review 提交复核 → finalize 生成报告。describe 返回接口，profiles 返回固定参数。
模板自动填入真实候选编号；finding_draft 生成发现草稿，write_evidence 生成证据文件和哈希。
coverage 复核提交 reviewed_files、interfaces 和 interface_inventory_complete，数量由程序计算；
接口数量低于启发式估计时须说明 estimate_difference_reason，未知总数保持 blocked。
progress 轻量查看已存进度，file_inventory 分页读取快照文件清单；二者不验证当前文件变化。
需要验证当前状态时使用 status；执行、提交复核和定稿仍检查内容快照。
这是本地 CLI/Python 工具接口，尚未安装为 MCP 服务，也不调整底层模型推理强度。

状态文件必须放在被审计目录外。任务采用独占锁和原子保存；中断后可继续。
纳入范围的文件内容使用SHA256检测变化，并记录Git HEAD；保留大小和时间戳的修改也会失效。
排除目录及符号链接不跟踪，探测限制为5万文件/1GiB，超限须缩小范围。
已有结果默认复用；retry=true 显式重跑并使候选分诊失效。

| 参数 | quick | comprehensive-low | comprehensive-high |
|---|---|---|---|
| 工作目标 | 15分钟 | 180分钟 | 300分钟 |
| 密钥扫描单文件上限 | 1 MiB | 2 MiB | 5 MiB |
| 密钥/配置检查超时 | 60秒 | 180秒 | 600秒 |
| Git历史提交上限 | 20 | 200 | 1000 |
| 历史扫描超时 | 30秒 | 60秒 | 180秒 |
| 历史输出上限 | 5 MB | 20 MB | 50 MB |
| 单条依赖命令超时 | 60秒 | 120秒 | 300秒 |
| 工具适配输出上限 | 10 MB | 25 MB | 60 MB |
| 清单探测目录深度（根为0） | 2 | 4 | 8 |
| npm开发依赖 | 不包含 | 包含 | 包含 |
| 代码审查轮次 | 1 | 1 | 2 |
| 人工/AI分析范围 | 改动的敏感路径 | 已识别接口及高风险调用链 | 全部关键边界、权限矩阵、替代假设二次复核 |

quick 禁止动态攻击；low/high 仅可另外在授权、隔离条件下开展。控制器本身不发起动态攻击。
high 必须提交 H1–H8；不适用须说明理由。不能按次数凑验证，也不静默降档。
各档依然使用扫描器的排除规则；清单探测深度不等于密钥扫描目录深度。

工具结果分为执行状态和发现状态，避免将“执行成功”当成“安全通过”。
缺失条件可 skip_check 并注明原因；报告保留限制。依赖工具联网需要 allow_network=true，
沿用已有用户授权，不要求每次重新询问。证据仍须脱敏；工具无法自动证明业务判断正确。
finalize 自动组装报告，但始终保留“需要人工复核”，不自动批准发布。
详细接口、字段和限制见英文 references/controller.md。

## 深度选择

- quick：发布前快速安全检查，目标不超过15分钟，不执行动态攻击。
- comprehensive-low：针对相关风险的全面审计，目标3小时内。
- comprehensive-high：逐项验证适用的 H1–H8，目标5小时内。

时间为规划目标。用户已明确选择时不重复询问；模糊请求先探测、建议并询问一次。
无人应答时默认 low 并说明。认证、支付、多租户、敏感数据、跨服务、LLM工具调用
用于风险判断；代码规模用于估算工作量，不强制升级。不得静默改变明确选择。

H1接口授权；H2跨边界信任；H3竞态/业务/LLM验证；H4依赖情报；H5二次复核；
H6覆盖与证据索引；H7部署供应链；H8报告一致性。每项必须提供完成证据或不适用理由；
H6/H8始终适用。未完成适用项即不能宣称已达到 high，不再按数量凑项。

## 执行与结论

静态检查只读。动态验证须已有明确授权、隔离环境、无生产数据和账号；不自动攻击。
记录计划、证据、结果和清理。未复现不代表排除，也不自动减分。
严重程度、证据状态、置信度、覆盖率分开记录。评分可选；缺失覆盖不可直接认定可发布。
结构与性能分析按需启用。敏感值完整脱敏，原始输出不写入报告，报告不自动提交。

## 工具

audit_depth.py：--risk 可重复声明风险；--high-status 检查高级审计记录。
scan_secrets.py：默认脱敏、记录排除项，baseline 必须匹配指纹。
audit_history.py：配置提交数量、超时及输出上限，仅扫描 HEAD 祖先的补丁新增文本。
self_check.py：严格模式退出0=无告警，1=FAIL，2=检查不完整或WARN。
audit_report.py：校验JSON、生成Markdown、对比前后报告；消失项待复核，不自动视为修复。

assets/提供快速和全面模板；references/report-format.md定义结构。模板需补全后才能通过。
Python 3.9+为维护实现，Bash为旧版有限回退，不具备本版全部功能。
修改后运行 unittest 与 audit_doctor.py；工具无法证明证据真实性，交付前必须复核。

## alpha1.7 证据与候选闭环

自动候选使用按来源位置确定的C-ID；移动代码行后不保证编号不变。triage.dispositions必须逐候选填写，confirmed必须关联
finding_id且该发现状态为confirmed；manual-review自动留在JSON与Markdown待复核列表。
resolved必须关联状态为resolved的发现，并提交retest：method、expected、observed、evidence及passed=true。
复测字段记录审阅后的证据，控制器不会自动证明修复有效。
旧版按检查名称分诊的格式不再接受。定稿时重新校验关联，不能用空findings隐藏已确认问题。

High的每个done项必须提供evidence对象：artifact、sha256、summary、items。
证据文件放在状态文件所在目录下，格式为对应H编号到items数组的JSON映射；控制器验证
文件路径、SHA256和具体条目一致。可调用write_evidence免去手工生成文件与计算哈希；
当前接口见references/controller-v17.md，H项字段表保留在references/controller-v16.md。
second-pass还须提交analysis数组：target、alternative_hypothesis、observation。
结构校验和文件哈希不能证明判断真实性，仍需认真复核证据。

扫描结果新增coverage：跳过内容或扫描零文件时为partial；报告列出跳过的路径和原因。
依赖响应结构异常返回未知；Python debug采用AST避免注释/文档字符串误报；Compose
支持块状映射和列表写法，复杂语法返回告警。密码规则支持同行多次命中及带BOM的UTF16/32。
中低危依赖通告同样进入候选；异常Go流和cargo计数矛盾返回未知。.github/.gitlab纳入扫描，
历史命中包含列号以区分同行重复值。支持带引号的Compose环境键及config["DEBUG"]赋值。
本版需新建alpha1.7状态，不静默迁移旧状态。三档扫描预算不变，low/high依赖检查包含开发依赖。
