# security-audit 中文说明

当前版本：**alpha1.5**。支持 quick / comprehensive-low / comprehensive-high。
新增持久化审计控制器和可直接调用的 JSON CLI/Python 接口；三档扫描参数、检查队列、
恢复执行、证据验收和报告整理由程序管理。先用 describe/profiles 查看接口与参数，
再按 start → next_action → run_check/record_review → finalize 执行。尚未安装 MCP 服务。
请阅读本目录 SKILL.md；英文规范为执行依据。新增风险优先选档、历史扫描、结构化报告
校验/生成/对比。未复现不减分，缺失项不视为通过，旧 Bash 脚本仅提供有限回退。
