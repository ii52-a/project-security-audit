# 进阶风险扫描清单

常规清单（server-vulns/api-audit）之外的深度维度。逐节检查；其中标 ★ 的高危项若静态存疑，自动进入阶段 7 攻击假设清单（attack-testing.md 第 2 节）。

## 1. 密码学误用

- 弱算法：MD5/SHA1 用于密码或签名校验；DES/3DES/RC4；AES-ECB 模式（相同明文块产出相同密文，可被分组分析）。
- IV/nonce 复用：硬编码 IV、每次加密用同一 nonce（GCM 下复用 nonce = 密钥等价泄露）★。
- 弱随机源：`Math.random()` / `random.random()` / `rand()` 用于生成 token、验证码、订单号、重置链接（可预测 → 会话伪造/遍历）★。
- 时序比较：用 `==`/`equals` 比较签名、HMAC、密码摘要（应 constant-time 比较：`crypto.timingSafeEqual`、`hmac.compare_digest`）。
- 密码哈希：无盐或全局固定盐；bcrypt cost < 10；自创哈希方案。
- JWT：接受多种算法由 header 决定（算法混淆）；未校验 exp/nbf；secret 同时用于其他用途。

## 2. 竞态与并发缺陷

- TOCTOU：先检查后使用——`exists()` 再 `open()`、先查余额再扣减、先查重再插入，中间无锁 ★。
- 双花/超发：优惠券领取、库存扣减、积分转账是"读-改-写"而非原子操作（无 `UPDATE ... WHERE stock>0`、无乐观锁版本号）★。
- 幂等缺失：支付回调、MQ 消费者重复投递会重复入账/发货（无唯一业务约束或去重表）。
- 锁的粒度：分布式部署下用进程内锁/内存 Map 保护共享资源（多实例间失效）。
- 长事务持有锁期间做外部调用（HTTP/发消息），放大竞态窗口。

## 3. LLM / AI 应用特有风险

- 系统提示泄露：应用把内部规则、凭据、内部接口写进 system prompt，可被诱导输出 ★。
- 提示注入：直接注入（用户输入覆盖指令）；**间接注入**——指令藏在 RAG 检索的文档、上传文件、网页内容、邮件里被模型当作指令执行 ★。
- 过度授权（excessive agency）：LLM 输出直接触发删除、群发、支付、SQL 等高危工具且无人工确认、无白名单 ★。验证时只在 mock/dry-run/一次性测试租户上执行，禁止真实删除、群发、支付。
- 输出未消毒即执行：模型生成的代码 `eval`、生成的 SQL 直接查询、生成的 shell 直接执行。
- 数据外带：用户 PII / 内部文档进 prompt 发往第三方模型 API（合规与泄露双重风险）。
- 资源耗尽：无每用户 token/调用上限（成本型 DoS）。
- RAG 知识源可被普通用户写入 → 投毒影响所有用户的回答。
- Agent 工具作用域：文件/浏览器/HTTP 工具无路径与网段限制，注入即可变 SSRF/任意读。

## 4. GraphQL / BFF

- 生产开放 introspection 与 field suggestion（错误信息反推 schema）。
- 无 query depth/complexity 限制（深层嵌套一次查询拖垮库）。
- 字段级授权缺失：type resolver 只在顶层鉴权，敏感字段（如 `user { email salary }`）任何登录者可查 ★。
- batching 滥用：单请求打包多个 mutation 绕过限流。

## 5. WebSocket / 实时通道

- 握手不校验 Origin（任意页面可连）★；连接建立后消息级无鉴权——连上即可订阅任意 userId/roomId 事件 ★。
- 无消息大小与发送频率限制；广播消息包含不应下发给该频道的敏感字段。
- 断线重连票据长期有效。

## 6. 微服务内部信任

- "内网可信"假设：服务间调用零认证，任一实例被攻破即横向通行 ★。
- 身份透传可伪造：网关鉴权后把 `X-User-Id` 头裸传后端，后端不重验（直连后端端口即可冒充任意用户）★。
- MQ 无发布/消费鉴权，任意能连队列的进程可注入消息。
- 调试端点（pprof、metrics、actuator）绑 0.0.0.0。

## 7. 云与 IAM

- 对象存储桶公开可读写；预签名 URL 有效期过长（>1h）且可猜路径。
- 角色/策略过权：`Action: "*"`、`Resource: "*"`，单服务泄露即接管账号 ★。
- 安全组/NACL 放行 `0.0.0.0/0` 到数据库、Redis、MQ、管理端口。
- 函数超时/内存与并发无限制（账单型滥用）；事件触发器无来源校验。

## 8. 前端深水区

- `postMessage` 监听方不校验 `event.origin`，收到消息即执行操作 ★；发送方把敏感数据 post 给 `*`。
- token 存 localStorage/sessionStorage（XSS 即失窃；HttpOnly Cookie 更稳）★。
- `window.open`/外链无 `rel="noopener"`（反向 tabnabbing）。
- source map（`.map`）部署到生产；错误上报（Sentry 等）把全量 state/表单值发出去。
- Service Worker 作用域过宽，且缓存更新策略缺失（被劫持内容长期驻留）。

## 9. 移动端（如适用）

- `strings.xml` / `Info.plist` / 打包资源里的第三方 key；日志开关在 release 未关。
- `allowBackup="true"`、`debuggable="true"` 出现在发布配置。
- TLS 校验残留关闭代码（TrustAllCerts / NSAllowsArbitraryLoads）★。
- Deeplink / URL scheme 未校验来源，可直达支付确认或 OAuth 回调页 ★。

## 10. 供应链投毒

- 依赖名与知名包差一两个字母（typosquatting）；同名不同 registry。
- `postinstall`/`preinstall` 脚本内容未审（拉远程脚本执行）。
- GitHub Actions：第三方 action 未 pin commit hash；`pull_request_target` 配合 fork 内容执行；secrets 泄给 fork PR。
- git hooks / husky / prepare 脚本下载并执行外部二进制。
- 私有镜像/代理源指向不明域名；`.npmrc`/`pip.conf` 里的 token 已提交。

## 输出要求

- 每节给出"检查了什么、结论"，无异常也要留痕。
- ★ 项的疑似发现写明证据位置，并显式加一句"→ 已进入攻击假设 ATK-xx"（编号在阶段 7 分配）。
