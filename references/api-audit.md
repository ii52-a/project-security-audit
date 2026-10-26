# 项目接口安全审查清单

先枚举全部接口，再对每个接口逐项检查。对每个接口核心回答四个问题：**谁能调？输入校验了吗？输出脱敏了吗？有频率限制吗？**

## 1. 接口枚举（先做）

从以下位置提取完整接口清单，写入报告附录：

- 路由定义（Express `app.get/post`、FastAPI `@router`、Spring `@RequestMapping`、Gin `r.GET` 等）
- RPC/GraphQL schema、WebSocket 事件名、消息队列消费者
- 管理后台接口、内部调试接口、定时任务与 CLI 入口（它们也是"接口"）

清单字段：方法 + 路径 + 处理函数位置 + 鉴权中间件(有/无) + 是否公开暴露。

## 2. 认证（Authentication）

- 接口是否声明了认证要求；有无"漏网"接口（新加路由没挂中间件）。
- Token 从哪来（Header/Cookie/URL 参数）——**URL 传 token 是 P1**（会进日志与 Referer）。
- Token 过期与刷新机制；长期有效的 API key 是否提供轮换手段。

## 3. 鉴权（Authorization / 越权）

- **水平越权（IDOR）**：对象级权限检查——接口按 ID 取资源时，是否校验资源属主。逐个接口核对 `findById(id)` 前有没有 `where userId = currentUser` 之类的约束。
- **垂直越权**：普通用户能否调用管理接口；角色检查是在中间件统一做，还是散落遗漏。
- **功能级**：导出、批量删除、支付改价等高危操作是否有二次校验（幂等 token、签名）。

## 4. 输入处理

- 所有入参（query、body、path、header、文件）是否有 schema 校验（zod/joi/pydantic/class-validator 等），未校验字段是否被直接透传到 ORM/SQL（mass assignment 风险：`req.body` 直接 `update`）。
- 数值边界：分页 size 是否上限（`size=999999999`）、金额是否服务端计算。
- 类型混淆：`Array.isArray` 检查、字符串 vs 对象（`{"$gt": ""}` 型 NoSQL 注入）。
- 富文本/HTML 输入是否消毒。

## 5. 输出处理与信息泄露

- 响应是否返回了多余字段：密码 hash 字段、内部 ID、其他用户的私有字段。检查序列化配置（`toJSON`、serializer、`select *` 后整体返回）。
- 错误响应是否区分"用户不存在"与"密码错误"（枚举辅助）；是否把堆栈/SQL 返回给客户端。
- 分页接口是否允许无限制遍历抓取全量数据。

## 6. 限流与防刷

- 登录、注册、找回密码、短信/邮件发送、支付类接口是否限流（无限流的短信接口 = 防轰炸 = P1）。
- 全局有没有 rate limit 中间件；是否基于 IP+账号双维度；分布式部署下限流是否用 Redis 而非内存。
- 验证码的启用场景与失效时间。

## 7. CORS 与跨域

- 配置来源是硬编码白名单还是通配/反射 Origin；`credentials: true` 时 Origin 必须白名单。
- 是否允许了 `null` Origin（iframe sandbox 场景可利用）。

## 8. 文件上传/下载接口

- 见 server-vulns.md 第 4 节，接口层面额外检查：上传后返回的 URL 域名、下载是否校验签名与有效期（防遍历他人文件）。

## 9. 第三方回调 / Webhook

- 支付回调是否验签（signature/证书），是否信任客户端传来的金额状态。
- 回调是否幂等（重复通知会否重复发货/入账）。

## 10. 接口文档与暴露面

- Swagger/OpenAPI 文档、GraphQL playground、Druid/Actuator 是否在生产暴露。
- OPTIONS/TRACE 等方法是否关闭；HTTP 与 HTTPS 是否同时开放且 http 不跳转。
