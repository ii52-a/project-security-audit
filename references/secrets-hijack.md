# 密钥泄露、硬编码与劫持风险检查清单

## 1. 硬编码密钥扫描

先运行 `bash scripts/scan_secrets.sh <目录>` 获得候选点，再人工逐条确认。脚本扫不到的模式要人工补查：

- 日志语句中打印的密码/token（`console.log(password)`、`logger.info(token)`）
- 前端打包产物/源码里的内网 IP、内部域名、接口密钥（搜索 `192.168.`、`10.`、`internal.`、`api-key`）
- 移动端配置（`AndroidManifest`、`Info.plist`）中的第三方 SDK key
- 错误处理中把连接串带进异常消息

## 2. 高危硬编码模式（按此核对扫描结果）

| 类别 | 典型模式 |
|---|---|
| 云厂商 AK/SK | `AKIA[A-Z0-9]{16}`（AWS）、`LTAI`（阿里云）、`AKLT`（火山） |
| 私钥文件内容 | `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----` |
| 数据库连接串 | `mysql://user:pass@`、`postgres://`、`mongodb://`、`redis://`（带密码的） |
| JWT/签名 secret | `secret`、`jwt_key`、`signing_key` 赋值为字面量 |
| 邮件/短信凭据 | `smtp` 密码、`Authorization: Basic`、Twilio/SendGrid key |
| OAuth client secret | `client_secret` 字面量 |
| 支付密钥 | 微信 `mch_key`、支付宝私钥、Stripe `sk_live_/sk_test_` |
| 弱默认口令 | `password = "123456"`、`root/root`、`admin/admin`、默认 token |

**判定规则**：出现在源码/配置且指向生产环境（域名、live key）→ P0；测试环境占位符 → P2 提醒；仅存在于示例文档 → 忽略但备注。

## 3. 密钥管理实践检查

- 是否使用环境变量/密钥管理服务（Vault、KMS、云函数环境变量）；`.env` 是否在 `.gitignore`。
- 是否提供 `.env.example`（不含真值）。
- git 历史深挖：`git log --all --diff-filter=A -- '*.env' '*.pem' '*.key' '*.p12'`，以及全量 `git log -p -S '<疑似密钥片段>'`。**已提交过即视为泄露，需轮换，仅删除文件不算修复**（写入报告 P0/P1）。
- 密钥是否有失效/轮换机制说明；同一个密钥是否复用在多环境。
- 前端项目中"环境变量"是否经打包进产物（`NEXT_PUBLIC_`、`VITE_` 前缀变量是公开的，放 secret 即 P0）。

## 4. 密码与凭据安全

- 明文密码出现在配置、日志、错误消息、数据库初始数据（seed 文件里的真实用户密码）。
- 密码策略：最小长度、复杂度、是否禁止常见密码；默认账号是否强制改密。
- 内部系统间调用的服务凭据：是否共享一个万能账号、是否写死在代码里。

## 5. 劫持类风险

- **会话劫持**：Cookie 缺 `HttpOnly`/`Secure`（XSS 可偷 session）；token 进 URL；登录后不重置 session id（session fixation）。
- **点击劫持**：缺 `X-Frame-Options` / CSP `frame-ancestors`（尤其管理后台与支付页）。
- **DNS/CDN 劫持面**：是否强制 HTTPS 与 HSTS（缺 HSTS 的登录页在 http 下可被劫持）；第三方 JS 资源（统计、SDK、CDN）是否带 `integrity` SRI 或自托管；DNS TTL 与域名解析是否用了不受信的公共解析做内部服务发现。
- **中间人**：代码里是否有 `http://` 内部调用、`rejectUnauthorized: false` / `verify=False` / `InsecureSkipVerify: true` 关闭证书校验（每处都是 P1）。
- **供应链劫持**：依赖是否锁版本与哈希（lock 文件提交）、`postinstall` 脚本是否来自不常见包、镜像源是否为官方/可信私有源。
- **账号劫持**：改邮箱/手机是否需要验证旧凭据；找回密码 token 的熵与时效；OAuth 回调 redirect_uri 是否校验（开放重定向可劫持授权码）。
- **开放重定向**：`redirect(参数)` 未白名单校验（`next=`、`returnUrl=`），配合钓鱼与 OAuth 劫持。
