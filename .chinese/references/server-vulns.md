# 服务器与运行环境常见漏洞检查清单

按类别逐项检查。每项发现需记录位置与证据。检查时优先看服务端代码与部署配置，其次看前端。

## 1. 注入类

- **SQL 注入**：搜索字符串拼接 SQL 的位置——`+ sql`、`f"SELECT`、`"SELECT " +`、模板字符串嵌入查询、`query(` 传入拼接串。ORM 的 `raw()`/`queryRaw()` 调用同样要核对参数是否绑定。检查排序/过滤字段名是否白名单（`ORDER BY ${userInput}` 是高频漏洞点）。
- **命令注入**：`exec`、`spawn`(shell:true)、`os.system`、`subprocess(shell=True)`、`Runtime.exec` 的参数是否来自用户输入。
- **代码/模板注入**：`eval`、`Function()`、`pickle.loads`、`yaml.load`(非 safe)、SSTI（用户输入直接进 `render_template_string` / `Template`）。
- **路径穿越**：用户输入拼进文件路径时是否过滤 `../`、是否 `resolve()` 后校验仍在允许目录内。覆盖上传、下载、读取、删除、解压（zip slip）场景。
- **反序列化**：Java（`ObjectInputStream`、Fastjson/Snakeyaml 老版本）、Python pickle、Node `node-serialize`、PHP `unserialize`。
- **XSS**：`innerHTML`/`dangerouslySetInnerHTML`/`v-html` 接收用户数据；富文本是否经消毒（DOMPurify 等）；服务端渲染模板是否转义。
- **XXE**：XML 解析器是否禁用外部实体（`FEATURE_SECURE_PROCESSING`、`resolve-entities=false`）。
- **LDAP / XPath / NoSQL 注入**：`$where`、`$ne` 直接接收用户输入的 Mongo 查询。

## 2. 认证与会话

- 密码存储：是否明文/MD5/SHA1 存储；应使用 bcrypt/argon2/scrypt。
- 会话/Token：JWT 是否校验签名与算法（防 `alg:none`、防混淆 RS256/HS256）、secret 强度；session id 是否登录后重置；Cookie 是否 `HttpOnly`、`Secure`、`SameSite`。
- 登录防爆破：是否有失败锁定、验证码或限流。
- 找回密码：token 是否可预测、是否一次性和限时、重置逻辑是否可越权改他人密码。
- 多用户体系下的"记住我"、API key 轮换、登出后 token 是否真正失效（有无黑名单/短期有效期）。

## 3. 授权与访问控制（服务端）

- 每个接口是否在服务端重复校验权限（前端隐藏 ≠ 鉴权）。
- IDOR：`/api/users/123/orders` 中的 123 是否校验属于当前用户。
- 管理接口是否与业务接口隔离、是否有独立鉴权中间件。
- 未授权即可访问的调试/健康检查/Actuator/Swagger 端点（`/debug`、`/actuator/env`、`/druid`、`/swagger`、`/.git`）。

## 4. 文件处理

- 上传：类型校验是否基于内容（magic bytes）而非仅扩展名/MIME；是否限制大小；存储路径是否不可执行（脱离 web 根、随机文件名）；是否校验重名覆盖。
- 下载：是否存在任意文件读取（路径穿越、绝对路径直接传入）。
- 图片处理库（ImageMagick/Pillow/Sharp）版本是否存在已知 CVE。

## 5. SSRF / CSRF / 劫持相关

- SSRF：服务端发起 HTTP 请求的 URL 是否来自用户输入；是否禁止访问内网网段（127.0.0.1、10/8、172.16/12、192.168/16、169.254.169.254 云元数据）；是否禁止重定向绕过、DNS rebinding。
- CSRF：状态变更接口是否校验 CSRF token 或依赖 SameSite；JSON API 是否校验 Content-Type。
- 点击劫持：是否设置 `X-Frame-Options: DENY` 或 `frame-ancestors` CSP。
- 中间人/劫持：是否强制 HTTPS（HSTS）、是否有降级到 http 的内部调用、WebSocket 是否 wss、外部 CDN/脚本引用是否带 SRI（integrity）。

## 6. 安全响应头与浏览器防护

检查响应头（可从 nginx 配置或框架中间件确认）：

- `Content-Security-Policy`（是否含 `unsafe-inline`/`unsafe-eval`、`*`）
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options`
- `Strict-Transport-Security`
- `Referrer-Policy`
- 错误页是否泄露堆栈、SQL、框架版本；生产是否关闭 debug 模式（`DEBUG=True`、`app.run(debug=True)`、Spring devtools）。

## 7. 部署与基础设施配置

- **Docker**：是否 root 运行、是否挂载 docker.sock、host 网络模式、secrets 是否写进镜像层（ENV/Dockerfile）、基础镜像是否过期。
- **docker-compose**：数据库是否暴露公网端口、默认密码（postgres/postgres、root/root）。
- **nginx**：`autoindex on`、缺少 `deny` 的敏感 location、大 upload 限制缺失、`alias` 目录穿越（alias 末尾斜杠问题）。
- **CI/CD**：workflow 中明文密钥、`pull_request_target` 滥用、第三方 action 未锁版本。
- **权限**：`.git`、`.env`、备份文件（`.sql`、`.bak`、`.zip`）是否部署在 web 可访问目录。
- **CORS**：`Access-Control-Allow-Origin: *` 与 `Allow-Credentials: true` 同时出现（非法组合但常见于误配）；反射 Origin 且允许凭据。

## 8. 依赖与组件

- 检查依赖清单中的高危老版本：`lodash < 4.17.21`、`log4j < 2.17`、`fastjson` 老版本、`openssl` 1.x、`node` < 18 等；能联网则运行 `npm audit --production` / `pip-audit` / `go list -m -u all` 获取确切结果。
- 是否存在未维护的依赖（最后更新 >2 年且有已知问题）。
- 锁文件（lock 文件）是否与清单一致、是否提交进仓库。
