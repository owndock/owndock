# API 契约

本目录只存放 API 契约源文件和生成配置，不放业务实现。[`openapi.yaml`](./openapi.yaml) 是 OpenAPI 3.0.3 发布前契约。当前所有正式 operation 都是 pre-release：可以用于前后端联调，但在首个稳定版本前仍可能通过受控迁移调整。

## 契约规则

1. 先定义资源、用例、权限和错误语义，再修改 OpenAPI；
2. transport DTO、领域模型和 MongoDB BSON 模型保持独立；
3. 不兼容变更进入新的路径主版本，兼容字段扩展经过契约测试；
4. `make api-validate` 使用固定版本 oasdiff 严格校验；
5. `internal/server` 契约测试用真实 Handler 响应对照 OpenAPI；
6. CI 使用目标分支契约执行 breaking-change 检测。

当前使用手写 HTTP DTO，不从 OpenAPI 生成服务代码。只有出现正式 SDK、多语言客户端或 gRPC 契约需求时才评估生成工具，避免生成层反向控制领域模型。

Agent 长连接使用独立 mTLS 端口和 NDJSON full-duplex 协议，不属于浏览器 REST API；协议见 [Agent Control Protocol v1](agent-control.md)，产品版本与协议版本的兼容/升级边界见[Agent 与 Server 版本兼容策略](../docs/agent-compatibility.md)。

## 通用行为

- 业务路径使用 `/api/v1`；`/livez`、`/readyz` 和 `/metrics` 是运维端点；
- 每个请求接受或生成 `X-Request-ID`，响应会返回该 header；
- JSON 写接口使用 `application/json`，请求体最大 1 MiB，拒绝未知字段和多个连续 JSON 值；
- 错误 `code` 供客户端稳定分支判断，`message` 只包含可安全公开的信息；
- 除明确标注的 bootstrap、login 和 Agent enrollment exchange 外，正式业务接口使用 Bearer session；
- Organization、Project 和资源所有权在后端校验，客户端提供的 ID 不能绕过范围限制。
- 正式产品路由统一经过 MongoDB 共享的来源/实例两级入口限流；超过阈值返回 `429 rate_limited` 和 `Retry-After`，保护存储不可用时返回 `503 ingress_protection_unavailable`。反向代理来源识别规则见[产品 API 入口保护](../docs/ingress-protection.md)。
- `/api/` 响应统一使用 `Cache-Control: no-store`。REST 身份只接受显式 Bearer Header，不读取用户 Session Cookie，也不启用 credentialed CORS；跨域浏览器只允许配置中的精确 HTTPS Origin。本地开发允许 loopback HTTP，详细规则见[浏览器接入 API](../docs/browser-api-security.md)。
- API 的稳定 `error.code` 是多语言客户端的分支契约。后端按 `Accept-Language` 生成 `zh-CN` 或 `en-US` 安全文案，并通过 `Content-Language` 标明实际语言；缺失、无效或不支持的语言回退到 `en-US`。Web、CLI 和 SDK 都不应按 `message` 文本分支，详见[多语言与本地化](../docs/localization.md)。

统一错误结构：

```json
{
  "error": {
    "code": "invalid_json",
    "message": "request body must be valid JSON",
    "request_id": "a1b2c3"
  }
}
```

## 当前正式产品 API

正式路由由 `product.enabled` 控制，并要求 MongoDB 同时启用。

| 领域 | 方法与路径 | 当前能力 |
| --- | --- | --- |
| Meta | `GET /api/v1/meta/version` | 查询服务版本、提交和构建时间 |
| Identity | `POST /api/v1/auth/bootstrap` | 使用环境 bootstrap token 创建首个 Organization、Owner 和 Session |
| Identity | `POST /api/v1/auth/login` | 创建本地 Bearer Session；账号尝试超过共享阈值时返回 `429` 与 `Retry-After` |
| Identity | `GET /api/v1/auth/me`、`POST /api/v1/auth/logout` | 查询当前身份或注销 Session |
| Identity | `GET /api/v1/auth/sessions`、`DELETE /api/v1/auth/sessions/{session_id}` | 查询当前用户的活跃 Session，或撤销一个属于自己的 Session |
| Identity | `GET/DELETE /api/v1/auth/users/{user_id}/sessions` | Owner 查询同 Organization 用户的安全会话摘要，或紧急撤销该用户全部 Session |
| Identity | `DELETE /api/v1/auth/users/{user_id}/sessions/{session_id}` | Owner 撤销同 Organization 用户的一个 Session；不能撤销当前 Owner Session |
| Managed Host | `GET/POST /api/v1/managed-hosts` | 查询或登记 Organization 主机 |
| Managed Host | `GET /api/v1/managed-hosts/{managed_host_id}` | 查询 Host、连接模式和当前 Agent 身份摘要 |
| Managed Host | `POST /api/v1/managed-hosts/{managed_host_id}:disable` | 禁用 Host、吊销数据库身份并使未用 enrollment 失效 |
| Agent enrollment | `POST /api/v1/managed-hosts/{managed_host_id}/enrollments` | Owner 创建只显示一次的短时 enrollment token |
| Agent enrollment | `POST /api/v1/agent/enrollments:exchange` | Agent 使用 token 和本地 CSR 兑换 mTLS 客户端证书；不使用用户 Session |
| Project | `GET/POST /api/v1/projects` | 查询或创建 Organization 下的 Project |
| Template | `GET /api/v1/templates`、`GET /api/v1/templates/{template_id}` | 查询无秘密、不可变版本的社区内置 Application 预设 |
| Application | `GET/POST /api/v1/projects/{project_id}/applications` | 查询或创建 Project Application；可选复制 Template 快照 |
| Release | `GET/POST /api/v1/projects/{project_id}/applications/{application_id}/releases` | 查询或创建固定 OCI digest 与运行规格的不可变 Release |
| Registry | `GET/POST /api/v1/projects/{project_id}/registry-credentials` | 管理显式 `anonymous/basic` Registry 连接；Basic 只保存外部秘密引用，响应只返回 `password_configured` |
| Source Repository | `GET/POST /api/v1/projects/{project_id}/repository-credentials` | 管理 Git 读取凭据元数据；响应不回读 `secret_ref` |
| Source Repository | `GET/POST /api/v1/projects/{project_id}/source-repositories` | 管理不含凭据的 HTTPS/SSH 仓库连接；创建不触发 Git 或 Build |
| Source Repository | `GET /api/v1/projects/{project_id}/source-repositories/{source_repository_id}` | 查询仓库协议、默认分支、Host Key 和安全连接状态 |
| Source Repository | `POST /api/v1/projects/{project_id}/source-repositories/{source_repository_id}/probe` | 单次解析外部凭据，只读验证远端仓库、默认分支和 TLS/SSH 主机身份 |
| Build Configuration | `GET/POST /api/v1/projects/{project_id}/applications/{application_id}/build-configurations` | 查询或创建受约束、版本化的 Dockerfile 构建配方；可由 Maintainer/Owner 配置 development 自动部署，但不立即启动 Build |
| Build Configuration | `GET/PATCH /api/v1/projects/{project_id}/applications/{application_id}/build-configurations/{build_configuration_id}` | 查询或按 `expected_version` 修改配方，防止并发覆盖 |
| Build | `GET/POST /api/v1/projects/{project_id}/builds`、`POST .../builds/{build_id}:cancel|:retry` | 查询或幂等创建 Build，协作取消非终态 Build，或从 failed Build 的不可变快照创建重试 |
| Build | `GET /api/v1/projects/{project_id}/builds/{build_id}` | 查询不可变源码身份、触发来源和构建配置快照 |
| Build | `GET /api/v1/projects/{project_id}/builds/{build_id}/logs` | 使用 Build 绑定的 opaque cursor 增量读取有界、TTL、已脱敏日志；响应明确 complete/truncated |
| Artifact | `GET /api/v1/projects/{project_id}/artifacts`、`GET .../artifacts/{artifact_id}` | 查询按 OCI digest 固定的 OwnDock Build 或外部 CI 镜像、生产者信任标记和 Release 交接状态 |
| Artifact | `POST /api/v1/projects/{project_id}/artifacts` | Developer 以上用 `Idempotency-Key` 登记外部 CI 的精确 digest；Server 先验证 Registry manifest，再原子创建 Evidence Jobs 与审计 |
| Artifact Evidence | `GET .../artifacts/{artifact_id}/evidence`、`GET .../evidence/{evidence_id}` | 查询绑定镜像 digest 的 SBOM、Provenance、签名或漏洞报告有界索引 |
| Artifact Evidence | `GET .../evidence/{evidence_id}:download` | 授权读取 OCI 证据正文；返回前校验 manifest、subject、媒体类型、大小、layer digest 和已支持的文档结构 |
| Artifact | `POST /api/v1/projects/{project_id}/artifacts/{artifact_id}:create-release` | 从 Artifact 幂等创建不可变 Release；可提供运行规格 |
| Build Trigger | `GET/POST /api/v1/projects/{project_id}/applications/{application_id}/build-configurations/{build_configuration_id}/triggers` | Owner/Maintainer 查询安全元数据或创建一次显示、只存哈希的自动化 Token |
| Build Trigger | `POST /api/v1/projects/{project_id}/applications/{application_id}/build-configurations/{build_configuration_id}/triggers/{build_trigger_id}:revoke` | 永久撤销自动化 Token |
| Build Trigger | `POST /api/v1/build-triggers/{build_trigger_id}` | 任意 Git 平台以专用 Bearer Token、完整 ref/Commit 和 `Idempotency-Key` 触发 queued Build |
| Build Hook | `GET/POST /api/v1/projects/{project_id}/applications/{application_id}/build-configurations/{build_configuration_id}/hooks` | Owner/Maintainer 查询安全元数据或创建 GitHub/GitLab/Gitea/Forgejo 签名 Webhook |
| Build Hook | `POST /api/v1/projects/{project_id}/applications/{application_id}/build-configurations/{build_configuration_id}/hooks/{build_hook_id}:revoke` | 永久撤销平台 Webhook |
| Build Hook | `POST /api/v1/build-hooks/{provider}/{build_hook_id}` | 先验签后解析平台 Push，按 delivery 去重并返回 `202 accepted/ignored` |
| Environment | `GET/POST /api/v1/projects/{project_id}/environments` | 写入逻辑环境的普通配置或 `secret://` 引用；响应只返回 `variable_keys` |
| Runtime Target | `GET/POST /api/v1/projects/{project_id}/runtime-targets` | 管理绑定同 Organization Host 的 `direct/agent` 运行目标 |
| Runtime Target | `POST /api/v1/projects/{project_id}/runtime-targets/{runtime_target_id}/probe` | 显式探测 direct Docker 目标并保存安全状态 |
| Runtime Inventory | `GET /api/v1/projects/{project_id}/runtime-inventory` | 查询经成功 Deployment 核验的 Project 受管容器安全视图 |
| Runtime Inventory | `GET /api/v1/managed-hosts/{managed_host_id}/runtime-inventory` | Owner/Maintainer 查询 Host 的四类安全资源，包括未受管资源 |
| Terminal Policy | `GET/PUT /api/v1/terminal-policy` | Owner 查询或保存 Organization 主机终端策略 |
| Terminal Policy | `GET/PUT /api/v1/projects/{project_id}/terminal-policy` | 查询或保存 Project 容器终端策略 |
| Terminal Session | `POST /api/v1/projects/{project_id}/terminal-sessions/container` | 只用 Deployment ID 请求当前受管容器会话 |
| Terminal Session | `POST /api/v1/managed-hosts/{managed_host_id}/terminal-sessions` | 请求固定 Managed Host 会话 |
| Terminal Session | `GET /api/v1/terminal-sessions/{session_id}`、`POST .../{session_id}:terminate` | 查询安全元数据或幂等终止会话 |
| Deployment | `GET/POST /api/v1/projects/{project_id}/deployments` | 查询或手动创建不可变 Deployment；响应以 `trigger_source` 和来源字段区分自动交付链路 |
| Deployment | `GET /api/v1/projects/{project_id}/deployments/{deployment_id}` | 查询 Deployment 状态 |
| Deployment | `POST /api/v1/projects/{project_id}/deployments/{deployment_id}/cancel` | 请求取消进行中的 Deployment |
| Deployment | `POST /api/v1/projects/{project_id}/deployments/{deployment_id}/retry` | 将失败 Deployment 重试为一个新操作 |
| Deployment | `POST /api/v1/projects/{project_id}/deployments/{deployment_id}/rollback` | 使用此前成功 Release 创建一个新回滚操作 |
| Audit | `GET /api/v1/audit-events` | 查询当前 Organization 或指定 Project 的安全审计元数据 |

该切片已具备内置 RBAC、范围校验、MongoDB Repository、事务审计和契约测试。社区版 Template 是无秘密的只读内置目录，Application 创建时只复制快照，不产生继承或自动同步；详见[Template 使用说明](../docs/templates.md)。Source Repository 支持受限 probe，但 API Server 不 checkout 源码；Build Configuration 保存受约束的版本化配方、Release 运行规格和可选 development 自动部署目标，路径、精确 ref、Registry 域名、平台、资源上限、环境阶段和 Project 所有权都在服务端验证。自动规则只有 Maintainer/Owner 可修改，staging/production 首版强制人工触发。手动、通用 Trigger Token 与平台 Webhook 都只读验证允许 ref、固定完整 Commit SHA、复制配置快照并创建 queued 记录。Trigger Token 固定配置范围，只显示一次且只存哈希；平台 Webhook 先对原始 body 验签，再按 delivery 长期去重。两类外部入口都不能覆盖仓库或构建目标。Build 状态机、取消/重试 API、Mongo 原子 claim、heartbeat、generation fence 和失联接管已经完成；lease 内部信息不回读。独立 Build Worker 已实现固定 Git 的 HTTPS/SSH 精确 Commit 检出、rootless BuildKit 构建和认证 Registry push；真实 digest 只在 fence 有效时形成 Artifact，Build 与 Artifact 原子提交，Release/自动 Deployment 失败只重试幂等交接而不重新构建。Build 日志已按序号、TTL 和容量上限保存，并在写入前流式脱敏；Viewer 以上可用 Build 绑定 cursor 增量读取。其客户规则见 [仓库说明](../docs/source-repositories.md)、[构建配方说明](../docs/build-configurations.md)、[Build 状态与重试](../docs/builds.md)、[Build 日志](../docs/build-logs.md)、[Artifact 与 Release](../docs/artifacts.md)、[自动部署规则](../docs/automatic-deployments.md)、[Build Worker](../docs/build-worker.md)、[Trigger Token](../docs/build-triggers.md)与[平台 Webhook](../docs/webhooks.md)。Runtime Inventory 只接受固定 Kind、Runtime Target、absent 开关、最大 200 条的页大小和不透明游标；未知或重复参数会被拒绝，不能提交 Docker endpoint、对象 ID 或任意 filter。direct/agent Docker Gateway 和受管 Worker 已实现但默认关闭；Agent 自动首次身份接入、双端 mTLS 连接/版本/心跳、类型化 probe/部署/Inventory 传输、抖动退避重连、本机 Docker 执行、secret-safe 结果缓存、持久切换水位和可恢复证书轮换已实现。Agent Server 与 Worker 同时启用时，Agent probe 和 Deployment Gateway 配套注册；enrollment 与证书轮换已有真实进程响应丢失/重启恢复证据，多主机生产系统验收仍未完成。密码恢复和 OIDC 尚未加入公开契约。

TerminalSession 控制面、同域 WSS、direct/Agent 容器 Docker exec 和主机 PTY/SSH Gateway 已加入公开契约。终端票据只通过短时、限定 connect path 的 Secure HttpOnly Cookie 下发，不进入 JSON 或 URL；真实远程主机与浏览器验收完成前仍按 pre-release 管理，详见[安全终端会话](../docs/terminal-sessions.md)和[容器与主机终端用户旅程](../docs/terminal-user-journey.md)。

凭据正文不通过资源 API 保存：Git、Runtime、Registry、Environment Secret 与 Agent CA 都由受约束的外部秘密来源提供。公开响应也不回传 `secret://` 引用：Registry/Runtime Target 只显示是否配置，Environment 只显示变量名。

## 默认关闭的工程样例

`development.enable_engineering_samples` 控制顶层 `/api/v1/applications`、`/api/v1/environments` 和 `/api/v1/deployments`。这些路由使用进程内存仓储、没有认证授权，只能在隔离的本地开发环境验证架构和错误模型，不是正式产品 API，也不能作为 Project 范围接口的兼容入口。

新增功能不得继续扩展工程样例；应直接进入有所有权、授权、持久化和审计的正式领域契约。
