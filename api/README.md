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

Agent 长连接使用独立 mTLS 端口和 NDJSON full-duplex 协议，不属于浏览器 REST API；协议见 [Agent Control Protocol v1](agent-control.md)。

## 通用行为

- 业务路径使用 `/api/v1`；`/livez`、`/readyz` 和 `/metrics` 是运维端点；
- 每个请求接受或生成 `X-Request-ID`，响应会返回该 header；
- JSON 写接口使用 `application/json`，请求体最大 1 MiB，拒绝未知字段和多个连续 JSON 值；
- 错误 `code` 供客户端稳定分支判断，`message` 只包含可安全公开的信息；
- 除明确标注的 bootstrap、login 和 Agent enrollment exchange 外，正式业务接口使用 Bearer session；
- Organization、Project 和资源所有权在后端校验，客户端提供的 ID 不能绕过范围限制。

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
| Identity | `POST /api/v1/auth/login` | 创建本地 Bearer Session |
| Identity | `GET /api/v1/auth/me`、`POST /api/v1/auth/logout` | 查询当前身份或注销 Session |
| Managed Host | `GET/POST /api/v1/managed-hosts` | 查询或登记 Organization 主机 |
| Managed Host | `GET /api/v1/managed-hosts/{managed_host_id}` | 查询 Host、连接模式和当前 Agent 身份摘要 |
| Managed Host | `POST /api/v1/managed-hosts/{managed_host_id}:disable` | 禁用 Host、吊销数据库身份并使未用 enrollment 失效 |
| Agent enrollment | `POST /api/v1/managed-hosts/{managed_host_id}/enrollments` | Owner 创建只显示一次的短时 enrollment token |
| Agent enrollment | `POST /api/v1/agent/enrollments:exchange` | Agent 使用 token 和本地 CSR 兑换 mTLS 客户端证书；不使用用户 Session |
| Project | `GET/POST /api/v1/projects` | 查询或创建 Organization 下的 Project |
| Application | `GET/POST /api/v1/projects/{project_id}/applications` | 查询或创建 Project Application |
| Release | `GET/POST /api/v1/projects/{project_id}/applications/{application_id}/releases` | 查询或创建固定 OCI digest 与运行规格的不可变 Release |
| Registry | `GET/POST /api/v1/projects/{project_id}/registry-credentials` | 管理引用外部秘密的 Registry Credential 元数据 |
| Environment | `GET/POST /api/v1/projects/{project_id}/environments` | 管理逻辑环境及普通配置值或 `secret://` 引用 |
| Runtime Target | `GET/POST /api/v1/projects/{project_id}/runtime-targets` | 管理绑定同 Organization Host 的 `direct/agent` 运行目标 |
| Runtime Target | `POST /api/v1/projects/{project_id}/runtime-targets/{runtime_target_id}/probe` | 显式探测 direct Docker 目标并保存安全状态 |
| Deployment | `GET/POST /api/v1/projects/{project_id}/deployments` | 查询或创建不可变 Deployment 操作 |
| Deployment | `GET /api/v1/projects/{project_id}/deployments/{deployment_id}` | 查询 Deployment 状态 |
| Deployment | `POST /api/v1/projects/{project_id}/deployments/{deployment_id}/cancel` | 请求取消进行中的 Deployment |
| Deployment | `POST /api/v1/projects/{project_id}/deployments/{deployment_id}/retry` | 将失败 Deployment 重试为一个新操作 |
| Deployment | `POST /api/v1/projects/{project_id}/deployments/{deployment_id}/rollback` | 使用此前成功 Release 创建一个新回滚操作 |
| Audit | `GET /api/v1/audit-events` | 查询当前 Organization 或指定 Project 的安全审计元数据 |

该切片已具备内置 RBAC、范围校验、MongoDB Repository、事务审计和契约测试。direct Docker Gateway 和受管 Deployment Worker 已实现但默认关闭；Agent 首次身份接入以及 Server 端 mTLS 连接/版本/心跳和 `runtime.probe` 类型化传输已实现，Agent 进程、实际命令执行器和 Agent Runtime Gateway 尚未实现。Template、Git-to-Deploy、Terminal 和用户管理 API 尚未加入公开契约。

凭据正文不通过资源 API 保存：Runtime、Registry、Environment Secret 与 Agent CA 都由受约束的外部秘密来源提供。

## 默认关闭的工程样例

`development.enable_engineering_samples` 控制顶层 `/api/v1/applications`、`/api/v1/environments` 和 `/api/v1/deployments`。这些路由使用进程内存仓储、没有认证授权，只能在隔离的本地开发环境验证架构和错误模型，不是正式产品 API，也不能作为 Project 范围接口的兼容入口。

新增功能不得继续扩展工程样例；应直接进入有所有权、授权、持久化和审计的正式领域契约。
