# API contracts

此目录只存放 API 契约源文件和生成配置，不放业务实现。[`openapi.yaml`](./openapi.yaml) 是发布前工程契约，使用 OpenAPI 3.0.3；其中 Application、Environment 和 Deployment operation 仅用于验证架构与契约工具链，不是已接受的产品 API。

API 开发遵循以下规则：

1. 先定义资源、用例、权限和错误语义，再编写 proto/OpenAPI 契约；
2. 契约变更必须记录兼容性、版本策略和废弃窗口；
3. 生成代码不可手工修改，生成命令必须可重复执行；
4. 接口统一使用项目的错误模型、分页模型和资源命名；
5. transport DTO、领域模型和持久化模型保持独立。

业务 API 从首版开始使用路径主版本 `/api/v1`。健康检查保留为不带版本的运维端点；不兼容变更进入新的主版本，兼容字段扩展留在当前版本并经过契约测试。

每个请求接受或生成 `X-Request-ID`，并在响应 header 中返回。API 错误统一为：

```json
{
  "error": {
    "code": "invalid_json",
    "message": "request body must be valid JSON",
    "request_id": "a1b2c3"
  }
}
```

`code` 是客户端分支判断依据；`message` 只包含可安全公开的信息，不能透传数据库、运行时或堆栈错误。

JSON 写接口的工程契约要求 `application/json`；实现允许省略 Content-Type 以方便本地调试，但客户端不应依赖该宽松行为。请求体最大 1 MiB，拒绝未知字段和多个连续 JSON 值。错误分别返回 `415 unsupported_media_type` 或 `400 invalid_json`。

`make api-validate` 使用固定版本 oasdiff 校验契约；CI 使用目标分支中的契约执行 breaking-change 检测。真实 HTTP Handler 的成功和错误响应由 `internal/server` 契约测试直接对照 OpenAPI 验证。

当前仍使用手写 HTTP DTO，不从 OpenAPI 生成服务代码。只有出现多语言 SDK、正式客户端或 gRPC 契约需求时才评估生成工具，避免生成层反向控制领域模型。

## 当前工程样例

样例路由由 `development.enable_engineering_samples` 控制并默认关闭。它们没有认证授权，只能在隔离的本地开发环境启用，不得作为生产接口或兼容承诺。

第一批应用资源先以 HTTP JSON 契约落地，作为领域边界和错误语义的验证样板：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/v1/applications` | 返回当前实例中的应用列表 |
| `POST` | `/api/v1/applications` | 创建应用，请求体为 `{"name":"demo"}` |

创建成功返回 `201` 和应用资源，初始状态为 `pending`；名称为空返回 `422`、重复名称返回 `409 name_conflict`、请求体不是合法 JSON 返回 `400`。当前实现使用内存仓储，仅用于验证 API、领域和数据适配器的边界。正式产品契约将按 Organization/Project 所有权、Release、逻辑 Environment、Runtime Target、身份权限和审计要求替换这些工程接口。

HTTP Handler 位于各模块的 `service` 子包，只负责协议解析和错误映射。创建、查询、引用检查等流程由 `biz.UseCase` 执行，HTTP DTO 不直接访问 Repository。

环境和部署资源也已建立第一版 JSON 契约：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` / `POST` | `/api/v1/environments` | 查询或创建运行环境；创建需要 `name` 和 `provider` |
| `GET` | `/api/v1/deployments?application_id=&environment_id=` | 按应用或环境筛选部署记录 |
| `POST` | `/api/v1/deployments` | 创建部署，需要 `application_id`、`environment_id` 和可选 `revision` |

部署创建后状态为 `queued`，实际构建和交付由后续 worker 异步推进。
