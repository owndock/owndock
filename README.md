# OwnDock

**Own your apps. Run them anywhere.**

OwnDock 是面向缺少专职平台团队的中小型公司的自托管应用交付与运行平台。首要用户是同时承担应用交付职责的开发者和技术负责人。产品方向包含两条交付入口：连接标准 Git 仓库完成受约束的 Dockerfile 构建，或者直接使用外部 CI 生成的 OCI 镜像；两者最终都形成不可变 Release，并在 Docker 运行目标上完成部署、状态查看、失败重试和回滚。当前实现状态见下方基线。

项目采用 **Go + Kratos 的模块化单体**：在单进程内保持清晰的领域边界和可测试契约，并允许模块在出现独立扩缩容或故障隔离需求时演进为服务。

本仓库负责后端服务，不包含 Web 前端工程。

## 当前基线

- Go module：`github.com/owndock/owndock`
- Go：1.26.5（`.go-version`、`go.mod`、CI 和构建镜像保持一致）
- Kratos：v2.9.2
- 依赖组装：composition root 手工组装，不使用 Google Wire
- 进程：控制面 `owndock`；主机侧 `owndock-agent`
- 可观测性：结构化 Access Log、Prometheus 指标；OpenTelemetry Trace 默认关闭，可通过 OTLP/HTTP 导出
- MongoDB：官方 Go Driver v2.8.0；服务端测试基线 8.3.7，默认关闭
- 正式产品切片：本地 bootstrap/login/session、内置 RBAC、Organization Managed Host、一次性 Agent enrollment 与证书身份、Project、Project Application、不可变 Release、Runtime Target 元数据、基础审计和 MongoDB migration
- 已接受、尚未实现：Git-to-Deploy、Docker Runtime Inventory 调度/Agent 传输/查询、Agent 自动安装与证书轮换、Template、多主机系统验收和安全 Terminal
- 默认接口：健康和版本接口；产品切片需要显式启用 MongoDB 与 `product.enabled`
- 工程样例：Application、Environment、Deployment JSON API，默认关闭；概念已进入产品模型，但当前实现不属于正式产品契约

当前版本已经提供 Project 范围的正式 Deployment 创建、查询、取消、失败重试、回滚、幂等回放、MongoDB 持久化和审计事务。本地登录使用 MongoDB 共享的账号尝试窗口，多 Server 实例不会因各自内存计数而绕过阈值，成功登录会清理计数。Managed Host 归 Organization 所有，Project Runtime Target 必须绑定同一 Organization 的 Host，并保持 `agent/direct` 连接模式一致。Agent 首次接入已支持一次性 token、CSR 签发客户端证书和固定 Host/instance 身份；Server 端独立 TLS 1.3 监听已支持 mTLS 数据库身份校验、`v1` 协商、心跳、在线状态、重连 fence、禁用 Host 后断流，以及严格类型化的 probe 和部署命令、有界发送队列、并发去重和只保存指纹/安全结果的进程内缓存。正式 `owndock-agent` 进程可以使用已签发证书主动连接 Server，通过受信任的本机 Unix Socket 执行 Docker probe、镜像准备、候选容器健康门禁、激活和安全取消，并以权限受限、原子写入的磁盘状态跨重启重放安全结果。Agent 另用独立、不可淘汰且失败关闭的槽位水位保存最高 cutover sequence，使容器被删除或 Agent 重启后仍能拒绝延迟旧命令。Agent 部署采用 `stage → Server 验证 Mongo lease/cutover fence → activate`，不会把控制面 fencing 压缩进一个远程命令；Agent Server 和 Deployment Worker 同时启用时，Agent prober 与 Gateway 会配套注册。Agent 自动安装、证书轮换和多主机故障系统验收仍未完成。Release 可绑定 Project 范围的 Registry Credential，并声明端口、Environment 配置键、CPU/内存和容器健康检查；凭据与秘密值只通过 `secret://` 引用在 Worker 执行期解析。默认关闭的受管 Worker 可以通过 direct mTLS 或 Agent 连接 Docker Engine，携带私有仓库认证按 digest 拉取镜像，候选容器健康后再替换旧容器；同 Deployment 的租约 generation 阻止过期 Worker，同一部署槽位单调递增的 cutover sequence 阻止跨 Deployment 的延迟旧命令覆盖新版本。真实本地 Docker Engine 集成测试覆盖 Agent probe、两阶段 Agent 部署/取消、direct 固定 digest 健康替换、失败保留、过期执行隔离和取消清理。Template、实际入口流量、远程 mTLS Engine 和故障注入验证仍需补齐。

Docker Runtime Inventory 已建立独立领域模型、MongoDB observation/chunk/resource/head Repository、v12 索引、direct/Agent 可复用的四类 Docker List 安全 mapper、精确字节有界分块，以及 Agent `prepare → pull chunk → release` 内存快照协议与两种模式的持久化编排。新 generation 在全部分块完成前不会替换当前视图，未完成批次两小时后回收，延迟旧 observation 不能覆盖新视图；模型不包含原始 Inspect、Environment 值、Registry authorization、Volume options/status 或宿主 Mount source。Runtime Target credential/source 接线与周期调度、Docker Event 对账、公开查询 API 和 Host/Project 权限仍未实现，详见 [docs/runtime-inventory.md](docs/runtime-inventory.md)。

顶层 Application、Environment 和 Deployment 使用进程内存仓储，服务重启后数据会丢失，只用于验证架构、契约和并发机制。它们与 Project 范围的正式 API 隔离。正式 Deployment 已采用 Project 作用域的幂等键、原子领取、租约版本控制和受管 Worker；Worker 默认关闭，启用和凭据约定见 [docs/worker.md](docs/worker.md)。

## 本地运行

```bash
go mod tidy
make check
make run
```

默认监听 `0.0.0.0:8000`。配置见 `configs/config.yaml`。

```bash
curl http://127.0.0.1:8000/livez
curl http://127.0.0.1:8000/readyz
curl http://127.0.0.1:8000/metrics
curl http://127.0.0.1:8000/api/v1/meta/version
```

如需在本地验证工程样例，可在非生产配置中将 `development.enable_engineering_samples` 显式设为 `true`。这些未认证的样例接口不得暴露到共享或生产网络。

MongoDB 启用时只从 `database.mongo.uri_env` 指定的环境变量读取连接串，默认变量名为 `OWNDOCK_MONGODB_URI`。启动会连接并 Ping，运行期 `/readyz` 会检查主节点可用性，停止时关闭连接池。开发与 CI 使用固定的 MongoDB 8.3.7 单节点 Replica Set，详见 [docs/mongodb.md](docs/mongodb.md)。

本地启用正式产品切片时，将 `database.mongo.enabled` 和 `product.enabled` 设为 `true`，并通过环境变量提供 MongoDB URI 与一次性 bootstrap token：

```bash
export OWNDOCK_MONGODB_URI='mongodb://...'
export OWNDOCK_BOOTSTRAP_TOKEN='use-a-long-random-bootstrap-token'
make run
```

随后调用 `POST /api/v1/auth/bootstrap` 创建首个 Organization 和 Owner。Bootstrap、登录、资源写入和未来部署流程见 [docs/flows.md](docs/flows.md)，Agent 首次安全接入见 [docs/agent-enrollment.md](docs/agent-enrollment.md)，完整请求契约见 [api/openapi.yaml](api/openapi.yaml)。

`make build` 会同时生成 `bin/owndock` 和 `bin/owndock-agent`。Agent 构建、证书文件、配置与当前开放边界见 [docs/agent.md](docs/agent.md)；提交的 [configs/agent.yaml](configs/agent.yaml) 只是非敏感模板，不能直接用于生产。

如需启用链路追踪，将 `observability.tracing.enabled` 设为 `true`，并将 `endpoint` 配置为 OTLP/HTTP Collector 的 `host:port`（通常为 `localhost:4318`）。`sample_ratio` 取值为 `0` 到 `1`，默认配置为 `1`；设为 `0` 时不采样新的根 Span，无需追踪时应直接关闭 tracing。生产环境建议由应用发送至 OpenTelemetry Collector，再由 Collector 转发到后端。

## 目录约定

```text
api/                 对外契约；后续放置 proto/OpenAPI 源文件
cmd/server/          API 服务进程 composition root
cmd/agent/           主机侧 Agent composition root
configs/             可提交的非敏感配置模板
docs/                项目架构和工程约束
internal/agent/      Agent 控制客户端、配置与本机运行时
internal/app/        Kratos 应用生命周期
internal/modules/    按领域垂直切分的业务模块
internal/platform/   配置、数据库、可观测性等平台能力
internal/server/     HTTP/gRPC transport 装配
internal/shared/     Server 与 Agent 的仓内共享纯 Go 契约
```

文档入口见 [docs/README.md](docs/README.md)，产品定义见 [docs/product.md](docs/product.md)，架构约束见 [docs/architecture.md](docs/architecture.md)，Docker 资源清单见 [docs/runtime-inventory.md](docs/runtime-inventory.md)，核心时序见 [docs/flows.md](docs/flows.md)，发布前契约见 [api/openapi.yaml](api/openapi.yaml)。其中标记为工程样例的 operation 不构成稳定产品承诺。`make check` 会执行格式、依赖完整性、架构边界、单元/契约测试、OpenAPI 校验、静态检查和构建验证；`make test-integration` 使用 Docker 验证固定 MongoDB Replica Set；`make test-runtime-integration` 针对本机 Docker Engine 验证固定 digest 的容器切换；`make vuln` 使用固定版本的 Govulncheck 检查可达漏洞。漏洞报告方式见 [SECURITY.md](SECURITY.md)。

## License

OwnDock 社区核心使用 [Apache License 2.0](LICENSE)。
