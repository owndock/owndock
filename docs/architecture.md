# 目标架构

## 决策

OwnDock 采用 Kratos v2 的模块化单体。

Kratos 负责应用生命周期、HTTP/gRPC transport、中间件、配置和日志接入；领域模型、状态机、授权规则和数据所有权由各业务模块负责。框架能力不进入领域核心，基础设施通过接口替换。

第一阶段不使用 Google Wire。依赖在 `cmd/server` 显式组装，使资源创建、生命周期和测试替换点一眼可见，也避开已归档项目成为核心构建依赖。

产品边界已经固定为 Organization 下的 Managed Host，以及 Project 下的 Source Repository、Application、Build、Artifact、Release、Environment、Runtime Target 和 Deployment，详见 [product.md](product.md)。当前已实现外部 OCI 镜像入口及除 Template、Git-to-Deploy 外的首个部署核心资源；Release、Registry Credential 和 Environment 配置绑定通过纯 Go 共享运行契约连接控制面与执行适配器。Deployment 具备默认关闭的受管 Worker 与基础 Docker 执行适配器。Git-to-Deploy 已接受但尚未实现，后续必须进入隔离 Build Worker/BuildKit 边界；默认关闭的顶层工程样例不属于正式产品实现。

## 模块边界

每个真实业务模块使用垂直切分：

```text
internal/modules/<domain>/
  biz/          实体、值对象、用例、仓储接口
  data/         MongoDB/外部系统适配器
  service/      transport DTO 与用例之间的转换
```

模块内请求链固定为 `HTTP/gRPC service → biz.UseCase → Repository/Gateway port ← data adapter`。Service 只处理协议解析、校验和错误映射；业务编排、状态规则与端口定义属于 `biz`。

约束：

- `biz` 不依赖 Kratos transport、Mongo driver 或其他模块的 `data`；
- 跨模块调用通过用例接口或显式事件，不直接读写对方 collection；
- transport DTO 不作为领域或持久化模型；`biz` 实体不得声明 JSON transport tag；
- 数据库 client、日志、遥测属于 `internal/platform`，领域仓储实现仍归模块所有；
- 只有出现独立扩缩容、故障隔离或团队所有权需求时，才把模块拆为服务。

这些规则由 `internal/architecture` 中的可执行测试守护。新增领域不能让 `biz` 直接导入其他领域、Kratos transport、数据库驱动或运行时 SDK，也不能直接把领域实体作为 HTTP JSON 契约。

## 进程边界

当前只建立 `cmd/server`，负责对外 API，并在启用时托管 Deployment Worker 生命周期。Agent 和 Build Worker 的职责已经确定，但完整实现前不创建空进程模板；CLI 等进程也只在职责和生命周期明确后创建。Web 前端由独立项目维护。

常驻任务实现 `Run(context.Context) error`，通过 `internal/platform/lifecycle.Server` 接入 Kratos App。构造函数不得启动 goroutine；停止过程必须响应 context，并受统一 shutdown timeout 约束。

## Build Boundary

Git-to-Deploy 已进入产品架构，但当前代码尚未实现。构建链必须与 API Server 和生产 Runtime Boundary 隔离：

- API Server 只校验并持久化 Source Repository、Build Configuration 和 Build 任务，不执行 Git checkout、Dockerfile 或任意 Shell；
- 独立 Build Worker 领取带租约和 fence 的任务，通过受认证窄接口调用固定版本、不可变镜像 digest 的 BuildKit；
- Build Worker 和 BuildKit 不挂载控制面数据库、宿主机 Docker Socket、生产 Volume 或 Runtime Target 凭据；
- 源码工作目录、构建缓存、Git 凭据、Registry push 凭据按步骤隔离并有界回收；
- Registry 返回真实 OCI digest 后创建 Artifact，Artifact 再通过窄用例接口创建不可变 Release；
- 外部 CI 镜像继续直接创建 Release，不依赖 Build 模块。

领域、Webhook 与安全图见 [Git-to-Deploy 产品与安全边界](git-to-deploy.md)。在 Build Worker、BuildKit 和系统测试完成前，不注册占位构建 API。

## Runtime Gateway 边界

Deployment `biz` 只定义 Execution Resolver、Credential Resolver、Executor 和 Runtime Gateway 端口，不导入 Docker SDK。执行计划使用与传输无关的 Runtime Connection 描述；Gateway Router 再按连接模式选择具体适配器。因此 Deployment 状态机不需要知道目标是控制面直连还是 Agent 转发。

当前正式 API 可以登记 `direct` 或 `agent` Runtime Target；`data` 使用固定版本的 Moby API/Client 模块实现并只注册 Direct Docker Gateway。Agent 首次 enrollment、CSR 证书签发和固定身份已经落地；Server 端独立 TLS 1.3 listener 已支持 mTLS 数据库身份校验、`v1` hello/heartbeat、在线状态、单实例重连替换和禁用断流，并提供首个只接受 Runtime Target ID 的 `runtime.probe` command/result。进程内 registry 使用有界队列、相同命令等待复用、有界结果缓存和 deadline/断线收敛，协议不提供任意 Shell 或 Docker endpoint。Agent 进程、实际命令执行器、证书轮换和系统测试完成前不注册 Agent 执行实现，也不会静默回退到 direct。`worker` 负责编排领取、心跳、状态机和审计。direct Runtime Target 只保存 `secret://alias`，mTLS PEM 在执行时从受约束环境变量解析，并在单次 Gateway 调用结束后尽力清零解析器返回的字节切片。

Managed Host 是 Organization 资源；Runtime Target 是 Project 对该 Host 上 Docker Engine 的显式使用绑定。两者连接模式必须一致。Agent enrollment token 只返回一次且数据库仅存哈希，CSR 由 Agent 在本地私钥上生成；Server 颁发只含 `clientAuth` 的固定身份，并在原子事务中消费 token、绑定 Host 和写审计。Agent hello 成功后 Host 进入 `online`，断线或 heartbeat timeout 后条件更新为 `offline`；session fence 防止旧连接覆盖新连接状态。Host 禁用会吊销数据库身份、使未使用 token 失效并取消当前进程连接。Agent Runtime Gateway 尚未实现，所以即使 Host 在线，Agent Target 仍不会进入 `ready`。direct Host 可选保存外部 SSH 引用，但主机终端实现前不会读取该引用。

基础 Docker 适配器使用作用域稳定的容器名、Deployment 标签和 fencing token 实现幂等及安全取消。适配器会应用 Release 声明的端口、环境变量、资源限制和 Docker HEALTHCHECK：候选容器启动并进入 healthy 后，Worker 再验证 MongoDB 活跃租约、移除旧容器并把候选容器改为稳定名称。不健康候选会被清理且旧容器保持运行。该策略仍需在真实 Engine、入口路由和端口所有权场景中验证实际停机窗口。

## 可观测性

HTTP 请求使用低基数 Prometheus 指标，并通过 OpenTelemetry 生成服务端 Span。Trace 默认关闭；开启后通过 OTLP/HTTP 发往 Collector，资源属性至少包含 `service.name`、`service.version` 和 `service.instance.id`。入口使用 W3C Trace Context 与 Baggage 传播格式，即使本地未启用导出，也继续传递上游 Trace ID。

每个 HTTP 请求结束后输出一条结构化 Access Log，包含 request ID、有效的 trace/span ID、method、path、status、耗时和响应字节数。日志只记录 URL path，不记录 raw query，避免令牌或其他敏感查询值进入日志；4xx 使用 warning，5xx 使用 error。Access Log 位于 Recovery 外层，因此已恢复的 panic 会被记录为 500。

Telemetry provider 由 `cmd/server` 创建并显式注入 transport，不在领域包中读取全局对象。provider 的关闭挂到 Kratos `AfterStop`，使用独立、带超时的 context 刷新批量 Span；composition root 同时保留幂等兜底清理，以覆盖启动中途失败。

指标标签和 Span 名称不得包含原始 URL、资源 ID、租户 ID 等无界值。业务模块需要增加手工 Span 时，应通过明确依赖获得 tracer，不能让 `biz` 依赖 exporter 或 SDK 实现。

## API 契约

`api/openapi.yaml` 是发布前 HTTP 行为的机器可读契约，覆盖运维接口、首个正式产品切片和当前工程样例；Prometheus `/metrics` 使用其自身 exposition 协议，不纳入 OpenAPI。正式切片 operation 已具备 Organization 所有权、内置角色授权、审计和 MongoDB 持久化，但在首个端到端部署用例完成前仍标记为 pre-release。Handler 显式完成 DTO 与领域对象转换，不把 OpenAPI schema 当作领域或持久化模型。

契约文件必须通过 oasdiff 严格校验，真实 Handler 的请求与响应必须通过 kin-openapi 契约测试。工程样例在产品接受前允许显式删除或重塑；正式 operation 则执行 breaking-change 门禁，不兼容变更进入新的 API 主版本并记录迁移窗口。

## MongoDB 平台边界

进程级 MongoDB Client 由 `internal/platform/mongo` 创建和关闭，业务模块只能通过自己在 `biz` 中定义的 Repository 接口使用持久化。MongoDB 默认关闭；启用时连接串来自指定环境变量，启动 Ping 失败会阻止服务启动，运行期 Ping 失败会使 `/readyz` 返回 503。

开发和 CI 使用 MongoDB 8.3.7 单节点 Replica Set，保证事务拓扑不会被 standalone 测试掩盖。业务 collection、BSON 模型和 migration 按已接受的产品所有权与不可变 Release 语义设计，不能从内存样例直接生成。启动时使用带租约锁的版本化 migration；资源写入和对应审计事件使用同一事务提交。

关键运行链路见 [flows.md](flows.md)。

## 版本策略

正式基线固定 Kratos v2.9.2，不跟随主分支上的 v3 开发状态。框架升级必须经过依赖审查、契约测试和回滚验证，不使用浮动版本。
