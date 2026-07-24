# 目标架构

## 决策

OwnDock 采用 Kratos v2 的模块化单体。

Kratos 负责应用生命周期、HTTP/gRPC transport、中间件、配置和日志接入；领域模型、状态机、授权规则和数据所有权由各业务模块负责。框架能力不进入领域核心，基础设施通过接口替换。

第一阶段不使用 Google Wire。依赖在 `cmd/server` 显式组装，使资源创建、生命周期和测试替换点一眼可见，也避开已归档项目成为核心构建依赖。

产品边界已经固定为 Organization/Project 下的 Template、Application、Release、Environment、Runtime Target 和 Deployment，详见 [product.md](product.md)。当前同名工程模块仍不是正式实现，只有满足所有权、权限、审计、持久化和产品契约后才能替换默认关闭的样例路由。

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

当前只建立 `cmd/server`，负责对外 API。agent、worker、CLI 等进程只在职责和生命周期明确后创建，不保留无实现的模板目录。Web 前端由独立项目维护。

常驻任务实现 `Run(context.Context) error`，通过 `internal/platform/lifecycle.Server` 接入 Kratos App。构造函数不得启动 goroutine；停止过程必须响应 context，并受统一 shutdown timeout 约束。

## 可观测性

HTTP 请求使用低基数 Prometheus 指标，并通过 OpenTelemetry 生成服务端 Span。Trace 默认关闭；开启后通过 OTLP/HTTP 发往 Collector，资源属性至少包含 `service.name`、`service.version` 和 `service.instance.id`。入口使用 W3C Trace Context 与 Baggage 传播格式，即使本地未启用导出，也继续传递上游 Trace ID。

每个 HTTP 请求结束后输出一条结构化 Access Log，包含 request ID、有效的 trace/span ID、method、path、status、耗时和响应字节数。日志只记录 URL path，不记录 raw query，避免令牌或其他敏感查询值进入日志；4xx 使用 warning，5xx 使用 error。Access Log 位于 Recovery 外层，因此已恢复的 panic 会被记录为 500。

Telemetry provider 由 `cmd/server` 创建并显式注入 transport，不在领域包中读取全局对象。provider 的关闭挂到 Kratos `AfterStop`，使用独立、带超时的 context 刷新批量 Span；composition root 同时保留幂等兜底清理，以覆盖启动中途失败。

指标标签和 Span 名称不得包含原始 URL、资源 ID、租户 ID 等无界值。业务模块需要增加手工 Span 时，应通过明确依赖获得 tracer，不能让 `biz` 依赖 exporter 或 SDK 实现。

## API 契约

`api/openapi.yaml` 是发布前 HTTP 行为的机器可读工程契约，覆盖运维接口和当前工程样例；Prometheus `/metrics` 使用其自身 exposition 协议，不纳入 OpenAPI。产品概念已经接受，但当前样例 operation 尚未满足正式所有权、授权、审计和持久化要求，不能因此成为稳定产品契约。Handler 仍显式完成 DTO 与领域对象转换，不把 OpenAPI schema 当作领域或持久化模型。

契约文件必须通过 oasdiff 严格校验，真实 Handler 的请求与响应必须通过 kin-openapi 契约测试。工程样例在产品接受前允许显式删除或重塑；正式 operation 则执行 breaking-change 门禁，不兼容变更进入新的 API 主版本并记录迁移窗口。

## MongoDB 平台边界

进程级 MongoDB Client 由 `internal/platform/mongo` 创建和关闭，业务模块只能通过自己在 `biz` 中定义的 Repository 接口使用持久化。MongoDB 默认关闭；启用时连接串来自指定环境变量，启动 Ping 失败会阻止服务启动，运行期 Ping 失败会使 `/readyz` 返回 503。

开发和 CI 使用 MongoDB 8.3.7 单节点 Replica Set，保证事务拓扑不会被 standalone 测试掩盖。业务 collection、BSON 模型和 migration 必须按已接受的产品所有权与不可变 Release/Deployment 语义设计，不能从当前内存样例直接生成。

## 版本策略

正式基线固定 Kratos v2.9.2，不跟随主分支上的 v3 开发状态。框架升级必须经过依赖审查、契约测试和回滚验证，不使用浮动版本。
