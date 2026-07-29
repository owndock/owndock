# Deployment Worker

> 正式 Deployment Worker 已进入主进程的受管生命周期，但默认关闭。当前 Docker 适配器用于验证固定 digest、mTLS、私有 Registry 认证、运行规格、健康门禁、fenced token、幂等容器替换和安全失败分类；本地真实 Engine 验证已完成，在远程 mTLS Engine、入口流量和故障注入系统验证完成前，不应视为生产就绪。

Deployment API 创建身份与目标不可变、执行状态可演进的交付记录，初始状态为 `queued`。Worker 负责消费队列并推进状态：

```text
queued → preparing → deploying → succeeded
```

Deployment Worker 不执行源码构建。已接受但尚未实现的 Git-to-Deploy 会由隔离 Build Worker/BuildKit 生成 digest Artifact，再创建 Release；构建缓存和不可信 Dockerfile 不进入本进程或生产 Runtime Target。创建 Deployment 前，API 要求 Runtime Target 已成功探测并处于 `ready`。`preparing` 阶段再次解析不可变 Release 和 Runtime Target，构造不含秘密正文的 Runtime Connection；Executor 按连接模式解析所需凭据，Gateway Router 选择已注册的运行时适配器，然后检查 digest 镜像：本地存在时直接复用内容寻址镜像，不存在时携带 Registry 凭据拉取。`deploying` 阶段创建或替换目标容器。

当前只注册 `direct` Docker Gateway：Server 使用目标的 mTLS 配置直接连接 Docker Engine。Agent 首次 enrollment、固定证书身份和 Server 端 `runtime.probe` 类型化传输已经实现，但 Agent 进程、实际探测执行和 Agent Gateway 尚未开放；未来 Agent Gateway 会复用相同的 Prepare、Deploy、Cancel 契约，不改变 Deployment 状态机。未注册的模式会得到稳定的 `unsupported_target` 失败类别，不会自动改用另一条连接路径。

Worker 不再使用“全量 List 后 Update”的领取方式。Repository 的 `ClaimNext` 原子领取 `queued` 任务，或接管租约已过期的 `preparing/deploying` 任务，同时写入 worker ID、租约截止时间和递增版本。Runner 再通过带期望版本的事务更新进入 `preparing`，确保状态审计与状态写入一起提交。后续 `SaveClaimed` 同时校验 owner、租约和期望版本，阻止旧 Worker 覆盖新状态。

Worker 通过 `biz.Executor` 接口调用准备、部署和取消清理。失败时只持久化稳定的 `failure_category`，不保存 Docker 原始错误、Endpoint 或秘密内容。`preparing`、`deploying`、`succeeded`、`failed` 和 `canceled` 均形成以 `system:{worker_id}` 为 Actor 的审计事件。

Docker 稳定容器名由 Project、Application、Environment 和 Runtime Target 的组合哈希生成；候选名和回退名还包含 Deployment 身份与 lease generation，既保证相同执行幂等，也避免不同 Deployment 的 generation 都从 1 开始时发生临时名称冲突。generation 只在同一 Deployment 内比较，不能跨 Deployment 判断新旧。取消旧操作时会先校验容器上的 Deployment 与 generation 标签，避免删除已由其他执行替换的容器。

租约接管意味着 Prepare/Deploy 可能在进程失联后重试，因此 Executor 以 Deployment ID 和 lease generation 作为执行身份。generation 只在重新领取时递增，心跳只更新 expiry/version。Runner 在步骤执行期间按租约时长的三分之一发送心跳；Docker 候选容器带 generation 标签，并在破坏性切换前通过 Repository 再次确认 owner、generation、状态和 expiry，已经失去租约的 Worker 无法删除当前容器。

Worker 通过 `internal/platform/lifecycle.Server` 加入 Kratos App，启动、停止和 MongoDB 清理顺序受统一生命周期管理。启用方式：

```yaml
runtime:
  deployment_worker:
    enabled: true
    poll_interval: 2s
    lease_duration: 30s
    operation_timeout: 10m
```

Runtime Target 的 `credential_ref` 当前只接受 `secret://{alias}`。例如 `secret://docker-production` 从以下进程环境变量读取 PEM，秘密正文不会进入配置、MongoDB、API 或审计：

```text
OWNDOCK_RUNTIME_DOCKER_PRODUCTION_CA_PEM
OWNDOCK_RUNTIME_DOCKER_PRODUCTION_CERT_PEM
OWNDOCK_RUNTIME_DOCKER_PRODUCTION_KEY_PEM
```

Registry Credential 同样只保存 `password_ref`。例如 `secret://private-registry` 在执行时读取：

```text
OWNDOCK_REGISTRY_PRIVATE_REGISTRY_PASSWORD
```

Environment 的值可以是普通字符串或 `secret://{alias}`。例如 `secret://database-url` 在执行时读取：

```text
OWNDOCK_CONFIG_DATABASE_URL_VALUE
```

Worker 只把 Release 声明过的配置键传入容器；未声明值被忽略，缺少已声明值会以 `configuration` 类别失败。解析后的秘密不写入 Deployment、MongoDB、API 或审计。

生产验收前仍需补充：

- 远程 mTLS Docker Engine、入口路由和端口占用集成测试；
- 在进程退出、网络分区、租约接管和切换窗口执行故障注入；
- 量化健康门禁替换的实际停机窗口并形成支持矩阵。

本地 Docker Engine 回归使用固定的
`nginx@sha256:1eff5a5f3fcf8431a0abb7eddf5471fec24e5e1905a2581aeacdb07a4479b92b`
镜像，不依赖浮动 tag：

```bash
make test-runtime-integration
```

该测试会创建带随机前缀的临时容器，并覆盖首次安装、健康候选替换、异常候选清理且旧实例继续运行、过期 fence 拒绝切换、旧实例回退名称清理以及取消清理。它只验证本机 Engine，不替代远程证书、网络和入口流量验收。
