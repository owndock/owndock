# Agent Control Protocol v1

> 状态：Server 端连接、认证、版本协商、心跳和类型化 probe/部署/Runtime Inventory command/result 传输已实现；`owndock-agent` 控制客户端、抖动退避重连、本机 Docker 执行、跨重启小结果缓存、Inventory 内存快照和持久切换水位也已实现。Runtime Inventory 尚未接入周期调度，自动安装、证书轮换和多主机故障系统验收仍未完成。

Agent 控制协议运行在独立的 mTLS 监听端口，不与浏览器 Bearer API 共用认证边界。Agent 主动发起：

```text
POST /api/v1/agent/connect
Content-Type: application/x-ndjson
```

请求体和响应体都是持续打开的 NDJSON 流，每行只能包含一个 JSON frame。HTTP/2 可以原生并发读写；HTTP/1.1 由 Server 显式开启 full duplex。该协议不是普通 REST operation，因此不放入主 HTTP OpenAPI 的默认 Server 地址。

## mTLS 身份

TLS 1.3 listener 强制校验 Agent CA 签发的客户端证书。证书叶子的唯一 SPIFFE URI 必须使用：

```text
spiffe://owndock/organizations/{organization_id}/managed-hosts/{host_id}/agents/{identity_id}/instances/{instance_id}
```

Server 还会使用证书序列号和 SHA-256 指纹查询 MongoDB，并确认：

- Agent Identity 存在、未吊销且未过期；
- Organization、Host、Identity、instance 与证书 URI 完全一致；
- Host 仍绑定该身份、使用 `agent` 模式且未禁用；
- hello frame 中的身份字段与证书身份完全一致。
- hello 上报的 capabilities 是 enrollment 时写入 Agent Identity 能力授权的子集。
- Agent 二进制新增 capability 不会自动扩大已有 Identity 权限；实际 hello 使用本机配置的列表。Runtime Inventory 的 prepare/chunk/release 必须作为一组授权和启用。

TLS 校验成功不等于应用身份成功；两层都通过后才能把 Host 标记为 `online`。

## Frame 规则

- 默认最大 frame 为 65,536 字节，可配置范围为 1 KiB～1 MiB；
- 未知 JSON 字段、多个 JSON 值、空 frame 和超限 frame 都会拒绝；
- Agent `sequence` 必须为大于零的单调递增整数；
- Server 使用独立的单调递增 `sequence`；
- Agent 可以发送 `hello`、`heartbeat` 和 `command_result`；Server 可以发送确认、安全错误和严格类型化的 `command`；
- `v1` 已注册 `runtime.probe`、`deployment.prepare/stage/activate/cancel` 和 `runtime.inventory.prepare/chunk/release`；目标只能使用 Server 已解析的 Runtime Target/Managed Host，不能由调用方提交 Docker endpoint；
- frame 中不能携带 Docker endpoint、Socket、SSH 地址、用户选择的 Shell 或任意宿主机命令；
- 连接建立后的协议错误通过安全 `error` frame 返回，不透传数据库或证书错误。

首个 Agent frame：

```json
{
  "type": "hello",
  "sequence": 1,
  "hello": {
    "organization_id": "organization-id",
    "managed_host_id": "host-id",
    "agent_identity_id": "identity-id",
    "instance_id": "instance-id",
    "boot_id": "linux-boot-id",
    "agent_version": "1.0.0",
    "protocol_version": "v1",
    "capabilities": [
      "runtime.probe",
      "deployment.prepare",
      "deployment.stage",
      "deployment.activate",
      "deployment.cancel",
      "runtime.inventory.prepare",
      "runtime.inventory.chunk",
      "runtime.inventory.release"
    ]
  }
}
```

Server 接受后返回：

```json
{
  "type": "hello_ack",
  "sequence": 1,
  "session_id": "session-id",
  "protocol_version": "v1",
  "heartbeat_interval_seconds": 10,
  "max_frame_bytes": 65536,
  "server_time": "2026-07-26T00:00:00Z"
}
```

心跳和确认：

```json
{"type":"heartbeat","sequence":2}
{"type":"heartbeat_ack","sequence":2,"acknowledged_sequence":2,"server_time":"2026-07-26T00:00:10Z"}
```

## 类型化命令

`runtime.probe` 的含义是：“请在这台已认证的 Host 上，检查 OwnDock 后端指定的 Runtime Target 是否可用”。Server 只给出领域 ID，不让浏览器或 Agent 临时替换 Docker 地址：

```json
{
  "type": "command",
  "sequence": 3,
  "command": {
    "command_id": "command-id",
    "kind": "runtime.probe",
    "deadline": "2026-07-26T00:00:30Z",
    "runtime_probe": {
      "runtime_target_id": "runtime-target-id"
    }
  }
}
```

Agent 必须在 deadline 前返回同一 `command_id`。成功结果只能是三个安全状态之一：

```json
{
  "type": "command_result",
  "sequence": 3,
  "command_result": {
    "command_id": "command-id",
    "status": "succeeded",
    "runtime_probe": {
      "status": "ready"
    }
  }
}
```

`runtime_probe.status` 只接受 `ready`、`unreachable` 或 `unsupported`。执行失败时不返回底层地址、Socket 或原始错误，只返回小写稳定错误码：

```json
{
  "type": "command_result",
  "sequence": 3,
  "command_result": {
    "command_id": "command-id",
    "status": "failed",
    "error_code": "runtime_unavailable"
  }
}
```

Server 接受并缓存结果后给出确认，Agent 之后才能安全清理自己的结果：

```json
{
  "type": "command_result_ack",
  "sequence": 4,
  "acknowledged_sequence": 3,
  "command_id": "command-id",
  "server_time": "2026-07-26T00:00:20Z"
}
```

命令传输遵循以下规则：

- 默认每条 Agent 连接最多排队 32 条待发送命令；队列已满时调用方立即得到 backpressure，不会无限占用内存；
- 同一 Host 上，相同 ID 且内容完全一致的并发请求复用同一个等待结果；相同 ID、不同目标、deadline 或部署内容会被拒绝；
- 每条新命令下发前都会检查当前已认证 hello 是否声明该 command capability；未声明时命令不会入队，Deployment Gateway 返回 `unsupported_target`；
- 已完成结果保存在 Server 进程内的全局有界缓存中，默认最多 256 条；缓存只保留 command kind、SHA-256 指纹和安全结果，不保留完整命令或秘密；同一进程内重连后可重放结果，Server 重启或缓存淘汰后不能把它当作持久化事实；
- Runtime Inventory 三类命令是例外：chunk 可能接近 frame 上限，且 prepare 对应 Agent 内存快照，不能作为跨重启事实，因此 Agent 磁盘缓存和 Server 已完成结果缓存都明确跳过它们；重试会重新下发同一 observation/index，Agent 进程仍在时从同一内存快照返回，Agent 重启后返回 snapshot missing 并重新开始 observation；
- command deadline 到期、Agent 断线、Host 被禁用或新 session 替换旧 session 时，所有仍在等待的调用都会得到明确失败；
- 重复且完全相同的结果可安全确认；未知、冲突或结构不匹配的结果会关闭当前协议连接；
- Project Runtime Target 已有受 RBAC 保护的 probe API，Server 侧会从数据库 Target/Host 映射到 `runtime.probe` command；Agent 控制客户端通过受信任的本机 Unix Socket Ping Docker，并把安全结果写入 `0600`、原子替换、有界的磁盘缓存。缓存 v2 只保存 command kind、SHA-256 指纹和安全结果，不保存 Runtime Target ID、Registry authorization、Environment 值或原始错误；旧版只含 probe 标识的缓存可以读取，并在后续写入时升级。Agent Control Server 启用后，composition root 会把 Agent prober 与已实现的 Deployment Gateway 配套注册；离线或未启用仍安全返回不可达/不可用，不会回退 direct。

## Runtime Inventory 拉取协议

Runtime Inventory 不把一台主机的全部 Container、Image、Network 和 Volume 塞进一条 command result。Server 使用三步拉取：

1. `runtime.inventory.prepare` 固定 Runtime Target、observation ID 和单块字节上限；
2. Agent 通过本机 Docker List API 生成安全投影，在内存中按字节和资源数分块；Server 收到 manifest 后逐个发送 `runtime.inventory.chunk`；
3. Server 每收到一块就校验并事务写入 MongoDB，全部完成后切换 current head，再发送 `runtime.inventory.release`。

prepare 示例：

```json
{
  "command_id": "command-prepare",
  "kind": "runtime.inventory.prepare",
  "deadline": "2026-07-30T10:00:30Z",
  "runtime_inventory": {
    "runtime_target_id": "runtime-target-id",
    "observation_id": "observation-id",
    "max_chunk_bytes": 49152
  }
}
```

Agent 只返回小 manifest。`retention_seconds` 是相对保留时间，不是 Agent 的绝对时间；Server 使用自己的开始时间计算截止点，避免主机时钟偏差影响协议：

```json
{
  "command_id": "command-prepare",
  "status": "succeeded",
  "runtime_inventory": {
    "manifest": {
      "observation_id": "observation-id",
      "schema_version": 1,
      "expected_chunks": 3,
      "expected_resources": 742,
      "retention_seconds": 600
    }
  }
}
```

chunk 请求只增加 index；返回值只能包含 OwnDock 安全资源结构：

```json
{
  "command_id": "command-chunk-0",
  "kind": "runtime.inventory.chunk",
  "deadline": "2026-07-30T10:00:30Z",
  "runtime_inventory": {
    "runtime_target_id": "runtime-target-id",
    "observation_id": "observation-id",
    "max_chunk_bytes": 49152,
    "chunk_index": 0
  }
}
```

当前限制为：

- 默认单块 48 KiB、最多 500 个资源，48 KiB 按完整 chunk JSON 的实际编码字节计算；
- Agent 最多同时保留 2 份快照，每份所有 chunk 合计不超过 32 MiB，10 分钟后即使 Server 未 release 也自动删除；
- 共享 transport 硬限制为 100,000 个资源、10,000 个 chunk 和 64 MiB 编码资源数据；Agent 的 32 MiB 上限更严格；
- 一次只拉取一块，现有 command/result 确认就是流控和背压边界；
- Container Env、Registry authorization、Volume mountpoint/options/status、宿主机 mount source、任意 Docker 原始错误和非白名单 Label 不进入 chunk；
- `release` 幂等；断线或部分失败时 MongoDB 继续返回上一份完整视图，open observation 两小时后自动回收。

```mermaid
sequenceDiagram
    participant S as OwnDock Server
    participant A as owndock-agent
    participant D as Docker Engine
    participant M as MongoDB

    S->>A: prepare(Target + observation + max bytes)
    A->>D: List Container/Image/Network/Volume
    A->>A: 白名单映射并生成内存 chunks
    A-->>S: manifest(counts + retention seconds)
    S->>M: Begin open observation
    loop 一次拉取一块
        S->>A: chunk(observation + index)
        A-->>S: bounded safe chunk
        S->>M: Append receipt + resources
    end
    S->>M: Complete and switch current head
    S->>A: release(observation)
```

共享协议、Agent 执行器和 Server 拉取编排已经实现；把它接到 Runtime Target credential/source resolver、周期任务和公开查询 API 仍属于后续任务。

## Agent Deployment 两阶段契约

Agent 部署不能简单地把现有 Server 直连 Docker 操作整体搬到远端。候选容器健康后，Server 必须重新验证 MongoDB 中当前 Deployment 的 worker owner、lease generation、状态、过期时间，以及它仍是部署槽位的当前序号，才能允许候选接管稳定容器名。每个命令还携带同一部署槽位内单调递增的 `cutover_sequence`：lease generation 区分同一 Deployment 的 Worker 尝试，cutover sequence 区分不同 Deployment 的新旧。内部 `v1` 契约因此按下面四种类型化命令拆分：

- `deployment.prepare`：按不可变 digest 检查或拉取镜像；只有该命令可携带有界 Registry authorization；
- `deployment.stage`：使用受约束的 Runtime Spec 和 Environment 创建候选容器并等待健康，但不切换稳定名称；
- `deployment.activate`：Server 重新通过 lease fence 后下发，只负责进行幂等的最终名称切换；
- `deployment.cancel`：只清理由同一 Deployment ID、fencing token 和 cutover sequence 拥有的候选、回退或稳定容器。

`prepare/stage/activate/cancel` 都固定 Deployment、Worker、generation、cutover sequence、Runtime Target 和稳定容器名，不能携带 Docker endpoint 或 Shell。`stage` 的 Environment 必须与 Release Runtime Spec 声明的键完全一致；`activate/cancel` 禁止携带 Registry、Environment 或镜像字段。Agent 会把 cutover sequence 写入候选和稳定容器标签，并在独立的本机文件中保存每个稳定容器槽位的最高 sequence 与 Deployment ID。该水位不随结果缓存淘汰；因此即使 Agent 重启或稳定容器被删除，延迟到达的旧 `prepare/stage/activate` 仍返回 `stale_execution`。较旧 `cancel` 仍可按完整执行身份清理自己的候选，不会删除新 Deployment。水位文件损坏、写入失败或达到配置上限时失败关闭。Agent 本机执行器、Server Gateway、secret-safe 双端结果缓存、跨重启/容器缺失延迟命令回归和单机真实 Engine 两阶段测试已经实现；两台真实主机、网络分区和网络层延迟命令的系统验收仍未完成，因此当前不能据此宣称 Agent 模式生产就绪。

```mermaid
sequenceDiagram
    autonumber
    participant W as Deployment Worker
    participant G as Agent Gateway
    participant R as Agent Connection Registry
    participant A as owndock-agent
    participant D as Docker Engine
    participant M as MongoDB Fence

    W->>G: Prepare(plan)
    G->>R: deployment.prepare(digest + bounded registry auth)
    R-->>A: typed command
    A->>D: inspect/pull immutable digest
    A-->>R: safe result
    W->>G: Deploy(plan)
    G->>R: deployment.stage(spec + resolved environment)
    R-->>A: typed command
    A->>D: create/start candidate; wait healthy
    A-->>R: staged
    G->>M: validate owner + generation + state + lease + current cutover
    alt fence current
        G->>R: deployment.activate(no secrets)
        R-->>A: typed command
        A->>D: compare cutover sequence; idempotent stable-name switch
        A-->>R: activated
    else fence stale
        G->>R: deployment.cancel(owned execution only)
        R-->>A: typed command
        A->>D: remove owned candidate
        G-->>W: stale execution
    end
```

不同 Deployment 乱序到达时，`cutover_sequence` 提供跨操作的比较依据：

```mermaid
sequenceDiagram
    autonumber
    participant S as Server
    participant A as Agent
    participant W as 持久切换水位
    participant D as Docker Engine

    S->>A: stage Deployment A (cutover 41)
    A->>W: 保存槽位最高水位 41
    A->>D: candidate A healthy
    Note over S,A: activate A 因网络延迟尚未到达
    S->>A: stage + activate Deployment B (cutover 42)
    A->>W: 原子更新槽位最高水位 42
    A->>D: B 接管稳定名称并保存 cutover=42
    Note over A,D: Agent 可重启，稳定容器也可能暂时缺失
    S-->>A: delayed activate A (cutover 41)
    A->>W: 比较持久水位 42 > 41
    A-->>S: stale_execution；稳定容器仍为 B
```

## 在线、重连与关闭

- hello 通过后，Server 原子写入 `online`、session/boot ID、版本、能力和 `last_seen_at`，并记录 `agent_session.connect`；
- 每次 heartbeat 只在 Host 仍绑定当前 session 且为 `online` 时更新时间；
- 超过 heartbeat timeout、请求结束或 Server 停止时，当前 session 条件更新为 `offline` 并记录 `agent_session.disconnect`；
- 同一 Host 的新连接会替换并取消旧连接；旧连接随后关闭时，session fence 会阻止它把新连接标记为离线；
- Owner 禁用 Host 时先提交禁用、身份吊销和审计，再取消本进程当前连接；后续 heartbeat 和重连都会失败；
- 单实例路由已经实现。未来多控制面实例需要 session affinity 或共享连接路由，不能假设进程内 registry 可以跨实例断流。

## 后续兼容扩展

`v1` 的后续 frame 只能加入与已授权领域操作关联的类型化 command/result，例如 Terminal session。每条 command 必须有唯一 command ID、幂等结果、超时和有界缓冲；协议不会提供“执行任意宿主机命令”的通用 RPC。

Server 侧 probe/Deployment 类型契约、重复等待、secret-safe 结果缓存和慢消费者 backpressure，以及 Agent 侧 TLS 1.3 客户端、严格帧校验、心跳、抖动退避重连、优雅停止、deadline、本机 Docker executor、并发去重和跨重启持久结果均已完成。双端流一致性测试已覆盖当前 `v1`；在相邻 Agent/Server 版本 conformance 和发行升级矩阵完成前，`AGENT-002` 仍处于进行中。
