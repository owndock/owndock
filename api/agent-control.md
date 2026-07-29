# Agent Control Protocol v1

> 状态：Server 端连接、认证、版本协商、心跳和首个类型化 `runtime.probe` command/result 传输已实现；OwnDock Agent 进程、命令执行器和 Runtime Gateway 尚未实现。

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

TLS 校验成功不等于应用身份成功；两层都通过后才能把 Host 标记为 `online`。

## Frame 规则

- 默认最大 frame 为 65,536 字节，可配置范围为 1 KiB～1 MiB；
- 未知 JSON 字段、多个 JSON 值、空 frame 和超限 frame 都会拒绝；
- Agent `sequence` 必须为大于零的单调递增整数；
- Server 使用独立的单调递增 `sequence`；
- Agent 可以发送 `hello`、`heartbeat` 和 `command_result`；Server 可以发送确认、安全错误和严格类型化的 `command`；
- `v1` 当前唯一允许的命令是 `runtime.probe`，目标只能使用 Server 已解析的 Runtime Target ID；
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
    "capabilities": ["docker"]
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
- 同一 Host 上，相同 ID 且内容完全一致的并发请求复用同一个等待结果；相同 ID、不同目标或 deadline 会被拒绝；
- 已完成结果保存在 Server 进程内的全局有界缓存中，默认最多 256 条；同一进程内重连后可重放结果，Server 重启或缓存淘汰后不能把它当作持久化事实；
- command deadline 到期、Agent 断线、Host 被禁用或新 session 替换旧 session 时，所有仍在等待的调用都会得到明确失败；
- 重复且完全相同的结果可安全确认；未知、冲突或结构不匹配的结果会关闭当前协议连接；
- 当前代码尚未提供用户可调用的命令触发 API，也没有 Agent 侧执行器。因此该传输能力不能被解释为 Agent Runtime Target 已可探测或部署。

## 在线、重连与关闭

- hello 通过后，Server 原子写入 `online`、session/boot ID、版本、能力和 `last_seen_at`，并记录 `agent_session.connect`；
- 每次 heartbeat 只在 Host 仍绑定当前 session 且为 `online` 时更新时间；
- 超过 heartbeat timeout、请求结束或 Server 停止时，当前 session 条件更新为 `offline` 并记录 `agent_session.disconnect`；
- 同一 Host 的新连接会替换并取消旧连接；旧连接随后关闭时，session fence 会阻止它把新连接标记为离线；
- Owner 禁用 Host 时先提交禁用、身份吊销和审计，再取消本进程当前连接；后续 heartbeat 和重连都会失败；
- 单实例路由已经实现。未来多控制面实例需要 session affinity 或共享连接路由，不能假设进程内 registry 可以跨实例断流。

## 后续兼容扩展

`v1` 的后续 frame 只能加入与已授权领域操作关联的类型化 command/result，例如 Deployment 和 Terminal session。每条 command 必须有唯一 command ID、幂等结果、超时和有界缓冲；协议不会提供“执行任意宿主机命令”的通用 RPC。

Server 侧 `runtime.probe` 类型契约、重复等待、结果缓存和慢消费者 backpressure 已完成。在 Agent 进程、Agent 侧持久幂等结果、优雅停止和相邻版本 conformance 完成前，`AGENT-002` 仍处于进行中。
