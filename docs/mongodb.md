# MongoDB 运行基线

OwnDock 使用官方 MongoDB Go Driver v2.8.0。开发和 CI 的服务端基线固定为 MongoDB 8.3.7，测试镜像为：

```text
mongo:8.3.7-noble@sha256:8444a416f2fc991f15064df9f6ea31ee02877607a70fd352ea998e6dbb5714b3
```

禁止使用 `mongo:latest`、`mongo:8` 或 `mongo:8.3` 等浮动 tag。版本升级必须同时更新镜像 digest、集成测试和发布说明。

## 配置

MongoDB 默认关闭。启用配置示例：

```yaml
database:
  mongo:
    enabled: true
    uri_env: OWNDOCK_MONGODB_URI
    database: owndock
    connect_timeout: 10s
    operation_timeout: 5s
    max_idle_time: 5m
    min_pool_size: 0
    max_pool_size: 100
```

连接串只从 `uri_env` 指定的环境变量读取，不写入配置模板、日志或版本库。生产环境需要认证和 TLS，并使用经过容量与故障转移验证的 Replica Set。

## 生命周期

- 启动时创建连接池并 Ping Primary；失败时服务不启动；
- 启动时获取带租约的全局锁并按版本执行 migration；已记录的同名版本会跳过，版本名称漂移会拒绝启动；
- 每次操作受 Client operation timeout 和调用方 context 共同约束；
- `/readyz` 会 Ping Primary，失败时返回通用 `not_ready`，不暴露数据库错误；
- Kratos 停止接收请求后关闭连接池；
- 业务模块不能直接创建 Client，也不能从 `internal/platform/mongo` 推导业务 schema。

正式资源创建与对应审计事件在同一 MongoDB 事务中提交。Bootstrap 的 Organization、Owner、Session 与审计同样保持原子性。当前 collection 包括 `organizations`、`users`、`sessions`、`managed_hosts`、`agent_enrollments`、`agent_identities`、`projects`、`product_applications`、`releases`、`registry_credentials`、`environments`、`runtime_targets`、`deployments`、`audit_events` 和 migration 元数据；索引只由版本化 migration 管理。Agent enrollment 只保存 token 的 SHA-256 hash；兑换时在事务中条件消费 token、创建固定身份并绑定 Host，重复兑换会整体回滚。Agent 连接在 `managed_hosts` 保存当前 boot/session fence、版本、能力和 `last_seen_at`；heartbeat 与 disconnect 必须匹配当前 session，避免旧连接覆盖新连接状态，连接/断开审计仍使用事务。Deployment 使用 Project 范围的唯一幂等索引，并为“同一 Application、Environment 与 Runtime Target 上曾成功部署的 Release”建立回滚查询索引。Migration v4 准备 Deployment 执行元数据，v5 建立 Registry Credential 索引，v6 为早期 Release 回填默认 CPU/内存运行规格，v7 允许同一 image digest 使用不同的不可变运行规格创建 Release，v8 建立 Organization Host 唯一命名和 Runtime Target Host 查询索引，v9 建立 enrollment token、过期清理、证书序列号/指纹和 Host 身份查询索引。

启动和事务写入时序见 [flows.md](flows.md)。

## 验证

普通单元测试不会启动容器：

```bash
make check
```

MongoDB 集成测试使用 Testcontainers 启动固定镜像的单节点 Replica Set，并验证连接、Ping、事务、migration 幂等、认证会话、Agent token 只存哈希/原子消费/重放回滚、Agent mTLS 身份查询/online/heartbeat/重连 fence/禁用吊销、正式资源持久化、Deployment 领取/终态/取消/重试/回滚、审计原子回滚和注销失效：

```bash
make test-integration
```
