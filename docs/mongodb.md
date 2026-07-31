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

正式资源创建与对应审计事件在同一 MongoDB 事务中提交。Bootstrap 的 Organization、Owner、Session 与审计同样保持原子性。当前 collection 包括 `organizations`、`users`、`sessions`、`login_attempts`、`managed_hosts`、`agent_enrollments`、`agent_identities`、`projects`、`product_applications`、`releases`、`registry_credentials`、`environments`、`runtime_targets`、`deployments`、`deployment_cutover_sequences`、`runtime_inventory_observations`、`runtime_inventory_chunks`、`runtime_inventory_resources`、`runtime_inventory_heads`、`runtime_inventory_counters`、`runtime_inventory_schedule`、`runtime_inventory_current`、`runtime_inventory_event_hints`、`audit_events` 和 migration 元数据；索引只由版本化 migration 管理。

`login_attempts` 只保存 normalized email 的 SHA-256 键、窗口、计数和阻断/过期时间，通过 revision 条件更新避免多实例并发绕过限制，成功登录会删除记录。新 Session 与“只保留该用户最新 N 个未过期 Session”的清理处于同一事务；Session 查询和撤销都固定当前 `user_id`，撤销与审计也原子提交，API 永不返回 `token_hash`。Agent enrollment 只保存 token 的 SHA-256 hash；兑换时在事务中条件消费 token、创建固定身份并绑定 Host，重复兑换会整体回滚。Agent 连接在 `managed_hosts` 保存当前 boot/session fence、版本、能力和 `last_seen_at`；heartbeat 与 disconnect 必须匹配当前 session，避免旧连接覆盖新连接状态，连接/断开审计仍使用事务。

Deployment 使用 Project 范围的唯一幂等索引，并为“同一 Application、Environment 与 Runtime Target 上曾成功部署的 Release”建立回滚查询索引。`deployment_cutover_sequences` 只保存部署槽位及其当前序号，不保存运行凭据；Deployment 与审计在同一事务中创建时，序号分配也处于该事务内。Runtime Inventory 把新 observation 写成独立 generation，所有声明分块完成后才在一个事务中更新显式 `present/absent` current 投影并切换 current head；open generation 先设置两小时 TTL，完成时移除当前 generation 的 TTL，上一 generation 和 absent current 项在被替换七天后回收。

Migration v4 准备 Deployment 执行元数据，v5 建立 Registry Credential 索引，v6 为早期 Release 回填默认 CPU/内存运行规格，v7 允许同一 image digest 使用不同的不可变运行规格创建 Release，v8 建立 Organization Host 唯一命名和 Runtime Target Host 查询索引，v9 建立 enrollment token、过期清理、证书序列号/指纹和 Host 身份查询索引，v10 为已有 Deployment 回填槽位级 cutover sequence 并初始化序号计数器，v11 为登录尝试建立 TTL 回收索引，v12 建立 Runtime Inventory observation/chunk/resource/head 的唯一、查询和 TTL 索引，v13 建立 Runtime Inventory 周期调度与 Host 诊断索引，v14 建立 current presence 与 Event hint 查询/TTL 索引。

Runtime Inventory 还使用 `runtime_inventory_counters` 为每个 Runtime Target 原子分配单调 generation；多 Server 不使用本机时间判断 observation 新旧。

`runtime_inventory_schedule` 为每个 Runtime Target 保存下一次到期时间、短时 owner/expiry 和递增 token。多个 Server 同时领取时只有一个原子更新成功；完成调度必须匹配 owner 和 token，旧实例不能覆盖租约接管后的结果。该 collection 不保存 endpoint、凭据引用、证书或采集错误正文。

`runtime_inventory_current` 是可重建读取投影，不是另一份 Docker 事实来源；它保留最新安全资源摘要、presence、first/last seen、absent 时间和 generation。`runtime_inventory_event_hints` 只保留 24 小时安全摘要，Event 只把调度提前，不能直接改 current presence。

启动和事务写入时序见 [flows.md](flows.md)。

## 验证

普通单元测试不会启动容器：

```bash
make check
```

MongoDB 集成测试使用 Testcontainers 启动固定镜像的单节点 Replica Set，并验证连接、Ping、事务、migration 幂等、认证会话、共享登录尝试并发阈值与成功清理、活跃 Session 上限/查询/撤销、Agent token 只存哈希/原子消费/重放回滚、Agent mTLS 身份查询/online/heartbeat/重连 fence/禁用吊销、正式资源持久化、Deployment 领取/终态/取消/重试/回滚、Runtime Inventory open TTL/分块幂等/显式 present/absent/恢复/旧批次 fence/并发调度租约/Event 与 Finish 竞态、审计原子回滚和注销失效：

```bash
make test-integration
```
