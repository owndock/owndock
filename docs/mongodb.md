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

正式资源创建与对应审计事件在同一 MongoDB 事务中提交。Bootstrap 的 Organization、Owner、Session 与审计同样保持原子性。当前 collection 包括 `organizations`、`users`、`sessions`、`projects`、`product_applications`、`releases`、`runtime_targets`、`audit_events` 和 migration 元数据；索引只由版本化 migration 管理。

启动和事务写入时序见 [flows.md](flows.md)。

## 验证

普通单元测试不会启动容器：

```bash
make check
```

MongoDB 集成测试使用 Testcontainers 启动固定镜像的单节点 Replica Set，并验证连接、Ping、事务、migration 幂等、认证会话、正式资源持久化、审计原子回滚和注销失效：

```bash
make test-integration
```
