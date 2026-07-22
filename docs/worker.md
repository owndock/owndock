# Deployment Worker

Deployment API 只负责创建不可变的交付记录，初始状态为 `queued`。Worker 负责消费队列并推进状态：

```text
queued → building → deploying → succeeded
```

真实构建器和运行时适配器尚未绑定。Worker 只依赖 `biz.Repository`，因此可以先用内存仓储测试流程，再接入队列、Docker、Kubernetes 或远程主机执行器。

Worker 通过 `Executor` 接口调用构建和部署：执行器失败会将部署置为 `failed`。当前提供 `NoopExecutor` 作为开发期适配器，生产环境必须替换为真实执行器。

项目已提供通用生命周期适配器 `internal/platform/lifecycle.Server`。真实 Worker 必须通过该适配器加入 Kratos App，不能在 composition root 或构造函数中自行派生无人管理的 goroutine。当前 Deployment Worker 尚未进入生产装配，避免 `NoopExecutor` 将真实任务错误标记为成功。

生产实现需要补充：

- 租约或乐观锁，避免多个 Worker 重复处理同一部署；
- 每一步的事件和日志记录；
- 超时、重试和幂等键；
- 失败状态及人工重试接口。
