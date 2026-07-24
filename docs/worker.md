# Deployment Worker

> 本文描述并发与生命周期工程样例，不代表 Deployment 已成为正式产品能力。样例 Worker 默认不装配到生产进程。

Deployment API 创建身份与目标不可变、执行状态可演进的交付记录，初始状态为 `queued`。Worker 负责消费队列并推进状态：

```text
queued → building → deploying → succeeded
```

真实构建器和运行时适配器尚未绑定。Worker 只依赖 `biz.Repository`，因此可以先用内存仓储测试流程，再接入队列、Docker、Kubernetes 或远程主机执行器。

Worker 不再使用“全量 List 后 Update”的领取方式。Repository 的 `ClaimNext` 必须原子地把 `queued` 任务推进到 `building`，或接管租约已过期的 `building/deploying` 任务，同时写入 worker ID、租约截止时间和递增版本。后续 `SaveClaimed` 同时校验 owner、租约和期望版本，阻止旧 Worker 覆盖新状态。

Worker 通过 `Executor` 接口调用构建和部署：执行器失败会将部署置为 `failed`，并把原始错误返回给调度边界用于日志、指标和退避。当前提供 `NoopExecutor` 作为开发期适配器，生产环境必须替换为真实执行器。

租约接管意味着 Build/Deploy 可能在进程失联后重试，因此真实 Executor 必须以 Deployment ID（必要时加 step）作为幂等键。当前 Runner 在步骤完成后续租；真实长耗时步骤还需要心跳续租，且步骤 timeout 必须小于可证明安全的租约窗口。

项目已提供通用生命周期适配器 `internal/platform/lifecycle.Server`。真实 Worker 必须通过该适配器加入 Kratos App，不能在 composition root 或构造函数中自行派生无人管理的 goroutine。当前 Deployment Worker 尚未进入生产装配，避免 `NoopExecutor` 将真实任务错误标记为成功。

生产实现需要补充：

- Mongo 适配器用原子条件更新实现现有租约与乐观锁契约；
- 长任务心跳续租和 fenced token，进一步阻止租约过期后的旧执行器产生副作用；
- 每一步的事件和日志记录；
- 超时、重试和幂等键；
- 失败状态及人工重试接口。
