# 目标架构

## 决策

OwnDock 采用 Kratos v2 的模块化单体。

Kratos 负责应用生命周期、HTTP/gRPC transport、中间件、配置和日志接入；领域模型、状态机、授权规则和数据所有权由各业务模块负责。框架能力不进入领域核心，基础设施通过接口替换。

第一阶段不使用 Google Wire。依赖在 `cmd/server` 显式组装，使资源创建、生命周期和测试替换点一眼可见，也避开已归档项目成为核心构建依赖。

## 模块边界

每个真实业务模块使用垂直切分：

```text
internal/modules/<domain>/
  biz/          实体、值对象、用例、仓储接口
  data/         MongoDB/外部系统适配器
  service/      transport DTO 与用例之间的转换
```

约束：

- `biz` 不依赖 Kratos transport、Mongo driver 或其他模块的 `data`；
- 跨模块调用通过用例接口或显式事件，不直接读写对方 collection；
- transport DTO 不作为持久化模型；
- 数据库 client、日志、遥测属于 `internal/platform`，领域仓储实现仍归模块所有；
- 只有出现独立扩缩容、故障隔离或团队所有权需求时，才把模块拆为服务。

## 进程边界

当前只建立 `cmd/server`，负责对外 API。agent、worker、CLI 等进程只在职责和生命周期明确后创建，不保留无实现的模板目录。Web 前端由独立项目维护。

## 版本策略

正式基线固定 Kratos v2.9.2，不跟随主分支上的 v3 开发状态。框架升级必须经过依赖审查、契约测试和回滚验证，不使用浮动版本。
