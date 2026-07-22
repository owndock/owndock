# OwnDock 核心领域模型

OwnDock 后端先围绕三个核心领域建立边界：应用（Application）、环境（Environment）和部署（Deployment）。本阶段只定义业务规则和仓储接口，不绑定 MongoDB、Docker 或具体云厂商。

## 关系

```text
Application 1 ──── * Deployment * ──── 1 Environment
```

- Application 表示用户希望交付和运行的软件单元。
- Environment 表示一个可承载应用的运行目标，例如本地 Docker、远程主机或后续 Kubernetes 集群。
- Deployment 表示某个应用版本投递到某个环境的一次不可变交付记录。

## 状态规则

应用创建后处于 `pending`；环境创建后处于 `active`。部署从 `queued` 依次进入 `building`、`deploying`，最终进入 `succeeded`、`failed` 或 `canceled`。

状态转换必须由领域方法执行，transport 层不得直接修改状态字段。异步 worker 后续只负责调用领域用例，不把 Docker/Kubernetes 状态直接暴露为 API 模型。

## 当前边界

三个领域都已采用 `service → biz.UseCase → Repository/Gateway` 依赖方向。Deployment 通过窄查询端口确认 Application 和 Environment 是否存在，不导入其他领域模型，也不跨模块访问数据适配器。

## 下一步实现顺序

1. 确认生产 MongoDB 支持矩阵后，用官方 Driver v2 适配器替换内存仓储，并保持 `biz.Repository` 接口稳定。
2. 为部署处理增加租约、幂等和真实执行器，再通过统一生命周期接入后台运行；开发期 `NoopExecutor` 不进入生产装配。
3. 增加租户、权限和审计事件，不把授权逻辑散落在 handler 中。
4. 在公开发布前固定 API 版本策略和生成式契约工具链。
