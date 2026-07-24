# 产品领域模型与工程差距

OwnDock 已接受 Template、Application、Release、Environment、Runtime Target 和 Deployment 的产品边界，完整定义见 [product.md](product.md)。

```text
Template --可选快照--> Application 1 --* Release
Release 1 --* Deployment *--1 Environment
Deployment *--1 Runtime Target
```

- Application 是长期软件服务身份；
- Release 是不可变可部署版本，并固定 OCI image digest；
- Environment 是 dev/staging/prod 等逻辑阶段；
- Runtime Target 是实际 Docker Engine 运行目标；
- Deployment 是不可变部署操作，重试和回滚产生新操作；
- Template 是可选的 Application 创建预设，不参与运行期隐式继承。

## 状态规则

当前工程样例中的应用创建后处于 `pending`，环境创建后处于 `active`，部署从 `queued` 依次进入 `building`、`deploying`，最终进入 `succeeded`、`failed` 或 `canceled`。这些状态只属于当前样例；正式 Deployment 至少采用 queued、running、succeeded、failed、canceling、canceled，并通过单独设计确定 Docker 执行阶段。

状态转换必须由领域方法执行，transport 层不得直接修改状态字段。异步 worker 后续只负责调用领域用例，不把 Docker/Kubernetes 状态直接暴露为 API 模型。

## 当前边界

现有三个模块都已采用 `service → biz.UseCase → Repository/Gateway` 依赖方向。Deployment 通过窄查询端口确认 Application 和 Environment 是否存在，不导入其他领域模型，也不跨模块访问数据适配器。

HTTP Service 使用独立响应 DTO，领域实体不声明 JSON tag。Deployment 的内部 `Version`、`Lease.Owner` 和 `Lease.ExpiresAt` 不属于公开 API，未来 Mongo BSON 映射也由 data adapter 独立定义。

Deployment Repository 已定义原子 `ClaimNext` 与带期望版本的 `SaveClaimed`，用于验证并发控制模式。这些机制可以作为正式实现证据，但接口必须根据 Project、Release、Environment、Runtime Target、幂等和审计要求重新设计。

## 下一步实现顺序

1. 定义首个正式 `/api/v1` 契约和 Project 所有权。
2. 建立 Organization、Project、Release、Runtime Target 与 Template 模块边界。
3. 实现身份、授权、基础审计、MongoDB Repository 和 migration。
4. 接入真实 Docker 执行，完成幂等、取消、重试和回滚。
5. 通过端到端用例后再将工程路由替换为正式产品契约。
