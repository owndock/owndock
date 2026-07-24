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

正式 Deployment 已在领域层固定 Release、Application、Environment、Runtime Target 和幂等键引用；重试和回滚仍创建新操作。状态允许 `queued`、`building`、`deploying`、`canceling`，并最终进入 `succeeded`、`failed` 或 `canceled`。当前执行仍需接入正式 API、Worker 和 Docker Gateway。

状态转换必须由领域方法执行，transport 层不得直接修改状态字段。异步 worker 后续只负责调用领域用例，不把 Docker/Kubernetes 状态直接暴露为 API 模型。

## 当前正式边界

已持久化并进入 `/api/v1` pre-release 契约的模型：

- 一个安装实例首次 bootstrap 一个 Organization 和 Owner；
- Project 以 Organization 为查询、名称和所有权边界；
- Application 位于 Project 下；
- Release 位于 Application 下，只接受固定 SHA-256 digest 的 OCI image reference，创建后不可变；
- Environment 位于 Project 下，阶段固定为 `development`、`staging` 或 `production`，不保存运行时凭据；
- Runtime Target 位于 Project 下，只接受带端口的 `tcp://` endpoint、TLS server name 和外部 `credential_ref`；
- Session 只保存 access token 的单向哈希；写操作与对应 Audit Event 在同一 MongoDB 事务中提交。

当前采用 Organization 级内置角色 Owner、Maintainer、Developer、Viewer。自定义角色、细粒度 Project 成员绑定和 OIDC 不在当前社区切片内。

Deployment 权限独立于 Runtime Target：Developer 可创建部署但不能取消部署，Maintainer 可取消部署，Viewer 仅可读取部署记录。

## 工程样例边界

现有三个模块都已采用 `service → biz.UseCase → Repository/Gateway` 依赖方向。Deployment 通过窄查询端口确认 Application 和 Environment 是否存在，不导入其他领域模型，也不跨模块访问数据适配器。

HTTP Service 使用独立响应 DTO，领域实体不声明 JSON tag。Deployment 的内部 `Version`、`Lease.Owner` 和 `Lease.ExpiresAt` 不属于公开 API，未来 Mongo BSON 映射也由 data adapter 独立定义。

Deployment Repository 已定义原子 `ClaimNext` 与带期望版本的 `SaveClaimed`，用于验证并发控制模式。这些机制可以作为正式实现证据，但接口必须根据 Project、Release、Environment、Runtime Target、幂等和审计要求重新设计。

## 下一步实现顺序

1. 建立 Template 和正式 Deployment 模型；Environment 已完成正式持久化切片。
2. 明确 Runtime Target 凭据存储与连接探测边界。
3. 接入真实 Docker 执行，完成幂等、取消、重试和回滚。
4. 增加用户管理、Project 成员绑定、登录限流和安全运维能力。
5. 通过首个端到端用例后移除或重塑工程样例。

当前和目标链路的时序见 [flows.md](flows.md)。
