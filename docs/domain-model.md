# 产品领域模型与工程差距

OwnDock 已接受外部 OCI 镜像部署、Git-to-Deploy、多主机 Agent 和安全终端进入同一产品方向。本文件同时标明领域关系和当前实现状态；完整产品语义见 [product.md](product.md)。

```text
Organization 1 --* Managed Host
Managed Host 1 --0..1 active Agent Identity
Managed Host 1 --* Runtime Target
Organization 1 --* Project
Project 1 --* Source Repository
Project 1 --* Registry Credential
Template --可选快照--> Application 1 --* Release
Application 1 --* Build Configuration
Build Configuration 1 --* Build 1 --0..1 Artifact
Artifact 1 --0..1 Release
Release 1 --* Deployment *--1 Environment
Deployment *--1 Runtime Target
Release *--0..1 Registry Credential
```

- Managed Host 是 Organization 纳管的实际 Linux 主机；
- Agent Enrollment 是短时一次性首次接入凭据，Agent Identity 是固定到 Host 和安装 instance 的机器身份；
- Source Repository 表示平台无关的标准 Git HTTPS/SSH 代码来源；
- Build Configuration 描述 Dockerfile、上下文、Registry、平台和资源限制；
- Build 是一次不可变构建执行，Artifact 是按 digest 固定的 OCI 构建结果；
- Application 是长期软件服务身份；
- Release 是不可变可部署版本，并固定 OCI image digest；
- Environment 是 dev/staging/prod 等逻辑阶段；
- Runtime Target 是 Project 获准使用某台 Managed Host 上 Docker Engine 的部署入口；
- Deployment 是不可变部署操作，重试和回滚产生新操作；
- Template 是可选的 Application 创建预设，不参与运行期隐式继承。

Template、Source Repository、Build Configuration、Build 和 Artifact 已进入产品模型，但尚未进入当前代码/API。Agent Enrollment、Agent Identity 和 Server 端 mTLS/版本/心跳在线基础已经实现，Server 端还具备首个 `runtime.probe` 类型化命令传输；Agent 进程、实际命令执行器和 Runtime Gateway 仍未实现。

## 已实现的状态规则

正式 Deployment 固定 Organization、Project、Release、Application、Environment、Runtime Target 和幂等键引用；重试和回滚创建带来源关系的新操作，不修改原记录。重试仅允许来源状态为 `failed`；回滚来源必须已进入终态，目标 Release 必须不同于来源 Release，并且曾在同一 Application、Environment 和 Runtime Target 成功部署。状态允许 `queued`、`preparing`、`deploying`、`canceling`，并最终进入 `succeeded`、`failed` 或 `canceled`。失败记录只公开稳定类别，不持久化底层连接或凭据错误。

状态转换必须由领域方法执行，transport 层不得直接修改状态字段。异步 Worker 通过领域 Gateway 调用 Docker，不把 Docker 原始状态或错误直接暴露为 API 模型。

Managed Host 的初始状态由连接模式决定：`agent` 为 `enrolling`，`direct` 为 `offline`。首次 Agent enrollment 原子消费后，Host 绑定固定 Agent Identity 并进入 `offline`；只有后续 mTLS 控制流完成版本协商和心跳后才能进入 `online`。禁用 Host 会进入 `disabled`、吊销当前数据库身份并使未消费 enrollment 失效。

## 当前已实现的正式边界

已持久化并进入 `/api/v1` pre-release 契约的模型：

- 一个安装实例首次 bootstrap 一个 Organization 和 Owner；
- Managed Host 位于 Organization 下，连接模式固定为 `agent` 或 `direct`；Owner 可注册、创建 enrollment 和禁用，Maintainer 可读取，Project 权限不会自动授予主机权限；
- Agent Enrollment 只保存 token hash 和过期/消费状态；Agent Identity 保存固定 Host/instance、证书序列号/指纹/到期时间、Agent/协议版本和声明能力；
- Project 以 Organization 为查询、名称和所有权边界；
- Application 位于 Project 下；
- Release 位于 Application 下，只接受固定 SHA-256 digest 的 OCI image reference，创建后不可变，并固定端口、配置键、CPU/内存与可选健康检查；
- Registry Credential 位于 Project 下，只保存 registry server、username 和外部 `password_ref`，不保存密码正文；
- Environment 位于 Project 下，阶段固定为 `development`、`staging` 或 `production`，保存 Release 配置键的普通值或 `secret://` 引用；
- Runtime Target 位于 Project 下，必须绑定同一 Organization 的 Managed Host，且连接模式必须一致；`direct` 要求带端口的 `tcp://` endpoint、TLS server name 和外部 `credential_ref`，`agent` 禁止这些直连字段；显式 direct 探测只公开 `ready`、`unreachable` 或 `credential_error` 安全状态；
- Deployment 位于 Project 下，支持创建、查询、取消、失败重试和回滚；受管 Worker 使用原子领取、租约 heartbeat、generation fence 和安全失败分类；
- Session 只保存 access token 的单向哈希；写操作与对应 Audit Event 在同一 MongoDB 事务中提交。

当前采用 Organization 级内置角色 Owner、Maintainer、Developer、Viewer。自定义角色、细粒度 Project 成员绑定和 OIDC 不在当前社区切片内。

Deployment 权限独立于 Runtime Target：Developer 可创建、重试和取消部署，Maintainer 还可执行回滚，Viewer 仅可读取部署记录。创建、重试或回滚前都要求所选 Runtime Target 已处于 `ready`；否则返回 `409 runtime_target_not_ready`，不会先创建一个注定无法执行的排队任务。当前只有显式探测成功的 direct Target 可以进入 `ready`。

## 已接受但尚未实现

- Template 创建和快照实例化；
- Source Repository、Repository Credential、Build Configuration、Build、Artifact、Build Worker/BuildKit 和 Webhook Adapter；
- Agent 进程、Agent 侧命令执行与持久幂等结果、证书安全轮换和 Agent Runtime Gateway；
- 多主机部署选址系统验收；
- TerminalSession、容器 exec、主机 PTY、WSS 终端传输和终端访问策略；
- 用户管理、Project 成员绑定、登录限流和完整安全运维。

这些能力不能通过占位路由、假状态或工程样例提前声明为可用。

## 工程样例边界

顶层 Application、Environment、Deployment 路由由开发配置显式启用，使用进程内存仓储且没有认证授权。它们仅用于验证 `service → biz.UseCase → Repository/Gateway` 依赖方向，不能进入共享或生产网络，也不能作为正式 Project API 的兼容入口。

正式 HTTP Service 使用独立响应 DTO，领域实体不声明 JSON tag。Deployment 的内部 `Version`、`Lease.Owner`、`Lease.ExpiresAt` 与 Agent token/certificate hash 不属于普通公开 API；Mongo BSON 映射由 data adapter 独立定义。

## 下一步实现顺序

1. 在已实现 enrollment、固定身份、心跳连接和 Server 端 `runtime.probe` 传输上完成 Agent 进程、Agent 侧持久幂等结果和证书轮换；
2. 接入 Agent Docker Runtime Gateway，并完成两主机不得串目标的系统验收；
3. 按独立构建信任边界实现 Git-to-Deploy，不在 API Server 或生产 Runtime Target 内执行不可信 Dockerfile；
4. 完成 Terminal 权限、TerminalSession、容器 exec、主机 PTY 和 WSS 安全链路；
5. 建立 Template、用户/成员管理以及生产安全运维能力；
6. 完成远程 mTLS Engine、入口流量、网络故障注入后移除或重塑工程样例。

当前和目标链路的时序见 [flows.md](flows.md)。
