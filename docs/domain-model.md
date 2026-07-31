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
Runtime Target 1 --* Runtime Inventory Observation
Runtime Inventory Observation 1 --* Container/Image/Network/Volume
Runtime Target 1 --* Runtime Inventory Current State
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
- Runtime Inventory Observation 是一次完整 Docker 资源观测 generation，只有全部分块完成后才能事务更新 Current State；
- Runtime Inventory Current State 保存资源最后安全摘要与 `present/absent` 时间线，不完整批次不能修改它；
- Template 是可选的 Application 创建预设，不参与运行期隐式继承。

Template、Source Repository、Build Configuration、Build 和 Artifact 已进入产品模型，但尚未进入当前代码/API。Agent Enrollment、Agent Identity、Server 端 mTLS/版本/心跳在线基础、类型化 probe/部署/Inventory 命令传输、`owndock-agent` 本机 Docker executor、secret-safe 小结果缓存与部署槽位持久水位已经实现。Runtime Inventory 已实现安全领域投影、分块 generation、MongoDB Repository、显式 present/absent current state、direct/Agent 编排、真实 Runtime Target/短时凭据接线、带分布式租约的周期调度和传输故障门禁；Event 安全提示、调度合并、direct/Agent snapshot window 和真实 HTTP Agent transport 已实现，持续 Event 游标订阅和公开权限查询尚未实现。自动安装、证书轮换和部署/终端的多主机故障系统验收仍未实现。

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
- Deployment 位于 Project 下，支持创建、查询、取消、失败重试和回滚；受管 Worker 使用原子领取、租约 heartbeat、同 Deployment generation fence、跨 Deployment cutover sequence 和安全失败分类；
- Session 只保存 access token 的单向哈希；每个用户的活跃 Session 数有配置上限，用户可查看安全摘要并撤销自己的 Session，撤销与 Audit Event 在同一 MongoDB 事务中提交；
- 登录尝试按 normalized email 的 SHA-256 键在 MongoDB 共享计数，达到配置阈值后返回统一 `429` 和 `Retry-After`；正确登录清理计数，TTL 回收过期窗口。
- Runtime Inventory 以 observation generation 写入 Container、Image、Network、Volume 的安全投影；新 generation 完整提交前不会修改 current presence，完整提交与 absent/present/head 切换处于同一事务，旧 observation 不能覆盖新视图。

当前采用 Organization 级内置角色 Owner、Maintainer、Developer、Viewer。自定义角色、细粒度 Project 成员绑定和 OIDC 不在当前社区切片内。

Deployment 权限独立于 Runtime Target：Developer 可创建、重试和取消部署，Maintainer 还可执行回滚，Viewer 仅可读取部署记录。创建、重试或回滚前都要求所选 Runtime Target 已处于 `ready`；否则返回 `409 runtime_target_not_ready`，不会先创建一个注定无法执行的排队任务。direct Target 通过受约束的 mTLS Docker Ping 探测，agent Target 通过当前已认证 Host 连接上的类型化 `runtime.probe` 探测；两种模式都只有显式探测成功后才进入 `ready`。

## 已接受但尚未实现

- Template 创建和快照实例化；
- Source Repository、Repository Credential、Build Configuration、Build、Artifact、Build Worker/BuildKit 和 Webhook Adapter；
- Docker Runtime Inventory 的 direct/Agent 持续 Event 游标订阅、Host/Project 权限和公开查询 API；
- Agent 自动安装、部署/取消执行、证书安全轮换和 Agent Runtime Gateway；
- 多主机部署选址系统验收；
- TerminalSession、容器 exec、主机 PTY、WSS 终端传输和终端访问策略；
- 用户管理、Project 成员绑定、来源 IP/全局入口限流、管理员级全用户会话治理和完整安全运维。

这些能力不能通过占位路由、假状态或工程样例提前声明为可用。

## 工程样例边界

顶层 Application、Environment、Deployment 路由由开发配置显式启用，使用进程内存仓储且没有认证授权。它们仅用于验证 `service → biz.UseCase → Repository/Gateway` 依赖方向，不能进入共享或生产网络，也不能作为正式 Project API 的兼容入口。

正式 HTTP Service 使用独立响应 DTO，领域实体不声明 JSON tag。Deployment 的内部 `Version`、`Lease.Owner`、`Lease.ExpiresAt`、`CutoverSequence` 与 Agent token/certificate hash 不属于普通公开 API；Mongo BSON 映射由 data adapter 独立定义。

## 下一步实现顺序

1. 在已实现 enrollment、固定身份、双端心跳连接、`runtime.probe`、两阶段部署和持久结果缓存上完成安装自动化和证书轮换；
2. 使用两台真实 Agent 主机完成选址、断线、网络分区、延迟旧命令和过期 fence 系统验收；
3. 完成 Runtime Inventory 的 Event 对账和权限查询；
4. 按独立构建信任边界实现 Git-to-Deploy，不在 API Server 或生产 Runtime Target 内执行不可信 Dockerfile；
5. 完成 Terminal 权限、TerminalSession、容器 exec、主机 PTY 和 WSS 安全链路；
6. 建立 Template、用户/成员管理以及生产安全运维能力；
7. 完成远程 mTLS Engine、入口流量、网络故障注入后移除或重塑工程样例。

当前和目标链路的时序见 [flows.md](flows.md)。
