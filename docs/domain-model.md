# 产品领域模型与工程差距

OwnDock 已接受外部 OCI 镜像部署、Git-to-Deploy、多主机 Agent 和安全终端进入同一产品方向。本文件同时标明领域关系和当前实现状态；完整产品语义见 [product.md](product.md)。

```text
Organization 1 --* Managed Host
Managed Host 1 --0..1 active Agent Identity
Managed Host 1 --* Runtime Target
Organization 1 --* Project
Project 1 --* Source Repository
Project 1 --* Repository Credential
Source Repository * --0..1 Repository Credential
Project 1 --* Registry Credential
Template --可选快照--> Application 1 --* Release
Application 1 --* Build Configuration
Build Configuration 1 --* Build Trigger
Build Configuration 1 --* Build Hook
Build Configuration 1 --* Build 1 --0..1 Artifact
External CI --register digest--> Artifact
Artifact 1 --* Artifact Evidence
Artifact 1 --0..1 Release
Release 1 --* Deployment *--1 Environment
Deployment *--1 Runtime Target
Release *--0..1 Registry Credential
Runtime Target 1 --* Runtime Inventory Observation
Runtime Inventory Observation 1 --* Container/Image/Network/Volume
Runtime Target 1 --* Runtime Inventory Current State
Organization 1 --* Terminal Access Policy
Project 1 --0..1 Terminal Access Policy
Deployment 1 --* Container Terminal Session
Managed Host 1 --* Host Terminal Session
```

- Managed Host 是 Organization 纳管的实际 Linux 主机；
- Agent Enrollment 是短时一次性首次接入凭据，Agent Identity 是固定到 Host 和安装 instance 的机器身份；
- Source Repository 表示平台无关的标准 Git HTTPS/SSH 代码来源，Repository Credential 只保存外部秘密引用和安全展示元数据；
- Build Configuration 描述 Dockerfile、上下文、Registry、平台、资源限制和可选 development 自动部署目标；
- Build 是一次不可变构建执行；Artifact 是按 digest 固定的 OCI 镜像产品记录，可来自 OwnDock Build 或外部 CI。外部来源不伪造 Build 关系，生产者保持 `declared`，直到独立签名或 Provenance 完成验证；
- Artifact Evidence 是绑定 Artifact digest 的 SBOM、Provenance、签名或漏洞报告有界索引，完整证据正文不嵌入 MongoDB 主文档；授权下载按 OCI descriptor 读取并复核 subject、layer digest 与文档结构；
- Application 是长期软件服务身份；
- Release 是不可变可部署版本，并固定 OCI image digest；
- Environment 是 dev/staging/prod 等逻辑阶段；
- Runtime Target 是 Project 获准使用某台 Managed Host 上 Docker Engine 的部署入口；
- Deployment 是不可变部署操作，重试和回滚产生新操作；
- Runtime Inventory Observation 是一次完整 Docker 资源观测 generation，只有全部分块完成后才能事务更新 Current State；
- Runtime Inventory Current State 保存资源最后安全摘要与 `present/absent` 时间线，不完整批次不能修改它；
- Template 是可选的 Application 创建预设，不参与运行期隐式继承。
- Terminal Access Policy 固定角色、环境/目标范围、超时与并发；Terminal Session 固定操作者和受管目标，只保存安全元数据。

Template 已以社区版只读内置目录进入正式 API；创建 Application 时复制带版本的构建路径和运行规格快照，后续目录升级不会隐式修改已有 Application。团队私有模板、继承、自动同步和市场不在社区版当前边界。Build Configuration、三类 Build 触发入口、状态机、Mongo queue/lease/generation fence、Artifact/Release 交接和 development 自动 Deployment 已进入正式契约。
独立 Build Worker 已完成固定 Git 2.55.0、HTTPS/SSH 临时凭据、Host Key 固定、Commit 二次验证、受限工作区、rootless BuildKit 构建、认证 Registry push，以及 Artifact/Release 幂等交接；真实 OCI digest 在 lease generation fence 下形成唯一 Artifact。Source Repository 与 Repository Credential 已实现安全登记、执行期秘密解析和受限只读 Git probe；自建 CA/代理兼容矩阵仍待完成。
Agent Enrollment、Agent Identity、Server 端 mTLS/版本/心跳在线基础、类型化 probe/部署/Inventory 命令传输、`owndock-agent` 本机 Docker executor、secret-safe 小结果缓存与部署槽位持久水位已经实现。首次安装支持本地 Ed25519 私钥/CSR、稳定 instance、一次性 token 私有文件、完全相同请求的 10 分钟响应恢复、pending 恢复和原子配置落盘。Agent 证书支持到期前本地生成密钥和 CSR、pending 请求恢复、Server 幂等响应、最多 10 分钟旧证书过渡、单文件 identity bundle 原子安装和新 hello 确认。Agent 正式发行路径已提供确定性双架构包、GitHub OIDC Sigstore keyless 签名、精确 Tag 身份约束和离线验签，首个受保护 Tag 尚待执行。Runtime Inventory 已实现安全领域投影、分块 generation、MongoDB Repository、显式 present/absent current state、direct/Agent 编排、真实 Runtime Target/短时凭据接线、带 Mongo 分布式租约的全量与 Event 调度和传输故障门禁；Event 安全提示、调度合并、direct/Agent snapshot window、有界持续读取、Docker 时间游标和失败不推进语义已实现。成功 Deployment 归属核验、Project/Host 权限分离、固定过滤与不透明游标的公开审计查询也已实现；真实双主机断线/事件洪峰系统验收尚未完成。Enrollment、证书轮换和部署/终端的真实多主机故障系统验收仍未完成。

## 已实现的状态规则

正式 Deployment 固定 Organization、Project、Release、Application、Environment、Runtime Target 和幂等键引用；重试和回滚创建带来源关系的新操作，不修改原记录。重试仅允许来源状态为 `failed`；回滚来源必须已进入终态，目标 Release 必须不同于来源 Release，并且曾在同一 Application、Environment 和 Runtime Target 成功部署。状态允许 `queued`、`preparing`、`deploying`、`canceling`，并最终进入 `succeeded`、`failed` 或 `canceled`。失败记录只公开稳定类别，不持久化底层连接或凭据错误。

状态转换必须由领域方法执行，transport 层不得直接修改状态字段。异步 Worker 通过领域 Gateway 调用 Docker，不把 Docker 原始状态或错误直接暴露为 API 模型。

Managed Host 的初始状态由连接模式决定：`agent` 为 `enrolling`，`direct` 为 `offline`。首次 Agent enrollment 原子消费后，Host 绑定固定 Agent Identity 并进入 `offline`；只有后续 mTLS 控制流完成版本协商和心跳后才能进入 `online`。禁用 Host 会进入 `disabled`、吊销当前数据库身份并使未消费 enrollment 失效。

## 当前已实现的正式边界

已持久化并进入 `/api/v1` pre-release 契约的模型：

- 一个安装实例首次 bootstrap 一个 Organization 和 Owner；
- Managed Host 位于 Organization 下，连接模式固定为 `agent` 或 `direct`；Owner 可注册、创建 enrollment 和禁用，Maintainer 可读取，Project 权限不会自动授予主机权限；
- Agent Enrollment 永不保存原始 token，只保存 token hash 和过期/消费状态；首次响应恢复窗口内还保存精确请求 hash、Identity ID 和公开证书/CA。Agent Identity 保存固定 Host/instance、证书序列号/指纹/到期时间、Agent/协议版本和声明能力；
- Project 以 Organization 为查询、名称和所有权边界；Owner 隐式访问全部 Project，其他用户必须通过 Project Member 获得 Maintainer、Developer 或 Viewer 角色；
- Application 位于 Project 下；可选引用只读内置 Template，并持久化与目录后续版本脱钩的 `template_snapshot`；
- Release 位于 Application 下，只接受固定 SHA-256 digest 的 OCI image reference，创建后不可变，并固定端口、配置键、CPU/内存与可选健康检查；
- Registry Credential 位于 Project 下，只保存 registry server、username 和外部 `password_ref`，不保存密码正文；公开 API 只返回 `password_configured`，不回传引用；
- Repository Credential 位于 Project 下，只保存 SSH Deploy Key/HTTPS Access Token 类型、展示元数据和外部 `secret_ref`；API 只返回 `secret_configured`；
- Source Repository 位于 Project 下，只接受无凭据 HTTPS/SSH 地址；SSH 必须固定 Host Key fingerprint，凭据类型必须与协议一致，初始状态为 `pending`，显式探测后只保存安全状态和时间；
- Build Configuration 位于 Project/Application 下，版本化保存 Source Repository、Dockerfile/context、精确允许 ref、Registry Credential、无 tag/digest 的镜像仓库、单一平台、资源/超时/并发、自动 Release 意图和最多 8 个 development 自动部署目标；关联资源必须同属 Project，只有 Maintainer/Owner 可修改自动部署列表，更新使用乐观版本并与审计原子提交；
- Build 位于 Project 下，触发时固定 Application、Build Configuration、精确 ref、完整 Commit SHA 和非秘密配置快照；状态只能通过领域状态机转换，Worker 使用 lease/generation fencing，取消协作收敛，失败重试创建带来源关系的新 Build；Application 退役会按有界批次把非终态 Build 转为 `canceling` 并等待 Worker 收敛，但保留全部终态历史；相同 Project 幂等键只回放相同触发意图，资源变更与审计原子提交；
- Build Trigger 绑定一个 Build Configuration，允许 ref 只能收窄配置范围；外部请求只能提交 ref 和 Commit SHA，Trigger ID 进入 Build 幂等意图与审计，撤销后不可恢复；
- Build Hook 绑定一个平台和 Build Configuration，Webhook Secret 与 Repository Credential 分离；原始 body 验签后才解析，provider + Hook + delivery ID 唯一，合法但不适用的事件记录为 ignored；
- Artifact 位于 Project/Application 下，来源固定为 `owndock_build` 或 `external`。外部登记只接受完整 OCI SHA-256 digest，先用所选 Registry Credential 回读并验证 manifest，再在同一事务中保存 Artifact、审计和 Evidence Jobs；Application 退役会把尚未创建 Release 的自动交接明确终结为 `release_skipped`，围栏前已创建的 Release 则补齐为 `release_created`；登记幂等键不公开，外部 Artifact 没有 Build/Build Configuration ID，也不会生成 OwnDock Build Provenance 或由平台自动补签；
- Environment 位于 Project 下，阶段固定为 `development`、`staging` 或 `production`，保存 Release 配置键的普通值或 `secret://` 引用；
- Runtime Target 位于 Project 下，必须绑定同一 Organization 的 Managed Host，且连接模式必须一致；`direct` 要求带端口的 `tcp://` endpoint、TLS server name 和外部 `credential_ref`，`agent` 禁止这些直连字段；公开 API 只返回 `credential_configured`，显式探测只公开安全状态；删除先持久化 `retiring` 关闭 ready 门禁，再收敛容器 TerminalSession、清除可重建 Runtime Inventory、排空 Deployment、删除精确运行资源并回收 Agent 水位；
- Environment 内部保存运行变量绑定，但公开 API 只返回排序后的 `variable_keys`，不回传明文值或 `secret://` 引用；
- Application 与 Environment 使用 `active → retiring → retired` 持久生命周期。Release、Build、Deployment 与容器 Terminal 创建会在同一事务写 active 父资源 admission revision，不能越过并发退役围栏；后台按部署槽位清理运行实例和 Terminal 会话，但保留不可变 Release、Build、Deployment 与 Audit 历史；详见 [resource-retirement.md](resource-retirement.md)；
- Deployment 位于 Project 下，支持创建、查询、取消、失败重试和回滚；`trigger_source` 区分 manual/automatic，自动记录来源 Artifact、Build 和 Build Configuration；受管 Worker 使用原子领取、租约 heartbeat、同 Deployment generation fence、跨 Deployment cutover sequence 和安全失败分类；
- Session 只保存 access token 的单向哈希；每个用户的活跃 Session 数有配置上限，用户可治理自己的 Session，Owner 可治理同一 Organization 成员的 Session；删除与 Audit Event 在同一 MongoDB 事务中提交，所有列表都排除 Token/hash；
- 登录尝试按 normalized email 的 SHA-256 键在 MongoDB 共享计数，达到配置阈值后返回统一 `429` 和 `Retry-After`；正确登录清理计数，TTL 回收过期窗口。
- 正式产品入口按可信来源和整个安装两级共享限流；只有直连对端命中显式可信代理 CIDR 时才解析 `X-Forwarded-For`，来源只保存 SHA-256 键，保护存储不可用时失败关闭。
- Runtime Inventory 以 observation generation 写入 Container、Image、Network、Volume 的安全投影；新 generation 完整提交前不会修改 current presence，完整提交与 absent/present/head 切换处于同一事务，旧 observation 不能覆盖新视图。
- Terminal Access Policy 分为 Project 容器策略和 Organization 主机策略；TerminalSession 以 `pending/open/closing/closed/failed/expired` 状态持久化，一次性 ticket 只存 hash，并以 MongoDB 唯一并发槽位约束多 Server 创建。

当前采用内置角色 Owner、Maintainer、Developer、Viewer。Owner 是 Organization 全局角色；其余角色通过 Project Member 显式绑定。Session 不缓存 Project 角色，每次请求实时解析，因此删除和降权立即生效。自定义角色和 OIDC 不在当前社区切片内。

Deployment 权限独立于 Runtime Target：Developer 可创建、重试和取消部署，Maintainer 还可执行回滚，Viewer 仅可读取部署记录。创建、重试或回滚前都要求所选 Runtime Target 已处于 `ready`；否则返回 `409 runtime_target_not_ready`，不会先创建一个注定无法执行的排队任务。direct Target 通过受约束的 mTLS Docker Ping 探测，agent Target 通过当前已认证 Host 连接上的类型化 `runtime.probe` 探测；两种模式都只有显式探测成功后才进入 `ready`。

## 已接受但待完成或待验收

- Source Repository 自建 CA/代理兼容矩阵；
- Docker Runtime Inventory 的双主机、Primary 切换、客户资源峰值和 Web E2E；
- Agent 自动安装和证书安全轮换的真实发行/故障验收；
- 多主机部署选址系统验收；
- Terminal 真实远程 Linux/SSH、多主机故障和浏览器安全 E2E；
- 完整安全运维（安全告警、凭据轮换和发布前入口压力/故障验收）。

这些能力不能通过占位路由、假状态或工程样例提前声明为可用。

## 工程样例边界

顶层 Application、Environment、Deployment 路由由开发配置显式启用，使用进程内存仓储且没有认证授权。它们仅用于验证 `service → biz.UseCase → Repository/Gateway` 依赖方向，不能进入共享或生产网络，也不能作为正式 Project API 的兼容入口。

正式 HTTP Service 使用独立响应 DTO，领域实体不声明 JSON tag。Deployment 的内部 `Version`、`Lease.Owner`、`Lease.ExpiresAt`、`CutoverSequence` 与 Agent token/certificate hash 不属于普通公开 API；Mongo BSON 映射由 data adapter 独立定义。

## 下一步实现顺序

1. 在已实现自动 enrollment、固定身份、双端心跳连接、可恢复证书轮换、`runtime.probe`、两阶段部署和持久结果缓存上完成真实安装/轮换故障系统验收；
2. 使用两台真实 Agent 主机完成选址、断线、网络分区、延迟旧命令和过期 fence 系统验收；
3. 完成 Runtime Inventory 的双主机、容量、事件洪峰和秘密泄漏系统验收；
4. 按独立构建信任边界实现 Git-to-Deploy，不在 API Server 或生产 Runtime Target 内执行不可信 Dockerfile；
5. 在已完成 Terminal 控制面、direct/Agent 容器与主机 Gateway、活动撤权和 WSS 安全链路上继续完成真实远程与浏览器系统验收；
6. 建立密码恢复/OIDC、Template 商业治理扩展和生产安全告警能力；
7. 完成远程 mTLS Engine、真实代理入口压力、网络故障注入后移除或重塑工程样例。

当前和目标链路的时序见 [flows.md](flows.md)。
