# OwnDock 文档导航

本文档目录同时记录产品目标和当前工程事实。为避免把计划误写成已交付能力，所有说明遵循三种状态：

- **已实现**：代码、API 契约和相应测试已经存在；
- **已接受、待完成或待验收**：属于当前产品方向，但实现或生产级系统证据尚未完整，不能对用户开放；
- **暂不支持**：没有进入当前产品范围，不能因为旧系统或底层组件存在就默认提供。

## 从哪里开始

| 读者 | 推荐入口 |
| --- | --- |
| 产品、设计、官网内容 | [产品定义](product.md) |
| 创建应用与内置预设 | [内置 Template 与 Application 快照](templates.md) |
| Git-to-Deploy 设计与内容 | [Git-to-Deploy 产品与安全边界](git-to-deploy.md) 与 [Source Repository 使用说明](source-repositories.md) |
| 第一次从 Git 部署 | [从 Git 到开发环境：完整用户旅程](git-to-deploy-quickstart.md) |
| 构建配方 | [Build Configuration 使用说明](build-configurations.md) |
| Registry 公开/私有连接 | [Registry 连接、匿名访问与 Basic 认证](registry-connections.md) |
| 手动构建 | [手动触发 Build](builds.md) |
| OwnDock/外部 CI 镜像与 Release | [Artifact 来源、外部登记与 Release 交接](artifacts.md) |
| 镜像 SBOM、签名与来源证据 | [Artifact Evidence：镜像证据索引](artifact-evidence.md) |
| 漏洞库下载、原子切换与恢复 | [Trivy 漏洞库快照运维](vulnerability-database.md) |
| 精确、限时且可审计的漏洞例外 | [漏洞豁免：如何临时接受一个已知风险](vulnerability-waivers.md) |
| 部署前检查镜像证据 | [Deployment Policy：部署准入规则与冻结快照](deployment-policies.md) |
| SLSA 字段与 Builder 信任边界 | [OwnDock Dockerfile Build Provenance v1](provenance-build-type.md) |
| 开发环境持续交付 | [自动部署规则](automatic-deployments.md) |
| Build Worker 运维与安全 | [Build Worker 运行与安全边界](build-worker.md) |
| Worker 指标、Trace 与告警 | [Worker 可观测性与告警](worker-observability.md) |
| Git-to-Deploy 安全验收 | [构建攻击、故障与秘密门禁](build-security-acceptance.md) |
| 构建日志与排障 | [Build 日志与排障](build-logs.md) |
| Git 平台自动触发 | [Build Trigger Token](build-triggers.md) |
| GitHub/GitLab/Gitea/Forgejo 自动触发 | [Git 平台 Webhook](webhooks.md) |
| 后端开发者 | [目标架构](architecture.md) 与 [领域模型](domain-model.md) |
| 后端测试与 CI | [Go 测试与变更覆盖率门禁](testing.md) |
| 社区版发布维护者 | [发布候选自动门禁与外部验收边界](release-readiness.md) |
| 前端和 API 客户端 | [API 契约说明](../api/README.md)、[OpenAPI](../api/openapi.yaml) 与 [Agent Control v1](../api/agent-control.md) |
| Web 前端跨域与 Token 安全 | [浏览器接入 API：Origin、Token 与安全响应头](browser-api-security.md) |
| 中英文界面、官网与开发文档 | [多语言与本地化](localization.md) |
| 本地账号与团队接入 | [本地用户邀请](users-and-invitations.md) |
| Project 成员、角色与即时撤权 | [Project 成员与权限](project-members.md) |
| 主机与容器终端 | [安全终端会话](terminal-sessions.md) |
| 终端页面、状态与客户操作说明 | [容器与主机终端用户旅程](terminal-user-journey.md) |
| 终端安全评审与发布门禁 | [终端威胁模型、安全指标与验收](terminal-security-acceptance.md) |
| 部署和运维人员 | [产品 API 入口保护](ingress-protection.md)、[MongoDB 基线](mongodb.md)、[Deployment Worker](worker.md)、[Docker Runtime Inventory](runtime-inventory.md)、[Inventory 验收手册](runtime-inventory-acceptance.md) |
| 单节点安装和恢复 | [社区版单节点安装、备份与恢复](community-installation.md) |
| Agent 安装与安全评审 | [Agent 安装、升级与回滚](agent-installation.md)、[Agent 运行与配置](agent.md)、[Agent 安全接入](agent-enrollment.md) |
| Agent 发布者与下载验签 | [Agent 正式发布与制品验签](release-security.md) |
| Agent/Server 升级与协议兼容 | [Agent 与 Server 版本兼容策略](agent-compatibility.md) |
| 联调和流程理解 | [核心流程时序](flows.md) |
| 安全问题报告 | [安全策略](../SECURITY.md) |

## 当前交付状态

| 状态 | 能力 |
| --- | --- |
| 已实现 | 后端 `zh-CN/en-US` 错误目录、`Accept-Language` 协商与 `Content-Language`；本地身份、活跃 Session 上限/自助治理、Owner 同组织会话治理、MongoDB 共享登录尝试限制、可信代理来源解析与来源/实例两级入口限流、内置 RBAC、Managed Host、Agent 一次性 enrollment/证书身份、Server 端 mTLS 连接/版本/心跳/`runtime.probe` 传输、`owndock-agent` 控制客户端/重连/本机 Docker probe/持久小结果缓存/部署切换水位、Agent 确定性双架构包/Sigstore keyless 发布签名/离线验签、Project/Application/Release/Registry Credential/Environment/Runtime Target/Deployment、Source Repository/Repository Credential 安全登记与只读探测、Build Configuration、手动 queued Build、一次显示且只存哈希的通用 Build Trigger Token、GitHub/GitLab/Gitea/Forgejo 签名 Webhook 与 delivery 去重、Build 状态机/Mongo lease、独立 Build Worker 的固定 Git 2.55.0 HTTPS/SSH 精确 Commit 检出、rootless BuildKit 构建和认证 Registry push、OwnDock Build 与外部 CI digest 的双来源 Artifact、Registry manifest 完整性探测、生产者信任标记和幂等 Release 交接、digest 绑定的 Artifact Evidence 有界索引/授权下载 API、OCI Referrers 原生/Tag Schema 能力探测、Evidence Job queue/lease/generation fence 与事务发布协议、独立 Evidence Worker、Artifact 事务排队、执行期 Registry 凭据、受限容器和固定 Syft 真实 Registry/CycloneDX 1.6 门禁、固定 Commit/配置快照/Builder/output digest 的 SLSA Provenance v1、固定 Trivy 的构建后/手动漏洞扫描、原子 DB 快照更新、受限离线扫描、OCI 详细报告与最新有界 stale 摘要、精确漏洞 ID 的 Project/Artifact 限时豁免与事务审计、Project/Environment 版本化 Deployment Policy、证据/签名/漏洞/豁免准入求值与不可变 Deployment 快照、development 显式自动部署规则、有界脱敏 Build 日志和 cursor API、基础审计、MongoDB migration、direct Docker Worker 基础执行；Docker Runtime Inventory 已有分代 current 投影、四类安全 mapper、Agent 分块与 Event 协议、Mongo 租约 Worker、成功 Deployment 归属核验，以及 Project/Host 权限分离的审计查询 API，但采集 Worker 默认关闭 |
| 已接受、待完成或待验收 | Evidence Worker 的真实超大镜像/生产出口系统验收、持续重扫调度和其他 KMS 客户矩阵；Web/官网/客户文档双语发布与正式客户 CLI；Git 自建 CA/代理兼容矩阵、Docker Inventory 双主机/客户等价 MongoDB 认证 TLS 故障切换/资源峰值/Web E2E、首个受保护 Agent Tag 的公开发行证据、enrollment/证书轮换真实故障注入、多主机升级/回滚系统验收、Terminal 真实远程 Linux/SSH 故障与浏览器 E2E |
| 暂不支持 | 任意 YAML/Shell 流水线、Kubernetes 运行时、浏览器提供任意 Docker 地址或容器 ID、无审计的主机访问 |

Terminal 当前已完成五项权限、Project/Organization 访问策略、TerminalSession 状态机、固定目标解析、MongoDB 并发槽位、一次性安全 Cookie、登录会话重新确认、活动连接周期复核与撤权宽限、REST API、同域 WSS、direct/Agent 受限容器与主机 Gateway 和元数据审计；真实远程 Linux/SSH、多主机故障和浏览器 E2E 尚未完成。详见[安全终端会话](terminal-sessions.md)。

这里的“已实现”不等同于生产就绪。远程 mTLS Engine、真实代理入口压测、网络故障注入以及完整安全系统测试通过前，当前版本仍是 pre-release。
