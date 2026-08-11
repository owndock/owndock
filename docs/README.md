# OwnDock 文档导航

本文档目录同时记录产品目标和当前工程事实。为避免把计划误写成已交付能力，所有说明遵循三种状态：

- **已实现**：代码、API 契约和相应测试已经存在；
- **已接受、尚未实现**：属于当前产品方向，但还不能对用户开放；
- **暂不支持**：没有进入当前产品范围，不能因为旧系统或底层组件存在就默认提供。

## 从哪里开始

| 读者 | 推荐入口 |
| --- | --- |
| 产品、设计、官网内容 | [产品定义](product.md) |
| Git-to-Deploy 设计与内容 | [Git-to-Deploy 产品与安全边界](git-to-deploy.md) 与 [Source Repository 使用说明](source-repositories.md) |
| 第一次从 Git 部署 | [从 Git 到开发环境：完整用户旅程](git-to-deploy-quickstart.md) |
| 构建配方 | [Build Configuration 使用说明](build-configurations.md) |
| 手动构建 | [手动触发 Build](builds.md) |
| 构建结果与 Release | [Artifact 与 Release 交接](artifacts.md) |
| 开发环境持续交付 | [自动部署规则](automatic-deployments.md) |
| Build Worker 运维与安全 | [Build Worker 运行与安全边界](build-worker.md) |
| Worker 指标、Trace 与告警 | [Worker 可观测性与告警](worker-observability.md) |
| Git-to-Deploy 安全验收 | [构建攻击、故障与秘密门禁](build-security-acceptance.md) |
| 构建日志与排障 | [Build 日志与排障](build-logs.md) |
| Git 平台自动触发 | [Build Trigger Token](build-triggers.md) |
| GitHub/GitLab/Gitea/Forgejo 自动触发 | [Git 平台 Webhook](webhooks.md) |
| 后端开发者 | [目标架构](architecture.md) 与 [领域模型](domain-model.md) |
| 前端和 API 客户端 | [API 契约说明](../api/README.md)、[OpenAPI](../api/openapi.yaml) 与 [Agent Control v1](../api/agent-control.md) |
| Web 前端跨域与 Token 安全 | [浏览器接入 API：Origin、Token 与安全响应头](browser-api-security.md) |
| 中英文界面、官网与开发文档 | [多语言与本地化](localization.md) |
| 本地账号与团队接入 | [本地用户邀请](users-and-invitations.md) |
| Project 成员、角色与即时撤权 | [Project 成员与权限](project-members.md) |
| 主机与容器终端 | [安全终端会话](terminal-sessions.md) |
| 终端安全评审与发布门禁 | [终端威胁模型、安全指标与验收](terminal-security-acceptance.md) |
| 部署和运维人员 | [产品 API 入口保护](ingress-protection.md)、[MongoDB 基线](mongodb.md)、[Deployment Worker](worker.md)、[Docker Runtime Inventory](runtime-inventory.md)、[Inventory 验收手册](runtime-inventory-acceptance.md) |
| Agent 安装与安全评审 | [Agent 运行与配置](agent.md)、[Agent 安全接入](agent-enrollment.md) |
| 联调和流程理解 | [核心流程时序](flows.md) |
| 安全问题报告 | [安全策略](../SECURITY.md) |

## 当前交付状态

| 状态 | 能力 |
| --- | --- |
| 已实现 | 后端 `zh-CN/en-US` 错误目录、`Accept-Language` 协商与 `Content-Language`；本地身份、活跃 Session 上限/自助治理、Owner 同组织会话治理、MongoDB 共享登录尝试限制、可信代理来源解析与来源/实例两级入口限流、内置 RBAC、Managed Host、Agent 一次性 enrollment/证书身份、Server 端 mTLS 连接/版本/心跳/`runtime.probe` 传输、`owndock-agent` 控制客户端/重连/本机 Docker probe/持久小结果缓存/部署切换水位、Project/Application/Release/Registry Credential/Environment/Runtime Target/Deployment、Source Repository/Repository Credential 安全登记与只读探测、Build Configuration、手动 queued Build、一次显示且只存哈希的通用 Build Trigger Token、GitHub/GitLab/Gitea/Forgejo 签名 Webhook 与 delivery 去重、Build 状态机/Mongo lease、独立 Build Worker 的固定 Git 2.55.0 HTTPS/SSH 精确 Commit 检出、rootless BuildKit 构建和认证 Registry push、Artifact 与幂等 Release 交接、development 显式自动部署规则、有界脱敏 Build 日志和 cursor API、基础审计、MongoDB migration、direct Docker Worker 基础执行；Docker Runtime Inventory 已有分代 current 投影、四类安全 mapper、Agent 分块与 Event 协议、Mongo 租约 Worker、成功 Deployment 归属核验，以及 Project/Host 权限分离的审计查询 API，但采集 Worker 默认关闭 |
| 已接受、尚未实现 | Web/官网/客户文档双语发布与正式客户 CLI；Template、Git 自建 CA/代理兼容矩阵、Docker Inventory 持续 Event/容量/秘密泄漏系统验收、Agent 安装自动化、证书轮换真实故障注入、多主机系统验收、Terminal 真实远程 Linux/SSH 故障与浏览器 E2E |
| 暂不支持 | 任意 YAML/Shell 流水线、Kubernetes 运行时、浏览器提供任意 Docker 地址或容器 ID、无审计的主机访问 |

Terminal 当前已完成五项权限、Project/Organization 访问策略、TerminalSession 状态机、固定目标解析、MongoDB 并发槽位、一次性安全 Cookie、登录会话重新确认、活动连接周期复核与撤权宽限、REST API、同域 WSS、direct/Agent 受限容器与主机 Gateway 和元数据审计；真实远程 Linux/SSH、多主机故障和浏览器 E2E 尚未完成。详见[安全终端会话](terminal-sessions.md)。

这里的“已实现”不等同于生产就绪。远程 mTLS Engine、真实代理入口压测、网络故障注入以及完整安全系统测试通过前，当前版本仍是 pre-release。
