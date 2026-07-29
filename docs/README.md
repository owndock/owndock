# OwnDock 文档导航

本文档目录同时记录产品目标和当前工程事实。为避免把计划误写成已交付能力，所有说明遵循三种状态：

- **已实现**：代码、API 契约和相应测试已经存在；
- **已接受、尚未实现**：属于当前产品方向，但还不能对用户开放；
- **暂不支持**：没有进入当前产品范围，不能因为旧系统或底层组件存在就默认提供。

## 从哪里开始

| 读者 | 推荐入口 |
| --- | --- |
| 产品、设计、官网内容 | [产品定义](product.md) |
| Git-to-Deploy 设计与内容 | [Git-to-Deploy 产品与安全边界](git-to-deploy.md) |
| 后端开发者 | [目标架构](architecture.md) 与 [领域模型](domain-model.md) |
| 前端和 API 客户端 | [API 契约说明](../api/README.md)、[OpenAPI](../api/openapi.yaml) 与 [Agent Control v1](../api/agent-control.md) |
| 部署和运维人员 | [MongoDB 基线](mongodb.md)、[Deployment Worker](worker.md) |
| Agent 安装与安全评审 | [Agent 安全接入](agent-enrollment.md) |
| 联调和流程理解 | [核心流程时序](flows.md) |
| 安全问题报告 | [安全策略](../SECURITY.md) |

## 当前交付状态

| 状态 | 能力 |
| --- | --- |
| 已实现 | 本地身份与 Session、内置 RBAC、Managed Host、Agent 一次性 enrollment/证书身份及 Server 端 mTLS 连接/版本/心跳/`runtime.probe` 类型化传输、Project/Application/Release/Registry Credential/Environment/Runtime Target/Deployment、基础审计、MongoDB migration、direct Docker Worker 基础执行 |
| 已接受、尚未实现 | Template、Git-to-Deploy、Agent 进程/实际命令执行器/Runtime Gateway、多主机系统验收、容器/主机 Terminal、用户和 Project 成员管理 |
| 暂不支持 | 任意 YAML/Shell 流水线、Kubernetes 运行时、浏览器提供任意 Docker 地址或容器 ID、无审计的主机访问 |

这里的“已实现”不等同于生产就绪。远程 mTLS Engine、入口流量、网络故障注入以及完整安全系统测试通过前，当前版本仍是 pre-release。
