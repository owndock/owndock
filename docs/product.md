# 产品定义

OwnDock 是面向缺少专职平台团队的中小型公司的自托管应用交付与运行平台。首要用户是同时承担应用交付职责的开发者和技术负责人。

本文描述已经接受的产品方向，不代表所有能力均已交付。当前代码状态见 [文档导航](README.md)，公开接口以 [OpenAPI](../api/openapi.yaml) 为准。

## 首个产品用例

用户可以连接标准 Git 仓库，让 OwnDock 通过受约束 Dockerfile 构建生成 OCI 镜像；也可以直接使用外部 CI 已生成的 OCI 镜像。两条入口都汇入不可变 Release，再由用户选择项目、逻辑环境和 Docker 运行目标，完成部署、状态查看、失败重试和回滚。

首发范围：

- 从安装到首次部署的目标时间不超过 30 分钟；
- 日常部署、状态查看、重试和回滚不要求登录目标主机执行 SSH；
- Release 固定 OCI image digest，不把浮动 tag 当作不可变版本；
- 首发只支持 Docker Engine；
- 内置构建只支持标准 Git HTTPS/SSH、固定 Commit、Dockerfile、隔离 Build Worker/BuildKit 和 Registry push；
- 不提供任意 YAML/Shell 流水线，也不在 API Server 或生产 Runtime Target 上构建客户源码；
- Kubernetes 和其他运行时通过后续适配器扩展。

当前代码已经实现外部 OCI 镜像到 Release/Deployment 的基础链路；Git-to-Deploy 已进入产品范围但尚未实现。产品接受不等于代码已交付。

## 产品模型

```text
Installation
    └── Organization
          ├── Users / Role Bindings
          ├── Templates
          ├── Managed Hosts
          │     └── Agent Identities
          └── Projects
                ├── Source Repositories
                ├── Applications
                │     ├── Build Configurations
                │     │     └── Builds
                │     │           └── Artifacts
                │     └── Releases
                ├── Environments
                ├── Runtime Targets
                ├── Registry Credentials
                └── Deployments

Template --optional snapshot--> Application
Source Repository 1 --* Build Configuration
Build Configuration 1 --* Build 1 --0..1 Artifact
Artifact 1 --0..1 Release
Application 1 --* Release
Release 1 --* Deployment *--1 Environment
Deployment *--1 Runtime Target
Runtime Target *--1 Managed Host
```

首版一个安装实例对应一个 Organization。Managed Host 是 Organization 纳管的实际 Linux 主机；Agent Identity 是 agent 模式 Host 当前获准出站连接的机器身份。Project 是源码、Application、构建、Release、Environment、Runtime Target、Deployment 和项目级凭据的授权、查询与名称隔离边界。Project 通过 Runtime Target 获得某台 Host 上 Docker Engine 的部署入口，不自动获得主机级权限。

### Managed Host 与 Agent Identity

Managed Host 支持 `agent` 和 `direct` 两种连接模式。Agent 模式适合内网主机：Agent 使用一次性 enrollment 获取绑定 Host 和安装 instance 的 mTLS 客户端证书，后续主动出站连接。Direct 模式由 Server 连接受保护的 Docker API。两种模式不会静默回退或混用。

完成 enrollment 只代表机器身份已建立；只有版本协商、心跳和能力验证成功后，Host 才能标记在线并参与部署。Project 的 Runtime Target 权限不会自动授予主机终端权限。

### Template

Template 是可选的 Application 创建预设。实例化时复制配置快照，Template 后续修改不会自动改变已有 Application。内置 Template 属于社区核心；复杂继承、自动同步和模板治理不进入首发。

### Application

Application 是 Project 内长期存在、可多次发布的软件服务身份，不等同于源码仓库、镜像、Release 或某次 Deployment。

### Source Repository、Build 与 Artifact

Source Repository 保存平台无关的 Git HTTPS/SSH 地址和外部读取凭据引用。私有仓库读取凭据与 Webhook 秘密分开：前者允许 OwnDock 拉取代码，后者只用于验证“何时触发构建”的通知。通俗解释、首版范围和安全隔离见 [Git-to-Deploy 产品与安全边界](git-to-deploy.md)。

Build Configuration 属于 Application，声明 Dockerfile、构建上下文、目标 Registry、平台与资源限制；Build 固定 Commit 和配置快照；成功推送 Registry 后形成按 digest 固定的 Artifact，再由 Artifact 创建不可变 Release。

Git checkout、不可信 Dockerfile 和 BuildKit 缓存必须位于隔离 Build Boundary，不能写入 MongoDB、进入 API Server，或挂载生产 Runtime Target 的 Docker Socket 和数据卷。

### Release

Release 是 Application 的不可变可部署版本，来源可以是 Build Artifact，也可以是外部 CI 镜像；至少固定 OCI image digest、端口、健康检查、资源和配置声明。任何修改都产生新 Release，Environment 相关秘密和值不以明文写入 Release。

### Environment 与 Runtime Target

Environment 表示 dev、staging、prod 等逻辑阶段。Runtime Target 表示 Project 被允许使用的 Docker Engine 运行目标，必须绑定同一 Organization 的 Managed Host，并使用与 Host 一致的 `agent` 或 `direct` 连接模式。逻辑 Environment、物理 Host 和部署入口必须保持独立。

### Deployment

Deployment 是把一个 Release 交付到 Environment 和 Runtime Target 的不可变操作记录。相同幂等键不能创建重复操作；重试和回滚都创建新 Deployment，并保留来源关系和原始结果。

## 身份与权限

首版提供本地 bootstrap Owner，并采用以下内置角色：

| 角色 | 核心权限 |
| --- | --- |
| Owner | Organization 设置、成员、主机、凭据和全部 Project |
| Maintainer | Project 管理、源码/Registry 凭据、构建规则、Runtime Target、部署和回滚 |
| Developer | Application、Build Configuration、构建/取消/重试、Release、部署和状态查看 |
| Viewer | 只读查看资源、状态和允许公开的审计信息 |

所有写操作和权限变更都必须形成基础审计事件。OIDC 保留为稳定扩展边界，但社区版首个用例不依赖 OIDC。主机终端属于独立的 Organization 高权限，不因 Maintainer 拥有 Project Runtime Target 而自动获得。

## 商业边界

OwnDock 采用 Open Core：

- 社区核心：单 Organization、标准 Git HTTPS/SSH、Deploy Key/PAT、Dockerfile 单 Build Worker、外部 OCI 镜像、Docker 多目标部署、本地账号、基础 RBAC/审计和基础安全终端；
- 商业扩展：GitHub/GitLab OAuth/App 仓库发现、分布式构建、审批与供应链治理、SSO/OIDC、自定义策略、终端录像/合规留存、高可用、灾备和企业支持。

社区核心必须能够独立完成 Git-to-Deploy、外部镜像部署和受权限控制的基础终端用例，不能反向依赖商业模块。
