# 产品定义

OwnDock 是面向缺少专职平台团队的中小型公司的自托管应用交付与运行平台。首要用户是同时承担应用交付职责的开发者和技术负责人。

## 首个产品用例

用户提供由外部 CI 生成的 OCI 镜像，在 OwnDock 中选择项目、逻辑环境和 Docker 运行目标，完成部署、状态查看、失败重试和回滚。

首发范围：

- 从安装到首次部署的目标时间不超过 30 分钟；
- 日常部署、状态查看、重试和回滚不要求登录目标主机执行 SSH；
- Release 固定 OCI image digest，不把浮动 tag 当作不可变版本；
- 首发只支持 Docker Engine；
- OwnDock 不负责源码拉取、编译和镜像构建；
- Kubernetes 和其他运行时通过后续适配器扩展。

## 产品模型

```text
Installation
    └── Organization
          ├── Users / Role Bindings
          ├── Templates
          └── Projects
                ├── Applications
                │     └── Releases
                ├── Environments
                ├── Runtime Targets
                ├── Registry Credentials
                └── Deployments

Template --optional snapshot--> Application
Application 1 --* Release
Release 1 --* Deployment *--1 Environment
Deployment *--1 Runtime Target
```

首版一个安装实例对应一个 Organization。Project 是 Application、Release、Environment、Runtime Target、Deployment 和项目级凭据的授权、查询与名称隔离边界。

### Template

Template 是可选的 Application 创建预设。实例化时复制配置快照，Template 后续修改不会自动改变已有 Application。内置 Template 属于社区核心；复杂继承、自动同步和模板治理不进入首发。

### Application

Application 是 Project 内长期存在、可多次发布的软件服务身份，不等同于镜像、Release 或某次 Deployment。

### Release

Release 是 Application 的不可变可部署版本，至少固定 OCI image digest、端口、健康检查、资源和配置声明。任何修改都产生新 Release，Environment 相关秘密和值不以明文写入 Release。

### Environment 与 Runtime Target

Environment 表示 dev、staging、prod 等逻辑阶段。Runtime Target 表示实际 Docker Engine 运行目标及其凭据、TLS、网络和连接状态。两者必须保持独立。

### Deployment

Deployment 是把一个 Release 交付到 Environment 和 Runtime Target 的不可变操作记录。相同幂等键不能创建重复操作；重试和回滚都创建新 Deployment，并保留来源关系和原始结果。

## 身份与权限

首版提供本地 bootstrap Owner，并采用以下内置角色：

| 角色 | 核心权限 |
|---|---|
| Owner | Organization 设置、成员、凭据和全部 Project |
| Maintainer | Project 管理、Runtime Target、Registry、部署和回滚 |
| Developer | Application、Release、部署、取消和状态查看 |
| Viewer | 只读查看资源、状态和允许公开的审计信息 |

所有写操作和权限变更都必须形成基础审计事件。OIDC 保留为稳定扩展边界，但社区版首个用例不依赖 OIDC。

## 商业边界

OwnDock 采用 Open Core：

- 社区核心：单 Organization、内置 Template、Docker 部署、本地账号、基础 RBAC 和基础审计；
- 商业扩展：SSO/OIDC、私有模板治理、自定义角色和策略、合规审计导出与留存、高可用、灾备和企业支持。

社区核心必须能够独立完成首个端到端用例，不能反向依赖商业模块。
