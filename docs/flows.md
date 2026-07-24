# 核心流程时序

本文用时序图说明 OwnDock 当前已实现的关键链路，以及首个端到端部署用例的目标链路。标题中的“已实现”表示代码、契约和测试已经存在；“目标”表示产品语义已经确定，但执行能力尚未接入，不能据此判断当前版本可以执行生产部署。

## 已实现：启动、Migration 与就绪

产品 API 依赖 MongoDB。进程先连接数据库并运行版本化 migration，全部成功后才创建产品模块和开始监听；任一步失败都会终止启动并清理已经创建的资源。

```mermaid
sequenceDiagram
    autonumber
    participant P as OwnDock Process
    participant C as Configuration
    participant M as MongoDB
    participant G as Migration Runner
    participant H as HTTP Server

    P->>C: 读取配置和环境变量
    C-->>P: product、MongoDB、安全配置
    alt product.enabled=true 且 MongoDB 未启用
        P-->>P: 配置校验失败并退出
    else MongoDB 已启用
        P->>M: 建立连接并 Ping Primary
        M-->>P: Replica Set 可用
        P->>G: Run(versioned migrations)
        G->>M: 获取带租约的全局 migration 锁
        loop 按版本顺序
            G->>M: 查询已应用版本
            alt 未应用
                G->>M: 幂等创建 collection indexes
                G->>M: 记录 version、name、applied_at
            else 已应用且名称一致
                G-->>G: 跳过
            end
        end
        G->>M: 释放 migration 锁
        P->>P: 组装身份、控制面与审计模块
        P->>H: 开始监听
        H-->>P: /readyz 可用
    end
```

## 已实现：首次初始化与本地登录

Bootstrap 只用于创建首个 Organization 和 Owner。调用方必须同时提供环境变量配置的 bootstrap token；创建首个用户后，再次 bootstrap 会返回冲突。密码使用 Argon2id 保存，Bearer token 只向客户端返回一次，MongoDB 中仅保存其单向哈希。

```mermaid
sequenceDiagram
    autonumber
    actor O as First Owner
    participant API as Identity HTTP API
    participant UC as Identity UseCase
    participant K as Password / Token Security
    participant M as MongoDB Transaction
    participant A as Audit Store

    O->>API: POST /api/v1/auth/bootstrap<br/>bootstrap token + organization + email + password
    API->>API: 常量时间校验 bootstrap token
    API->>UC: Bootstrap(...)
    UC->>K: Argon2id hash(password)
    UC->>K: 生成随机 session token 和 SHA-256 token hash
    UC->>M: 开始事务
    M->>M: 确认尚无用户
    M->>M: 写 Organization、Owner、Session hash
    UC->>A: 写 identity.bootstrap 审计事件
    alt 任一写入失败
        M-->>UC: 回滚全部写入
        UC-->>API: 安全错误响应
    else 全部成功
        M-->>UC: 提交事务
        UC-->>API: 原始 access token、用户和过期时间
        API-->>O: 201 Created
    end

    O->>API: POST /api/v1/auth/login<br/>email + password
    API->>UC: Login(...)
    UC->>K: 校验 Argon2id password hash
    UC->>K: 生成新 session token 和 token hash
    UC->>M: 事务写 Session hash + login 审计
    M-->>UC: 提交
    UC-->>O: Bearer access token
```

## 已实现：认证、授权、资源写入与审计

Project、Project 下的 Application、不可变 Release 和 Runtime Target 共用相同的写入骨架。身份来自 Bearer session，Organization 所有权和角色权限由 UseCase 强制执行。资源与审计事件处于同一 MongoDB 事务，因此审计失败不会留下无审计的资源。

```mermaid
sequenceDiagram
    autonumber
    actor D as Developer
    participant API as Product HTTP API
    participant I as Session Authenticator
    participant U as Control Plane UseCase
    participant R as RBAC / Ownership
    participant M as MongoDB Transaction
    participant A as Audit Store

    D->>API: POST /api/v1/projects/{project_id}/...<br/>Authorization: Bearer token
    API->>I: hash(token) 并查询未过期 Session
    I-->>API: Principal(user, organization, role, session)
    API->>U: 创建资源 + Principal + request ID
    U->>R: 校验角色权限
    U->>M: 校验 Project/Application 属于当前范围
    alt 未认证、无权限或范围不匹配
        U-->>API: 401 / 403 / 404
        API-->>D: 不暴露跨 Organization 资源信息
    else 校验通过
        U->>M: 开始事务并写入资源
        U->>A: 写 resource.create 审计事件
        alt 资源或审计写入失败
            M-->>U: 回滚事务
            U-->>API: 稳定错误码
        else 全部成功
            M-->>U: 提交事务
            U-->>API: 新资源
            API-->>D: 201 Created
        end
    end
```

## 目标：从 Release 到 Docker Deployment

下面是首个产品用例的目标流程，当前尚未实现。它用于约束后续 Environment、Deployment 状态机、凭据解析、Docker Gateway 和 Worker 的设计，不表示 Runtime Target 创建后已经发生连接探测或部署。

```mermaid
sequenceDiagram
    autonumber
    actor D as Developer
    participant API as Deployment API
    participant U as Deployment UseCase
    participant M as MongoDB
    participant W as Deployment Worker
    participant S as Secret Resolver
    participant G as Docker Gateway
    participant A as Audit Store

    D->>API: 创建 Deployment<br/>release + environment + runtime target + idempotency key
    API->>U: CreateDeployment(...)
    U->>M: 校验 Project 范围和引用资源
    U->>M: 事务创建 queued Deployment + 审计
    U-->>D: 202 Accepted + deployment ID

    W->>M: 原子领取 queued Deployment 和租约
    W->>S: 按 credential_ref 解析短期凭据
    S-->>W: TLS/认证材料（不落入 Release）
    W->>G: 连接 Docker Engine 并按 digest 拉取/运行
    alt 部署成功
        G-->>W: 运行实例状态
        W->>M: 条件更新为 succeeded
        W->>A: 写 deployment.succeeded
    else 可恢复失败
        G-->>W: 分类后的失败
        W->>M: 更新为 failed，保留诊断摘要
        W->>A: 写 deployment.failed
        D->>API: retry 或 rollback
        API->>U: 创建关联到原操作的新 Deployment
        U->>M: 使用新幂等键写入新操作
    end
```

## 阅读边界

- 当前正式持久化资源：Organization、User、Session、Project、Project Application、Release、Runtime Target、Audit Event。
- 当前 Runtime Target 状态固定为 `pending`，只保存连接元数据和 `credential_ref`，不保存凭据正文。
- Environment、Template、Deployment 正式模型、Docker 连接探测与执行仍是后续纵向切片。
- 顶层 Application、Environment、Deployment 路由是默认关闭的工程样例，与正式 Project 范围 API 相互隔离。
