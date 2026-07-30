# Agent 安全接入

OwnDock Agent 适合控制面无法主动访问的内网主机。主机上的 Agent 后续会主动向 OwnDock Server 建立出站连接；管理员不需要为了部署而把 Docker API 或 SSH 端口暴露到公网。

当前已实现首次接入身份和双端控制连接：Owner 创建一次性接入凭据，Agent 在主机本地生成私钥和 CSR，Server 签发只用于客户端认证的证书，并把证书固定到 Organization、Managed Host、Agent Identity 和本次安装实例。兑换时提交的 capabilities 会写入 Agent Identity，成为该身份的能力授权上限；后续 mTLS hello 只能声明其子集，不能通过重连自行增加部署权限。`owndock-agent` 可以使用已落盘的证书通过独立 TLS 1.3 端口完成身份校验、`v1` 协商、心跳和安全重连，Server 据此维护 `online/offline`；类型化控制流可执行本机 Docker probe 和两阶段 Deployment，双端近期缓存只保留命令指纹与安全结果。自动生成私钥、兑换 enrollment 并安装配置的发行安装器以及证书轮换仍未实现；真实双主机、断线和网络分区系统验收也仍待完成。

## 通俗理解

- **Enrollment token** 类似只可使用一次、15 分钟后失效的“入场码”，只负责首次接入，不是 Agent 的长期密码；
- **CSR** 是 Agent 用本地主机私钥生成的“证书申请”。私钥不会发送给 Server；
- **Agent certificate** 是 Server 签发的长期机器身份证。证书中的 URI 固定 Organization、Host、Agent Identity 和 instance；
- **Agent Identity** 表示某台 Managed Host 当前获准连接的 Agent 安装实例，不等同于用户账号；
- **Capabilities** 是 Agent 接入时声明的能力，后续还必须通过版本协商和实际命令通道验证，不能仅凭该字段授权高风险操作。

```mermaid
sequenceDiagram
    autonumber
    actor O as Owner
    participant API as OwnDock Server
    participant DB as MongoDB
    participant A as Agent 主机
    participant CA as Agent CA

    O->>API: 为 agent 模式 Host 创建 enrollment
    API->>API: 生成随机 token 与 SHA-256 hash
    API->>DB: 事务保存 hash、过期时间和审计
    API-->>O: 原始 token（仅返回一次）
    O->>A: 通过安全渠道交给安装程序
    A->>A: 本地生成私钥和 CSR
    A->>API: token + CSR + instance/version/capabilities
    API->>DB: 按 hash 查询未过期、未消费的 enrollment
    API->>CA: 校验 CSR 并签发 clientAuth 证书
    API->>DB: 同一事务消费 token、创建固定身份、绑定 Host、写审计
    API-->>A: Agent 证书 + CA 证书
    Note over A: 私钥始终只保存在 Agent 主机
    Note over A,API: 后续使用证书建立独立 mTLS 控制连接
```

## API 流程

1. Owner 创建 `connection_mode=agent` 的 Managed Host；
2. Owner 调用 `POST /api/v1/managed-hosts/{managed_host_id}/enrollments`；
3. Server 返回 `enrollment_token` 和 `expires_at`，并设置 `Cache-Control: no-store`。原始 token 不写入 MongoDB，也不会再次显示；
4. Agent 在目标主机本地生成私钥和 CSR；
5. Agent 调用无需用户 Bearer token 的 `POST /api/v1/agent/enrollments:exchange`，提交一次性 token、CSR、instance ID、Agent/协议版本和能力；
6. Server 返回 Agent 证书、CA 证书和证书过期时间，并原子消费 token。过期、重复使用、Host 已禁用或跨 Host 的请求都会失败；
7. Owner 可调用 `POST /api/v1/managed-hosts/{managed_host_id}:disable` 禁用 Host。该操作同时使未使用 enrollment 过期，并在数据库中吊销当前 Agent Identity。

完整字段和错误码以 [OpenAPI](../api/openapi.yaml) 为准。

当前安装步骤仍需要管理员或安装脚本把兑换得到的 CA、Agent 证书和本机私钥安全写入主机，然后填写 Agent 配置；正式自动化安装器尚未交付。进程构建和运行配置见 [Agent 运行与配置](agent.md)。

## Server 配置

该功能默认关闭。启用时，CA 证书和私钥只从配置指定的环境变量读取：

```yaml
security:
  agent_pki:
    enabled: true
    ca_certificate_env: OWNDOCK_AGENT_CA_CERT_PEM
    ca_private_key_env: OWNDOCK_AGENT_CA_KEY_PEM
    enrollment_ttl: 15m
    certificate_ttl: 720h
```

```bash
export OWNDOCK_AGENT_CA_CERT_PEM='-----BEGIN CERTIFICATE----- ...'
export OWNDOCK_AGENT_CA_KEY_PEM='-----BEGIN PRIVATE KEY----- ...'
```

CA 必须是仍在有效期内、允许签发证书且与私钥匹配的 X.509 CA。生产环境应由秘密管理系统注入环境变量，限制读取权限，并备份 CA；不要把 PEM 写入配置文件、镜像、日志或仓库。证书有效期必须长于 enrollment 有效期，且最终不会超过 CA 的到期时间。

启用 Server 端控制连接还需要独立监听地址和由 Agent 信任 CA 签发、具有 `serverAuth` 用途的 Server 证书：

```yaml
server:
  agent:
    enabled: true
    address: 0.0.0.0:8443
    server_certificate_env: OWNDOCK_AGENT_SERVER_CERT_PEM
    server_private_key_env: OWNDOCK_AGENT_SERVER_KEY_PEM
    handshake_timeout: 10s
    heartbeat_interval: 10s
    heartbeat_timeout: 30s
    max_frame_bytes: 65536
    outbound_buffer: 32
    completed_command_cache: 256
    protocol_versions: [v1]
```

`outbound_buffer` 限制单条连接中尚未发送的命令数，`completed_command_cache` 限制整个 Server 进程保存的近期命令结果数；完成缓存只保留命令 kind、指纹和安全结果，不保留 Registry authorization、解析后的环境秘密或完整命令。两者都是内存保护边界，不是持久化任务队列。控制端口只服务 Agent mTLS，不承载浏览器或用户 Bearer API。生产防火墙可以允许 Agent 主动访问该端口，但不能关闭客户端证书校验。Wire 协议见 [Agent Control Protocol v1](../api/agent-control.md)。

## 安全边界

- MongoDB 只保存 enrollment token 的 SHA-256 hash、证书序列号和 SHA-256 指纹；
- Server 不接受 Agent 上传的证书身份字段，证书 Subject 和 SPIFFE URI 由服务端生成；
- CSR 必须自签名有效，并使用 RSA 2048 位以上、ECDSA P-256 以上或 Ed25519 公钥；
- 签发证书只有 `clientAuth` 用途，不可充当 Server 证书；
- 同一 Host 只能激活一个首次接入身份；重复请求依赖 MongoDB 事务和条件更新拒绝；
- Host 禁用后的数据库吊销、当前单实例连接取消以及重连/heartbeat 身份检查已经实现；多控制面实例跨进程断流和证书安全轮换仍未实现；
- enrollment 保存的 capabilities 是身份授权上限；hello 能力必须是其子集，Server 路由还会在每次命令入队前检查对应 capability；
- API、Access Log、Trace、审计和测试产物不得记录原始 token、私钥或 CSR 私钥材料。
