# 终端威胁模型、安全指标与验收

交互式终端能够在受管容器或主机内执行操作，因此必须把“连接成功”和“安全交付”分开判断。OwnDock 的原则是：浏览器只选择产品资源，Server 固定实际目标与能力，传输层只转发有界字节，持久层和可观测系统只保存会话元数据。

## 一条命令运行当前门禁

```bash
make test-terminal-security
```

该命令以竞态检测运行 Terminal 领域、WSS、direct/Agent Gateway、双端协议、本机 Agent executor 和指标测试，不要求外部 Docker 或 MongoDB。普通 `make check` 仍覆盖编译、静态检查、全量单元测试与 OpenAPI。

## 威胁模型

| 威胁 | 设计约束 | 当前自动化证据 |
| --- | --- | --- |
| 伪造容器或越过 Project | API 只接受 Deployment ID；Server 固定当前成功实例、Runtime Target 和 generation | 目标解析、跨 Project、身份不匹配测试 |
| 将终端变成任意 Docker exec | shell 由适配器固定；拒绝任意 endpoint、container ID、command、user、env、workdir、privileged | direct 与 Agent executor 契约测试 |
| 窃取或重放连接凭据 | 短时票据只存 SHA-256，使用限定 connect path 的 Secure/HttpOnly/SameSite Cookie 并原子消费 | ticket 生命周期和单次消费测试 |
| Cross-Site WebSocket Hijacking | WSS 要求唯一、严格同域 Origin；不复用 REST CORS 白名单 | 缺失与跨站 Origin 测试 |
| 登录退出、角色变化或策略收紧后保留 Shell | 活动连接每 2 秒复核权威会话、登录、角色、策略和目标；撤权通知后按当前策略宽限关闭 | 管理员终止、撤权宽限、权限恢复和复核故障测试 |
| 目标替换后仍操作旧容器 | exec 前后及连接期复核稳定容器标签、Deployment 和 cutover identity | direct 目标替换与 Agent 标签测试 |
| 浏览器把主机终端升级为任意账号或命令执行 | Agent OPEN 只有 kind/窗口，本机配置固定有效账号与 Shell；direct SSH 四项连接信息由 Managed Host 固定 | 协议字段拒绝、固定账号、最小环境与跨层 Agent conformance |
| SSH 中间人或错误凭据连接到其他主机 | 只用固定公钥认证并强制 SHA-256 Host Key；没有跳过校验开关 | 固定用户/客户端公钥握手、Host Key 正反向与 PEM 清零测试 |
| 主机 Shell 结束后遗留子进程 | 独立 PTY/进程组，TERM 后关闭控制 PTY，短宽限后 KILL | 本机真实 Shell + 长时子进程回收测试 |
| 畸形帧、超大输入或消息洪峰耗尽内存 | 严格方向/字段/序号，4 KiB 控制帧、32 KiB 数据帧、200 输入消息/秒和有界队列；只持久化稳定违规码 | 浏览器协议、Agent 协议、超大 payload 不落流和错误字段泄漏测试 |
| Agent 断线、慢消费者或复用错 Host | 每会话序号与有界队列；断线关闭且不恢复旧 PTY；Registry 按固定 Host 路由 | Gateway、Registry 和竞态测试 |
| 终端内容进入日志、Trace、指标或 MongoDB | 普通可观测接口只接收固定 kind/mode/reason；持久化只写会话元数据和安全错误码 | 指标不受信标签归一化与泄漏断言 |

## 指标

Server `/metrics` 暴露以下低基数指标：

| 指标 | 标签 | 用途 |
| --- | --- | --- |
| `owndock_terminal_connections_active` | `kind`, `connection_mode` | 当前活动终端数 |
| `owndock_terminal_connections_total` | `kind`, `connection_mode` | 累计成功建立的连接数 |
| `owndock_terminal_connection_closes_total` | `kind`, `connection_mode`, `reason` | 按稳定原因统计关闭次数 |
| `owndock_terminal_connection_duration_seconds` | `kind`, `connection_mode`, `reason` | 连接时长分布 |

`kind` 仅允许 `container/host`，`connection_mode` 仅允许 `direct/agent`，`reason` 仅允许领域定义的八种关闭原因；任何未知值都会归一化，不能制造客户级时序。禁止把 Organization、Project、Actor、TerminalSession、Managed Host、Runtime Target、Deployment、容器名、IP 或错误正文放进标签。

建议至少告警：活动连接异常跃升、`connection_failed` 或 `target_unavailable` 比例持续升高、`permission_revoked` 后仍有超出策略宽限的连接。指标只能用于发现问题；单次操作定位使用审计元数据，不通过临时记录终端内容排障。

## 数据泄漏边界

允许持久化或导出的内容：操作者与固定目标引用、连接模式、来源元数据、创建/连接/结束时间、状态、关闭原因、安全错误码和审计动作。

禁止持久化或导出的内容：一次性票据正文、Cookie、stdin、stdout、stderr、命令、Shell history、环境变量、Docker 原始认证、SSH 私钥、完整底层错误和未经约束的协议 payload。商业版将来若提供会话录像，必须使用独立开关、权限、加密、保留期和访问审计，不能改变社区版默认不录像的行为。

## 尚未形成生产证据

以下项目仍阻断 Terminal 的生产就绪声明：

- 两台真实 Agent 主机上的断线、网络分区、Agent 重启、容器退出和慢消费者故障注入；
- 真实浏览器的 Cookie、反向代理、关闭码、后台标签页、网络切换和 CSP 矩阵；
- 多 Server 实例对管理员终止、登录撤销、角色与策略变更的最大发现延迟验收；
- 主机 PTY/direct SSH 已具备固定身份、最小环境、PTY 进程组回收、公钥认证和 SHA-256 Host Key 固定的本地/协议测试；仍需真实远程 Linux/SSH 的进程树、断网、服务重启、Host Key 轮换和秘密哨兵系统门禁；
- 对 MongoDB、审计导出、Access Log、Trace backend、Prometheus 和测试 artifact 的端到端秘密哨兵扫描。

这些验证完成前，文档继续把完整交互式终端标记为 pre-release。
