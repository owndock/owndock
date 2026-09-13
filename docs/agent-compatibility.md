# Agent 与 Server 版本兼容策略

> 状态：当前 Agent/Server 双端 `v1` conformance、真实 Agent 进程的 TLS 1.3 mTLS hello/heartbeat/断线重连、未知协议失败关闭和单一协议版本源已经实现。仓库尚无第一个正式 Release Tag，因此“当前版本与上一正式版本”两向签名二进制矩阵还不能执行，不能对外承诺滚动升级兼容窗口。

产品版本和控制协议是两件不同的事：

- 产品版本使用 `MAJOR.MINOR.PATCH`，例如 Agent `1.3.2`；
- 控制协议当前只有 `v1`，负责 hello、心跳、类型化命令、结果和临时 Terminal frame；
- capability 表示一张 Agent 身份在 `v1` 内被授权的功能上限，不等同于协议版本。

两个产品版本都声明 `v1`，只说明它们使用同一套 wire contract；只有混合版本测试通过，才能说明它们可以安全滚动升级。

## 当前强制边界

`internal/shared/agentprotocol.Version` 是 Agent enrollment、控制客户端和启动日志的唯一版本源。Server 配置目前也只接受这个已经实现的版本。管理员把配置改成 `v2` 或 `v1.1` 不会“打开新协议”，而是在启动校验阶段直接失败。

这是有意的失败关闭策略。当前 decoder 拒绝未知字段，因此即使只是给现有 frame 增加字段，也可能让旧 Agent 或旧 Server 断流。在 `v1` 下允许的修改只有：

- 修复不改变 JSON 形状、字段含义、顺序约束或上限的实现问题；
- 在既有枚举和 capability 已明确允许的范围内修复行为；
- 增加日志、指标、测试和文档，但不能改变线上 frame。

需要新增字段、枚举语义或握手能力时，必须新增明确的协议 adapter（例如 `v2`），并让 Server 在过渡期同时保留经过测试的旧 adapter。不能只在 `protocol_versions` 配置中添加一个字符串。

## 目标兼容窗口

首个稳定版本后，社区版的目标窗口是：

| 组合 | 目标 | 当前证据 |
| --- | --- | --- |
| 当前 Server + 当前 Agent | 必须通过 | 源码级双端与外部真实 Agent 进程 mTLS、命令路由及重连 conformance 已通过 |
| 当前 Server + 上一正式 Agent | 支持 Server 先升级 | 等首两个正式 Tag 后执行 |
| 上一正式 Server + 当前 Agent | 支持 Agent 灰度及 Server 回滚 | 等首两个正式 Tag 后执行 |
| 当前 Server + 更早 Agent | 不默认承诺 | 需要单独维护/商业支持决定 |
| 未知控制协议 | 拒绝连接 | 已实现并测试 |

Patch 版本不得故意破坏相同协议下的兼容性。Minor 版本只有在上述两向矩阵和双主机灰度通过后才能声明兼容。Major 版本可以改变产品兼容窗口，但仍需明确协议过渡和回滚路径。

## 推荐升级顺序

在正式矩阵通过以后，推荐：

1. 保留上一版本 Server 和 Agent 的已签名回滚制品；
2. 先升级 Server，确认旧 Agent 仍能连接、心跳和执行已有 capability；
3. 只升级一台 Agent，观察 enrollment identity、证书轮换、部署水位、Inventory 和 Terminal；
4. 扩大 Agent 灰度，最后完成剩余主机；
5. 回滚演练先回滚一台 Agent，再验证 Server 回滚后新旧 Agent 的行为。

如果 hello 返回协议不兼容、已有 capability 消失、部署 fence/水位异常或新旧节点结果不一致，停止扩大灰度。不能把 Agent 切到 direct 模式作为静默 fallback；连接模式变化需要显式权限、凭据和审计。

## 正式矩阵需要保存的证据

每次正式 Minor/Agent 协议相关 Release 至少记录：

- 两个 Git Tag、完整 commit SHA 和 Sigstore 已验签制品；
- Server/Agent 产品版本、控制协议和 capability 集合；
- linux/amd64、linux/arm64 的安装/升级/回滚结果；
- 旧 Agent → 新 Server、新 Agent → 旧 Server 的连接、心跳和命令结果；
- 两台 Host 混合版本期间不串目标、断线隔离、部署 cutover 水位和证书轮换；
- 失败时的安全错误、日志/指标和实际回滚耗时。

当前仓库没有正式 Tag 可作为“上一版本”，因此 CI 先运行同源码双端 conformance、真实 Agent 进程的 mTLS/监听器重启恢复、同一控制面入口下两个不同 Managed Host Agent 的身份隔离、确定性类型化命令路由与单 Host 会话恢复，以及真实 systemd 测试版本升级和坏版本恢复。双 Agent 门禁证明共享 CA、入口、进程、证书、命令结果缓存和重连状态不会造成跨 Host 串线，但其固定过期命令不替代真实 Docker 部署。`agent-release-compatibility` 工作流会在首个正式 Tag 发布后只记录基线；从第二个已发布 Tag 开始，它会下载当前与上一 Release 的双架构包，分别核验精确 Tag 的 Sigstore 身份，再用 amd64 真二进制执行离线旧版安装→新版升级→旧版回滚并确认状态保留。

发布后工作流还会从两份已验签 `RELEASE.txt` 固定的 commit 构建各自的 one-shot conformance Server：上一版 Agent 连接当前 fixture、当前 Agent 连接上一版 fixture；两边都必须完成精确证书身份、`v1` hello、heartbeat、监听器中断和自动重连。这个轻量 live wire 门禁不依赖 Mongo 或 Docker，适合每个 Release 强制执行；真实 Docker 命令、双主机和证书轮换矩阵仍需生产等价系统验收，完成前本页状态保持 provisional。
