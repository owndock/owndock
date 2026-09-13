# MongoDB 运行基线

OwnDock 使用官方 MongoDB Go Driver v2.8.0。开发和 CI 的服务端基线固定为 MongoDB 8.3.7，测试镜像为：

```text
mongo:8.3.7-noble@sha256:8444a416f2fc991f15064df9f6ea31ee02877607a70fd352ea998e6dbb5714b3
```

禁止使用 `mongo:latest`、`mongo:8` 或 `mongo:8.3` 等浮动 tag。版本升级必须同时更新镜像 digest、集成测试和发布说明。

## 配置

MongoDB 默认关闭。启用配置示例：

```yaml
database:
  mongo:
    enabled: true
    uri_env: OWNDOCK_MONGODB_URI
    uri_file: ""
    database: owndock
    connect_timeout: 10s
    operation_timeout: 5s
    max_idle_time: 5m
    min_pool_size: 0
    max_pool_size: 100
```

连接串从 `uri_env` 指定的环境变量，或从 `uri_file` 指定的绝对路径二选一读取；同时配置或都不配置会拒绝启动。文件必须是最多 8 KiB 的普通文件，不能是符号链接或允许 group/world 写入，且只能包含一个非空行。连接串不写入配置模板、日志或版本库。Compose 基线使用文件型 Secret，并分离 root 初始化身份、仅可读写 `owndock` 数据库的应用身份，以及只挂载到 Mongo 容器的 `backup`/`restore` 操作身份；生产环境还需要 TLS，以及经过容量与故障转移验证的 Replica Set。

单节点安装、备份和恢复边界见[社区版单节点安装与恢复](community-installation.md)。

## 生命周期

- 启动时创建连接池并 Ping Primary；失败时服务不启动；
- 启动时获取带租约的全局锁并按版本执行 migration；已记录的同名版本会跳过，版本名称漂移会拒绝启动；
- 每次操作受 Client operation timeout 和调用方 context 共同约束；
- `/readyz` 会 Ping Primary，失败时返回通用 `not_ready`，不暴露数据库错误；
- Kratos 停止接收请求后关闭连接池；
- 业务模块不能直接创建 Client，也不能从 `internal/platform/mongo` 推导业务 schema。

正式资源创建与对应审计事件在同一 MongoDB 事务中提交。Bootstrap 的 Organization、Owner、Session 与审计同样保持原子性。当前 collection 包括 `organizations`、`users`、`user_invitations`、`sessions`、`login_attempts`、`managed_hosts`、`agent_enrollments`、`agent_identities`、`projects`、`project_members`、`product_applications`、`releases`、`registry_credentials`、`repository_credentials`、`source_repositories`、`build_configurations`、`build_triggers`、`build_trigger_rate_limits`、`build_hooks`、`webhook_deliveries`、`builds`、`artifacts`、`artifact_evidence`、`environments`、`runtime_targets`、`deployments`、`deployment_cutover_sequences`、`runtime_inventory_observations`、`runtime_inventory_chunks`、`runtime_inventory_resources`、`runtime_inventory_heads`、`runtime_inventory_counters`、`runtime_inventory_schedule`、`runtime_inventory_current`、`runtime_inventory_event_hints`、`ingress_rate_limits`、`audit_events` 和 migration 元数据；索引只由版本化 migration 管理。

Repository Credential 文档保存 `secret_ref`，公开列表查询在 MongoDB projection 层直接排除该字段。Source Repository 探测不保存 Token、私钥、远端 refs 或原始 Git 错误，只在同一事务中更新安全 `status`、`last_probed_at`、`updated_at` 和对应 Audit Event。

Build Configuration 保存可修改的版本化构建配方和最多 8 个 development 自动部署目标，不保存 Git/Registry 秘密、源码或缓存。Build 与 Artifact 复制该规则快照，历史执行不随配置更新变化。更新以当前 `version` 作为条件，冲突时返回稳定的 `version_conflict`，不会最后写入者静默覆盖；创建/更新与 Audit Event 位于同一事务。索引固定 Application 范围名称唯一性、稳定列表排序，以及 Source Repository/Registry Credential 引用查询。

Build 保存完整 Commit SHA、触发 ref、触发来源和非秘密配置快照。Project + `idempotency_key` 唯一索引阻止重复入队；重复请求只在 Application、Build Configuration、ref、触发来源和可选期望 Commit 均一致时回放原记录。首次 Build 与 Audit Event 位于同一事务。当前文档不保存源码、Git/Registry 秘密或日志正文。

Build queue 直接复用 `builds` collection，不额外引入消息队列。Worker 通过单文档原子更新领取最早可执行记录，写入短时 `lease.owner/expires_at` 并递增 `lease.generation`；heartbeat 只有在 owner、generation、version 和未过期 lease 全部匹配时才能续期。失联后的新 Worker 接管会获得更大的 generation，旧 Worker 的状态、Artifact 或 Release 写入必须失败。状态转换与 Audit Event 在同一事务中提交；取消保留协作清理阶段，重试创建带 `source_build_id` 的新记录。

Build 日志使用 `build_log_streams` 保存每个 Build 的总字节、下一序号、截断和到期元数据，使用 `build_log_chunks` 保存按 sequence 排序的脱敏文本。每块分配 sequence 与插入正文处于同一 Replica Set 事务；Project + Build + sequence 索引用于 cursor 增量读取，两个 collection 都有 TTL 索引。默认每 Build 10 MiB、每块 16 KiB、保留 7 天；达到上限后只把 stream 标记为 `truncated`，不继续增长。详见 [Build 日志与排障](build-logs.md)。

`artifact_evidence` 只保存绑定 Artifact/subject digest 的证据索引，包括 kind、媒体类型、格式版本、producer、OCI descriptor digest 和验证状态。完整 SBOM、Provenance、签名 bundle 或漏洞报告不嵌入 MongoDB。Project + Artifact + 创建时间支持稳定列表；Project + Artifact + kind + producer + format version + descriptor digest 只拒绝完全相同的证据，允许以后重新扫描并保留历史。持久化数据读取时重新执行领域校验，损坏 digest 或枚举值失败关闭。详见 [Artifact Evidence](artifact-evidence.md)。

`artifact_evidence_jobs` 保存 Evidence Worker 的有界执行状态，不保存报告正文。队列按状态、lease 到期时间和创建时间领取；Organization + Project + 请求幂等键防止同一次请求重复排队，同时允许使用新幂等键重试或重扫。Worker 接管时递增 generation，最终 Evidence 索引与 Job 成功状态在 MongoDB Replica Set 事务内共同提交，过期 generation 的事务失败并回滚。

Build Trigger 保存绑定范围、精确允许 ref、状态和 Token SHA-256 哈希，不保存可调用的明文 Token；列表查询在 MongoDB projection 层排除 `token_hash`。Project + normalized name 和 Token hash 分别唯一。`build_trigger_rate_limits` 使用 revision 条件更新实现多 Server 共享固定窗口，并由 TTL 索引自动回收过期计数；Trigger 和 Webhook Hook 使用不同键前缀，ID 相同也不会共享计数。该集合不保存请求正文、Commit、Token、Webhook 签名或 Secret。

Build Hook 保存平台、Build Configuration、精确允许 ref 和外部 `secret_ref`；公开列表 projection 不返回该引用，只返回 `secret_configured`。`webhook_deliveries` 以 provider + Hook + delivery ID 唯一，并在同一事务内关联 queued Build 和审计。该 collection 不保存原始 body、签名或 Secret，也不设置 TTL，避免自动过期后的旧 delivery 再次触发。

`login_attempts` 只保存 normalized email 的 SHA-256 键、窗口、计数和阻断/过期时间，通过 revision 条件更新避免多实例并发绕过限制，成功登录会删除记录。新 Session 与“只保留该用户最新 N 个未过期 Session”的清理处于同一事务；Session 查询和撤销都固定当前 `user_id`，撤销与审计也原子提交，API 永不返回 `token_hash`。Agent enrollment 只保存 token 的 SHA-256 hash；首次兑换在事务中条件消费 token、创建固定身份并绑定 Host。为恢复提交后的响应丢失，enrollment 最多 10 分钟保存精确请求 SHA-256、已签发的公开证书/CA 和 Identity ID；只有同 token hash 与同请求 hash 可以取回原响应，不创建第二身份或审计，不同请求仍整体拒绝。Agent 连接在 `managed_hosts` 保存当前 boot/session fence、版本、能力和 `last_seen_at`；heartbeat 与 disconnect 必须匹配当前 session，避免旧连接覆盖新连接状态，连接/断开审计仍使用事务。

Owner 管理员会话接口先按 Organization 读取目标用户，再以目标 `user_id` 查询或删除 Session。单会话和全部会话撤销都在事务中写入管理员审计；跨 Organization 用户按不存在处理。当前 Owner 不能从管理员入口撤销自己的当前 Session 或批量撤销自己，避免误操作切断唯一管理入口。

`ingress_rate_limits` 只保存来源/全局准入键的 SHA-256、窗口起点、计数、revision 和过期时间，不保存原始 IP、请求路径、header 或正文。Mongo 条件替换保证多个 Server 共享固定窗口；migration v31 的 TTL 索引清理过期窗口。保护状态无法读取或更新时请求失败关闭，具体代理信任与返回语义见[产品 API 入口保护](ingress-protection.md)。

`user_invitations` 保存 Organization、规范化邮箱、状态、版本、到期时间和一次性 Token SHA-256 哈希。接受时使用 status/version/expiry 条件更新，并在同一事务创建 Viewer 用户、Session 和审计；成功或撤销后移除 Token hash。Token hash 唯一索引阻止碰撞，active-only TTL 索引清理过期未使用邀请，不会删除 accepted/revoked 元数据。

`project_members` 保存 Organization、Project、用户、不可为 Owner 的 Project 角色和乐观锁版本。Project + 用户、Project + 邮箱均唯一，Organization + 用户 + Project 索引用于过滤用户可见 Project。Session 不保存 Project 角色；每次 Project 请求实时读取成员关系，所以降权和删除无需等待 Session 过期。

Deployment 使用 Project 范围的唯一幂等索引，并为“同一 Application、Environment 与 Runtime Target 上曾成功部署的 Release”建立回滚查询索引。自动 Deployment 额外按 Project、Artifact、Environment 和 Runtime Target 建立部分索引，并保存 `trigger_source` 与 Build 链路字段；旧记录回填为 `manual`。`deployment_cutover_sequences` 只保存部署槽位及其当前序号，不保存运行凭据；Deployment 与审计在同一事务中创建时，序号分配也处于该事务内。Runtime Inventory 把新 observation 写成独立 generation，所有声明分块完成后才在一个事务中更新显式 `present/absent` current 投影并切换 current head；open generation 先设置两小时 TTL，完成时移除当前 generation 的 TTL，上一 generation 和 absent current 项在被替换七天后回收。

Runtime Target 删除把 `retiring` 与最小退役上下文原子持久化：Organization、Actor、Request ID 和开始时间。migration v46 的 `status + retirement.started_at + _id` 索引支持 Server 有界扫描；最终删除与原始身份审计处于同一事务。记录在提交删除前始终可重新发现，因此 Server 重启或客户端不再重试也不会遗失已接受的退役工作。

Application 与 Environment 使用软退役保留业务历史。Migration v48 回填 `active` 状态，把名称唯一索引改为只约束 active 文档，并分别增加 `status + retirement.started_at + _id` 部分索引。开始退役会原子保存 Organization、Actor、Request ID 与开始时间；完成时写入 `retired_at` 并移除临时上下文。默认列表、Application/Environment 引用解析和运行配置读取只接受 active 文档，不可变 Release 历史可按已知 Application ID 继续读取。Migration v49 为活动容器 TerminalSession 回填 Application/Environment ID，并建立 active 部分索引，使资源退役可有界关闭关联会话。

Migration v50 为 Build 建立 Organization/Project/Application/status/创建时间顺序索引。Application 退役据此每批最多读取 100 个 queued/checking_out/building/pushing/canceling Build；转入 canceling 与逐 Build 审计处于同一事务，Build Worker 写入终态后下一轮退役扫描自然推进。

退役收敛使用 migration v47 的 Organization/Project/Runtime Target/active/时间索引有界扫描 TerminalSession。会话状态转换与逐会话审计原子提交；Runtime Inventory 则在独立事务中分批删除完全可重建的调度、批次和 current 投影。Inventory `Begin` 与 `Complete` 都复核 Target=ready，阻止已领取租约的旧 Worker 在清理后重建视图。

Migration v4–31 的执行与业务索引沿用各模块版本记录；v32/v33 建立 Terminal 策略、会话、并发槽位和登录 Session 绑定，v34–43 建立 Artifact 证据、签名、漏洞与 Deployment Policy 索引，v44/v45 支持外部 Artifact 和 Registry 匿名/Basic 模式，v46 建立 Runtime Target 退役队列，v47 建立按 Target 收敛活动 TerminalSession 的索引，v48/v49 建立 Application/Environment 软退役及关联 Terminal 收敛，v50 建立 Application 活动 Build 收敛索引。

Runtime Inventory 还使用 `runtime_inventory_counters` 为每个 Runtime Target 原子分配单调 generation；多 Server 不使用本机时间判断 observation 新旧。

`runtime_inventory_schedule` 为每个 Runtime Target 保存全量采集与 Event 轮询各自的下一次到期时间、短时 owner/expiry 和递增 token，以及最后安全处理的 Docker 事件时间游标。多个 Server 同时领取同类任务时只有一个原子更新成功；完成调度必须匹配 owner 和 token，旧实例不能覆盖租约接管后的结果。Event 失败时不推进游标。该 collection 不保存 endpoint、凭据引用、证书或采集错误正文。

`runtime_inventory_current` 是可重建读取投影，不是另一份 Docker 事实来源；它保留最新安全资源摘要、presence、first/last seen、absent 时间和 generation。受管容器的 Project/Deployment 字段只在成功 Deployment 与候选 Label 的 Organization、Project、Application、Runtime Target 全部匹配后写入。Migration v16 建立 Project/Host 视图索引，v17 优化包含 absent 时的稳定游标排序；集成测试会检查最终索引字段顺序，防止后续迁移意外退化。`runtime_inventory_event_hints` 只保留 24 小时安全摘要，Event 只把调度提前，不能直接改 current presence。

启动和事务写入时序见 [flows.md](flows.md)。

## 验证

普通单元测试不会启动容器：

```bash
make check
```

MongoDB 集成测试使用 Testcontainers 启动固定镜像的单节点 Replica Set，并验证连接、Ping、事务、migration 幂等、认证会话、共享登录尝试并发阈值与成功清理、活跃 Session 上限/自助及管理员撤销、来源入口并发阈值与 TTL 索引、Agent token 只存哈希/原子消费/同请求恢复/冲突重放拒绝、Agent mTLS 身份查询/online/heartbeat/重连 fence/禁用吊销、正式资源持久化、Deployment 领取/终态/取消/重试/回滚、Runtime Inventory open TTL/分块幂等/显式 present/absent/恢复/旧批次 fence/1,202 资源批量归属核验/Project 与 Host 最大页长分页隔离/全量与 Event 并发租约/Event 与 Finish 竞态/失败不推进游标、审计原子回滚和注销失效：

```bash
make test-integration
```
