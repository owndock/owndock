# OwnDock

**Own your apps. Run them anywhere.**

OwnDock 是面向缺少专职平台团队的中小型公司的自托管应用交付与运行平台。首要用户是同时承担应用交付职责的开发者和技术负责人。产品方向包含两条交付入口：连接标准 Git 仓库完成受约束的 Dockerfile 构建，或者直接使用外部 CI 生成的 OCI 镜像；两者最终都形成不可变 Release，并在 Docker 运行目标上完成部署、状态查看、失败重试和回滚。当前实现状态见下方基线。

项目采用 **Go + Kratos 的模块化单体**：在单进程内保持清晰的领域边界和可测试契约，并允许模块在出现独立扩缩容或故障隔离需求时演进为服务。

本仓库负责后端服务，不包含 Web 前端工程。

## 当前基线

- Go module：`github.com/owndock/owndock`
- Go：1.26.5（`.go-version`、`go.mod`、CI 和构建镜像保持一致）
- Kratos：v2.9.2
- 依赖组装：composition root 手工组装，不使用 Google Wire
- 进程：控制面 `owndock`；主机侧 `owndock-agent`；隔离源码执行进程 `owndock-build-worker`；隔离镜像证据进程 `owndock-evidence-worker`；外部调度的一次性 `owndock-vulnerability-db-updater`
- 可观测性：结构化 Access Log、HTTP 与统一 Worker Prometheus 指标、独立 Build Worker 健康/就绪端点；OpenTelemetry HTTP/Worker Trace 默认关闭，可通过 OTLP/HTTP 导出
- 浏览器 API 安全：默认同源；可配置精确 HTTPS CORS Origin，拒绝通配符和 credentialed CORS；`/api/` 统一 `no-store` 并设置 API 安全响应头
- MongoDB：官方 Go Driver v2.8.0；服务端测试基线 8.3.7，默认关闭
- 正式产品切片：本地 bootstrap/login/session、一次性用户邀请、Owner 管理员会话治理、Project 成员绑定与即时撤权、可信代理来源识别和来源/实例共享入口限流、内置 RBAC、只读内置 Template 与 Application 快照、Organization Managed Host、一次性 Agent enrollment 与证书身份、Project、Project Application、Source Repository/Repository Credential 与只读连接探测、Build Configuration、三类 Build 触发入口、状态机、取消/重试与 Mongo queue/lease/fence、隔离 Build Worker 的固定 Git HTTPS/SSH 精确 Commit 检出、rootless BuildKit 构建与认证 Registry push、OwnDock Build 或外部 CI digest 双来源 Artifact、Registry manifest 完整性探测和生产者信任标记、Artifact Evidence 有界索引/授权下载 API、OCI Referrers 原生/Tag Schema 探测、Evidence Job queue/lease/generation fence、CycloneDX 1.6 SBOM、SLSA Provenance v1、固定 Trivy 漏洞扫描及原子数据库快照、精确漏洞 ID 的 Project/Artifact 限时豁免、Project/Environment 版本化 Deployment Policy 与不可变准入快照、幂等 Release 交接、development 显式自动部署、不可变 Release、Runtime Target、Runtime Inventory 安全查询、基础审计和 MongoDB migration
- 资源退役：Application 与 Environment 先关闭新工作入口，再由持久后台流程排空 Deployment、关闭容器 Terminal、清理精确运行槽位并释放 Agent watermark，同时保留不可变历史；详见 [docs/resource-retirement.md](docs/resource-retirement.md)
- 已接受、待完成或待验收：其他 KMS 客户矩阵，以及 Evidence Worker 的客户等价出口矩阵；Git/Registry 品牌与客户网络兼容矩阵、首个受保护 Agent Tag 的公开发行证据、多主机升级/回滚系统验收，以及 enrollment/证书轮换/Terminal 的真实远程与浏览器安全验收
- 默认接口：健康和版本接口；产品切片需要显式启用 MongoDB 与 `product.enabled`

本地用户由 Owner 使用一次性邀请接入并自行设置密码。受邀 Viewer 默认看不到任何 Project；Owner 或 Project Maintainer 显式绑定 Project 角色。角色不缓存到 Session，每次 Project 请求实时解析，因此移除成员后原 Session 的下一次请求立即失去访问权限。Owner 还可以查看同 Organization 用户的不含 Token/hash 的 Session 摘要，并在账号泄漏或离职时撤销一个或全部 Session。

正式产品 API 在认证和业务 Handler 之前使用 MongoDB 共享的来源/实例两级入口限流。只有显式配置的可信直连代理才能提供客户来源链；超过阈值返回 `429` 和 `Retry-After`，保护状态不可用时请求失败关闭。部署规则见 [docs/ingress-protection.md](docs/ingress-protection.md)。

当前版本已经提供只读内置 Template 目录，并在创建 Application 时复制与后续目录版本脱钩的安全快照；同时提供 Project 范围的正式 Deployment 创建、查询、取消、失败重试、回滚、幂等回放、MongoDB 持久化和审计事务。本地登录使用 MongoDB 共享的账号尝试窗口，多 Server 实例不会因各自内存计数而绕过阈值，成功登录会清理计数。Managed Host 归 Organization 所有，Project Runtime Target 必须绑定同一 Organization 的 Host，并保持 `agent/direct` 连接模式一致。Agent 首次接入已支持安装器本地生成私钥和 CSR、一次性 token、固定 Host/instance 身份、完全相同请求的短时响应丢失恢复和原子配置落盘；Server 端独立 TLS 1.3 监听已支持 mTLS 数据库身份校验、`v1` 协商、心跳、在线状态、重连 fence、禁用 Host 后断流，以及严格类型化的 probe 和部署命令、有界发送队列、并发去重和只保存指纹/安全结果的进程内缓存。正式 `owndock-agent` 进程可以使用已签发证书主动连接 Server，通过受信任的本机 Unix Socket 执行 Docker probe、镜像准备、候选容器健康门禁、激活和安全取消，并以权限受限、原子写入的磁盘状态跨重启重放安全结果。Agent 另用独立、不可淘汰且失败关闭的槽位水位保存最高 cutover sequence，使容器被删除或 Agent 重启后仍能拒绝延迟旧命令。Agent 部署采用 `stage → Server 验证 Mongo lease/cutover fence → activate`，不会把控制面 fencing 压缩进一个远程命令；Agent Server 和 Deployment Worker 同时启用时，Agent prober 与 Gateway 会配套注册。Agent 证书支持到期前自动轮换、响应丢失恢复、最多 10 分钟旧证书过渡和新 hello 确认；真实 enrollment/轮换故障注入和多主机系统验收仍未完成。Release 可绑定 Project 范围的 Registry Credential，并声明端口、Environment 配置键、CPU/内存和容器健康检查；凭据与秘密值只通过 `secret://` 引用在 Worker 执行期解析。默认关闭的受管 Worker 可以通过 direct mTLS 或 Agent 连接 Docker Engine，携带私有仓库认证按 digest 拉取镜像，候选容器健康后再替换旧容器；同 Deployment 的租约 generation 阻止过期 Worker，同一部署槽位单调递增的 cutover sequence 阻止跨 Deployment 的延迟旧命令覆盖新版本。真实本地 Docker Engine 集成测试覆盖 Agent probe、两阶段 Agent 部署/取消、direct 固定 digest 健康替换、失败保留、过期执行隔离和取消清理。Source Repository 支持标准 HTTPS/SSH 地址、外部秘密引用、双指纹校验和显式只读 probe；probe 不 checkout 源码、不执行仓库内容。Build Configuration 提供 Application 范围版本化配方 API；手动、通用 Trigger Token 和 GitHub/GitLab/Gitea/Forgejo 签名 Webhook 都会固定允许 ref、完整 Commit SHA 和非秘密配置快照，再创建 queued Build。API Server 不 checkout 或执行客户代码；独立 `owndock-build-worker` 使用固定 Git 2.55.0 检出精确 Commit，通过固定版本和 digest 的 rootless BuildKit 构建，并以单次 Session 凭据推送 Registry；真实 OCI digest 会在 lease generation fence 下形成 Artifact，并按配置幂等创建带同一运行规格的不可变 Release。Maintainer/Owner 可为 development 配置最多 8 个自动部署目标；规则进入不可变快照，并通过普通 Deployment 用例执行就绪检查、幂等与审计，staging/production 首版始终人工触发。BuildKit status 在持久化前流式脱敏，并通过有界 cursor API 增量读取。实际入口流量、远程 mTLS Engine 和故障注入验证仍需补齐。

Docker Runtime Inventory 已建立独立领域模型、MongoDB observation/history/current Repository、direct/Agent 可复用的四类 Docker 安全 mapper、精确字节有界分块、Agent 内存快照协议、持续 Event 游标和默认关闭的受管 Worker。新 generation 在全部分块完成前不会修改 current presence；完整提交会在同一事务标记 absent、恢复 present 并切换 head。模型不保存原始 Inspect、Environment 值、Registry authorization、Volume options/status 或宿主 Mount source。Project 查询只返回经成功 Deployment 核验的受管容器，Host 查询以独立权限返回四类安全资源；固定过滤、不透明游标和审计已进入公开 API。真实双主机、网络分区和容量故障验收仍需补齐，详见 [docs/runtime-inventory.md](docs/runtime-inventory.md)。

正式 Deployment 已采用 Project 作用域的幂等键、原子领取、租约版本控制和受管 Worker；Worker 默认关闭，启用和凭据约定见 [docs/worker.md](docs/worker.md)。早期未认证、进程内存实现的顶层 Application、Environment 和 Deployment 样例已删除，所有产品资源统一进入 Project 所有权、授权、持久化和审计边界。

通用 Build Trigger API 现已独立于用户 Session：Owner/Maintainer 为一个 Build Configuration 创建只显示一次的 Token，数据库只保存哈希；Git 平台只能提交完整 ref 与 Commit SHA，不能覆盖仓库和构建目标，并受 MongoDB 跨 Server 共享限流保护。详见 [docs/build-triggers.md](docs/build-triggers.md)。

平台 Webhook Adapter 已支持 GitHub、GitLab Standard Webhooks、Gitea 和 Forgejo：先对原始请求体验签，再解析 Push，按 delivery ID 去重并快速返回 `202`。详见 [docs/webhooks.md](docs/webhooks.md)。

## 本地运行

```bash
go mod tidy
make check
make run
```

默认监听 `0.0.0.0:8000`。配置见 `configs/config.yaml`。

```bash
curl http://127.0.0.1:8000/livez
curl http://127.0.0.1:8000/readyz
curl http://127.0.0.1:8000/metrics
curl http://127.0.0.1:8000/api/v1/meta/version
```

MongoDB 启用时从 `database.mongo.uri_env` 指定的环境变量或 `uri_file` 指定的受限 Secret 文件二选一读取连接串，默认开发变量名为 `OWNDOCK_MONGODB_URI`。启动会连接并 Ping，运行期 `/readyz` 会检查主节点可用性，停止时关闭连接池。开发与 CI 使用固定的 MongoDB 8.3.7 单节点 Replica Set，详见 [docs/mongodb.md](docs/mongodb.md)。

本地启用正式产品切片时，将 `database.mongo.enabled` 和 `product.enabled` 设为 `true`，并通过环境变量提供 MongoDB URI 与一次性 bootstrap token：

```bash
export OWNDOCK_MONGODB_URI='mongodb://...'
export OWNDOCK_BOOTSTRAP_TOKEN='use-a-long-random-bootstrap-token'
make run
```

随后调用 `POST /api/v1/auth/bootstrap` 创建首个 Organization 和 Owner。Bootstrap、登录、资源写入和部署流程见 [docs/flows.md](docs/flows.md)，部署前的镜像证据门禁见 [docs/deployment-policies.md](docs/deployment-policies.md)，Agent 首次安全接入见 [docs/agent-enrollment.md](docs/agent-enrollment.md)，完整请求契约见 [api/openapi.yaml](api/openapi.yaml)。

`make build` 会同时生成 `bin/owndock`、`bin/owndock-agent`、`bin/owndock-build-worker`、`bin/owndock-evidence-worker` 和一次性 `bin/owndock-vulnerability-db-updater`。Agent 构建、证书文件、配置与当前开放边界见 [docs/agent.md](docs/agent.md)，正式发布身份与客户离线验签见 [docs/release-security.md](docs/release-security.md)；Build Worker 见 [docs/build-worker.md](docs/build-worker.md)，Evidence Worker 见 [docs/artifact-evidence.md](docs/artifact-evidence.md)，漏洞库更新与恢复见 [docs/vulnerability-database.md](docs/vulnerability-database.md)，限时风险接受见 [docs/vulnerability-waivers.md](docs/vulnerability-waivers.md)。提交的配置文件只是非敏感模板，不能直接用于生产。

如需启用链路追踪，将 `observability.tracing.enabled` 设为 `true`，并将 `endpoint` 配置为 OTLP/HTTP Collector 的 `host:port`（通常为 `localhost:4318`）。`sample_ratio` 取值为 `0` 到 `1`，默认配置为 `1`；设为 `0` 时不采样新的根 Span，无需追踪时应直接关闭 tracing。生产环境建议由应用发送至 OpenTelemetry Collector，再由 Collector 转发到后端。

## 目录约定

```text
api/                 对外契约；后续放置 proto/OpenAPI 源文件
cmd/server/          API 服务进程 composition root
cmd/agent/           主机侧 Agent composition root
cmd/vulnerability-db-updater/  一次性 Trivy DB 快照发布工具
configs/             可提交的非敏感配置模板
docs/                项目架构和工程约束
internal/agent/      Agent 控制客户端、配置与本机运行时
internal/app/        Kratos 应用生命周期
internal/modules/    按领域垂直切分的业务模块
internal/platform/   配置、数据库、可观测性等平台能力
internal/server/     HTTP/gRPC transport 装配
internal/shared/     Server 与 Agent 的仓内共享纯 Go 契约
```

文档入口见 [docs/README.md](docs/README.md)，单节点安装与恢复见 [docs/community-installation.md](docs/community-installation.md)，本地用户接入见 [docs/users-and-invitations.md](docs/users-and-invitations.md)，Project 授权见 [docs/project-members.md](docs/project-members.md)，第一次从 Git 部署见 [docs/git-to-deploy-quickstart.md](docs/git-to-deploy-quickstart.md)，产品定义见 [docs/product.md](docs/product.md)，架构约束见 [docs/architecture.md](docs/architecture.md)，Git 仓库连接见 [docs/source-repositories.md](docs/source-repositories.md)，构建配方见 [docs/build-configurations.md](docs/build-configurations.md)，手动构建见 [docs/builds.md](docs/builds.md)，自动部署见 [docs/automatic-deployments.md](docs/automatic-deployments.md)，Docker 资源清单见 [docs/runtime-inventory.md](docs/runtime-inventory.md)，核心时序见 [docs/flows.md](docs/flows.md)，发布候选门禁见 [docs/release-readiness.md](docs/release-readiness.md)，发布前契约见 [api/openapi.yaml](api/openapi.yaml)。`make check` 会执行格式、依赖完整性、架构边界、单元/契约测试、GitHub Actions 静态校验、OpenAPI 校验、静态检查和构建验证；`make test-community-deployment` 校验单节点 Secret 和 Compose 配置，`make test-community-integration` 通过真实容器验证启动、Bootstrap、候选升级、基线回滚、持久化及备份恢复；`make test-integration` 使用 Docker 验证固定 MongoDB Replica Set；`make test-runtime-integration` 针对本机 Docker Engine 验证固定 digest 的容器切换；`make test-release-candidate` 组合正式 Tag 前可重复执行的仓库内门禁；`make vuln` 使用固定版本的 Govulncheck 检查可达漏洞。漏洞报告方式见 [SECURITY.md](SECURITY.md)。

入口限流与反向代理信任配置见 [docs/ingress-protection.md](docs/ingress-protection.md)。

## License

OwnDock 社区核心使用 [Apache License 2.0](LICENSE)。
