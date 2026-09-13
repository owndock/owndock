# Go 测试与变更覆盖率门禁

OwnDock 不要求一次把全部历史代码覆盖率推到同一个数字，而是要求每次新增或修改的可执行 Go 语句至少达到 80% 覆盖率。这样门禁会持续阻止测试债务增长，同时不会用一个全仓平均值掩盖新代码的风险。

## 本地执行

先选择一个不可变的 Git commit 作为比较基线，再执行：

```bash
make test-changed-coverage COVERAGE_BASE=<完整或可解析的 commit SHA>
```

命令会执行全部 Go 单元测试、真实 HTTP/OpenAPI 契约测试、MongoDB Replica Set 集成测试，以及固定 Distribution/Cosign/Vault Transit 镜像的供应链系统测试，合并多个 atomic coverage profile，然后仅统计基线之后新增或修改行所对应的可执行语句。失败报告会按文件列出未覆盖的变更行。HTTP、Mongo 与供应链 profile 显式覆盖业务模块，因此跨 package 的真实 Handler/Repository 执行不会丢失归属。

`COVERAGE_BASE` 不能省略。不要用会随时间移动的分支名作为发布证据；Pull Request CI 会使用目标分支的 commit SHA，push CI 使用事件中的前序 commit。

## 统计边界

- 默认阈值是 80%，可用 `CHANGED_COVERAGE_THRESHOLD` 临时提高，不能在 CI 中降低；
- `_test.go`、标准 `Code generated ... DO NOT EDIT.` 文件和没有可执行语句的纯声明文件不进入分母；
- 生产 Go 文件如果没有进入任何 coverage profile，门禁直接失败，防止通过漏跑 package 绕过检查；
- 覆盖率只证明语句被执行，不能代替权限矩阵、状态机、故障补偿、竞态和端到端验收。

## 排除规则

极少数通过真实子进程、打包或平台系统测试验证的入口与 fixture，记录在 `.github/changed-coverage-exclusions.txt`。每条排除必须包含精确路径、复核日期和原因；到期后门禁自动失败。不得为了让比例通过而加入普通业务代码，也不得用目录级排除覆盖生产模块。

CI 仍会独立执行格式、依赖校验、`go vet`、全量单元测试、MongoDB 集成测试、API 契约、构建、Agent 进程测试和 race 检测。`make test-integration` 同时运行单节点完整产品持久化回归、启用认证且只有目标数据库 `readWrite` 权限的应用身份回归、认证 + `requireTLS` 的加密/明文拒绝/错误 CA 回归，以及三成员 Replica Set 的全员就绪、Primary 停止、不同成员接管、切换后 majority 事务恢复和跨切换 Runtime Inventory current view 提交。架构测试还要求生产代码中的每个 Driver `WithTransaction` 显式使用统一耐久选项。定时/手动双架构安全 Job 继续重复执行供应链真实 Registry/KMS 门禁，防止只在相关源码发生变化时运行。变更覆盖率只是其中一道门禁。

正式 Tag 会执行更完整的仓库内发布候选组合门禁：

```bash
make test-release-candidate
```

它在上述基础上组合社区版 Compose 启动/Bootstrap/持久化重启/候选升级/基线回滚/停写备份/空卷恢复、真实本机 Docker、Agent 进程轮换/双 Host 隔离和 Terminal 专项竞态测试。社区系统门禁在原生 Ubuntu 24.04 amd64/arm64 Runner 上运行；正式 Release 从第二个版本开始还会由 `community-release-compatibility` 使用相邻两版已签名制品重跑同一旅程。它与客户等价环境的人工阻断项见[社区版发布候选门禁](release-readiness.md)。

## 私有 Sigstore keyless 门禁

`.github/workflows/supply-chain-keyless.yml` 会启动固定版本的私有 Sigstore 栈，使用其 Fulcio、Rekor、CT Log、TSA 和 OIDC 签发真实 keyless bundle。签名完成后，测试会停止承载这些服务的 KinD 节点，再仅依赖固定 trusted root 和 Registry 调用 OwnDock 适配器验证 bundle。门禁同时要求正确 identity/issuer 通过，错误 identity、错误 issuer、跨 digest 重放和缺少透明日志根材料全部失败关闭。

`make test-private-sigstore-integration` 不会自行创建信任基础设施，它是供上述 CI 或已预置等价私有 Sigstore 环境调用的内部入口。手工运行需要显式提供 signing config、trusted root、精确 identity/issuer、短时 OIDC token 和可停止的 KinD 节点容器；不应把 token 写入命令行、文件或日志。该工作流的首次 GitHub Actions 远程结果尚未获取，因此本地通过编译和静态检查不等于这项系统门禁已经验收。

## 漏洞扫描门禁

Trivy 适配器单元测试覆盖固定 `0.74.0`、精确 digest 调用、扫描前后 DB 元数据一致、扫描期间 DB 变化失败关闭、输出上限、凭据清零和错误分类。MongoDB Replica Set 门禁覆盖 Evidence、最新 Vulnerability Observation 和 Job 完成的同事务提交，并验证持续重扫的有界游标、两个 Server 并发只产生一个活动任务、同一失败重试时间桶去重和下一时间桶恢复入队。

Registry 传输测试使用自签名 TLS Registry 和真实 HTTP CONNECT 隧道，验证未配置时忽略宿主环境代理、配置后只走显式代理、仍执行 CA/主机名校验且不发送 `Proxy-Authorization`。Syft、Trivy、Cosign 的子进程测试进一步核对只注入配置指定的大小写代理变量并清空 `NO_PROXY`；ORAS、Artifact Probe、Evidence Reader 和 Referrer Client 对含凭据或非规范代理地址失败关闭。

真实 Distribution/Syft 门禁还会上传一个带实际压缩 layer blob 的超限 OCI 镜像，在较小但同语义的测试阈值下验证 OwnDock 先读取不可变 manifest 并在 Syft 子进程启动前失败关闭。配套生成器和 Worker 测试继续验证 Registry Credential 清零与稳定的 `resource_limit` 分类。纯解析测试覆盖单 manifest、多平台 index、畸形 digest/size、递归 index 和数量上限；这项门禁验证产品代码，不依赖 Syft 对 Registry source 的上游大小参数实现。

`make test-vulnerability-integration` 会从固定 digest 的 Trivy 多架构镜像提取扫描器，通过正式 Snapshot Manager 下载真实 DB 并原子发布 `current`，再启动固定版本的私有 Distribution Registry。门禁验证精确镜像 digest 扫描、报告主题绑定、OCI Referrer 发布和完整内容回读；同一测试还在非 root、只读根、无 capabilities、PID/CPU/内存/tmpfs 上限下使用只读 DB 完成离线扫描，并用 16 MiB+1 的真实子进程输出验证硬截断和凭据清零。

Updater 镜像另已在相同的非 root、只读根、无 capabilities 和有限资源约束下下载并发布真实 DB。该测试下载量较大，因此不进入普通 `make check`，而由定时/手动的双架构 `test-build-security` 执行。首次 GitHub Actions 双架构结果尚未获取；误报豁免以及生产出口/客户文件系统矩阵仍待补齐，因此不能据此宣称漏洞治理已全部生产就绪。
