# OwnDock Dockerfile Build Provenance v1

本文定义 OwnDock 生成的 SLSA Provenance v1 中两个稳定 URI 的含义，供客户、验证器、官网和后续 SDK 使用：

- `buildType`：`https://owndock.net/build-types/dockerfile/v1`
- `builder.id`：`https://owndock.net/builders/buildkit/v1`

URI 的 `/v1` 是 OwnDock 契约主版本。字段含义发生不兼容变化时必须使用新 URI；增加可忽略的兼容字段不改变历史声明。

## Build Type

这个 Build Type 表示：OwnDock 从已登记的 Git Source Repository 检出一个精确 Commit，在隔离 Build Worker 中使用固定版本的 rootless BuildKit 和 Dockerfile frontend 构建单一 Linux 平台镜像，并将结果推送到 OCI Registry 后取得不可变 digest。

### `externalParameters`

这些参数来自 Project 内的用户配置或构建触发，因此验证者必须按自己的允许规则检查：

| 字段 | 含义 |
| --- | --- |
| `source.repository` | 去掉用户信息和凭据后的 `git+https` 或 `git+ssh` URI |
| `source.ref` | 触发构建的完整 Git ref，例如 `refs/heads/main` |
| `buildConfiguration.id` | Build Configuration ID |
| `buildConfiguration.version` | Build 创建时复制的配置版本 |
| `buildConfiguration.applicationId` | 配置所属 Application |
| `dockerfile` | 仓库内 Dockerfile 相对路径 |
| `context` | 仓库内 build context 相对路径 |
| `platform` | 当前支持 `linux/amd64` 或 `linux/arm64` |

`resolvedDependencies[0]` 使用同一源码 URI 和 ref，并用 `digest.gitCommit` 固定完整 40 位 Commit SHA。验证时不能只检查 branch/ref；必须检查 Commit。

### `internalParameters`

这些参数由 Build Configuration 快照和受信任的 Worker 装配决定：

| 字段 | 含义 |
| --- | --- |
| `resources` | CPU、内存和临时磁盘上限 |
| `timeoutSeconds` | 构建超时 |
| `buildKitImage` | 带 SHA-256 digest 的 rootless BuildKit 镜像 |
| `dockerfileFrontend` | 带 SHA-256 digest 的 Dockerfile frontend 镜像 |

完整的 external/internal 参数会以确定性 JSON 计算 SHA-256，并作为 `runDetails.byproducts` 中的 `build-configuration-snapshot` 固定。任何参数修改都会改变该 digest。

## Builder

`https://owndock.net/builders/buildkit/v1` 表示 OwnDock 的隔离 Build Worker + rootless BuildKit 执行模式。它不表示所有安装实例共享同一个云端构建服务，也不表示 OwnDock 团队自动信任客户自己的主机。

Builder 信任边界包括：

- 当前 OwnDock Build Worker 二进制与其版本/Commit；
- 声明中固定 digest 的 BuildKit 和 Dockerfile frontend；
- 运行 Worker 的客户基础设施、容器隔离和配置；
- 负责 MongoDB queue/lease/generation fence、源码 Commit 二次核对和 Registry output digest 记录的控制逻辑。

`builder.version` 分别记录 OwnDock 版本、OwnDock Commit 和 BuildKit 版本；`builderDependencies` 再固定 BuildKit/frontend 镜像 digest。不同安全模式如果拥有不同信任边界，必须使用不同的 `builder.id`，不能沿用本 ID。

## Subject 与时间

- `subject[0].name` 是 Artifact 的 Registry repository；
- `subject[0].digest.sha256` 是 BuildKit push 后 Registry 返回的最终镜像 digest；
- `metadata.invocationId` 是 Build ID；
- `startedOn` 和 `finishedOn` 是控制面状态机记录的构建开始与 Artifact 创建时间。

只允许一个 subject。Tag 不进入 subject，也不能代替 digest。

## 安全声明边界

当前实现生成标准 in-toto Statement v1 / SLSA Provenance v1，并对下载内容执行 OCI manifest、subject、layer digest 和字段一致性校验。它没有在字段中写入 `slsaLevel`，也不宣称通过 SLSA Build L2/L3 评估。

在镜像签名任务完成前，Evidence 显示 `verification_status: unverified`。这表示存储完整性和声明结构已经验证，但 signer identity 还没有验证。客户若需要把 Provenance 用作 production 部署门禁，应等待受信任签名身份、trust root 和失败关闭策略同时启用。

Registry 密码、Git Token、SSH 私钥、Environment Secret、运行时变量值和其他 `secret://` 内容不会进入 Provenance。

## 最小验证清单

验证器至少应检查：

1. in-toto `_type` 和 SLSA `predicateType` 精确匹配 v1 URI；
2. subject repository/digest 与准备部署的 Artifact 完全一致；
3. `buildType` 和 `builder.id` 在允许列表中；
4. source URI、ref 和 Commit 符合 Project 预期；
5. Build Configuration ID/version、Dockerfile、context 和 platform 符合发布规则；
6. BuildKit/frontend 使用允许的不可变 digest；
7. 配置快照 digest、Builder 依赖 digest 和时间字段有效；
8. 当策略要求可信身份时，另外验证后续 Signature bundle，不能只信任 JSON 自述。
