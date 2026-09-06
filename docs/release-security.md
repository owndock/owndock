# Agent 正式发布与制品验签

> 状态：仓库已经实现确定性双架构 Agent 制品、五个多架构后端镜像、统一摘要清单、Sigstore keyless 签名、精确发布身份校验和离线验签。首个受保护正式 Tag 的公开 Release 及其下载/隔离网络验收仍需在 GitHub 上执行，因此当前不能把本地构建包或镜像描述为正式签名发行版。

本页面向两类读者：下载 Agent 的管理员需要确认“文件确实来自 OwnDock 的指定版本”；发布维护者需要保证“CI 之外没有人可以悄悄替换发行文件”。

## checksum 和签名分别解决什么问题

`SHA256SUMS` 记录每个文件的 SHA-256。它能发现下载损坏或文件被修改，但如果攻击者同时替换文件和 checksum，单独校验 checksum 仍会通过。

OwnDock 再使用 Sigstore/Cosign 签名整份 `SHA256SUMS`。签名证书由 GitHub Actions 的短时 OIDC 身份取得，不使用长期私钥；验签时必须同时匹配：

- 仓库：`owndock/owndock`；
- 工作流：`.github/workflows/release.yml`；
- Tag：用户正在安装的精确 `vMAJOR.MINOR.PATCH`；
- OIDC 签发方：`https://token.actions.githubusercontent.com`。

因此，从其他仓库、其他工作流或另一个版本复制来的有效签名也不能通过。

## 正式 Release 包含哪些文件

以 `v0.1.0` 为例，GitHub Release 由受保护工作流一次性创建：

```text
owndock-agent_0.1.0_linux_amd64.tar.gz
owndock-agent_0.1.0_linux_arm64.tar.gz
RELEASE.txt
SHA256SUMS
SHA256SUMS.sigstore.json
verify-owndock-agent-release
CONTAINER_IMAGES.txt
CONTAINER_IMAGES.sigstore.json
owndock-community_0.1.0.tar.gz
COMMUNITY_SHA256SUMS
COMMUNITY_SHA256SUMS.sigstore.json
```

`RELEASE.txt` 把产品、版本、Git Tag、完整 commit SHA 和源码仓绑定在一起。`SHA256SUMS.sigstore.json` 是 Sigstore bundle，包含签名证书和透明日志证明。GitHub 自动生成的 “Source code” zip/tar.gz 不在该清单内，不属于 OwnDock Agent 签名制品。

`CONTAINER_IMAGES.txt` 另外列出 Server、Build Worker、Build Egress Gateway、Evidence Worker 和 Vulnerability DB Updater 的五个 `image@sha256:digest`。每个 digest 都有同一 Release 工作流身份产生的 keyless 镜像签名；该文本清单本身也有独立 bundle。镜像先按 digest 推送，全部构建成功后才提升 SemVer tag；工作流只允许同一 digest 的幂等恢复，拒绝把已有版本 tag 改指其他内容。

`owndock-community_0.1.0.tar.gz` 是可复现的单节点 Compose 安装包，包含 Secret 初始化以及保守的空库恢复/停写备份工具。`COMMUNITY_SHA256SUMS` 同时固定该安装包和 `CONTAINER_IMAGES.txt`，并由独立 Sigstore bundle 保护，避免攻击者替换安装配置后仍引用合法镜像。

## 客户验签

先在可信环境安装并验证 Cosign。发行工作流固定使用 Cosign `v3.0.6`；客户应使用 `v3.0.6` 或更新且仍受支持的安全版本，不使用来源不明的二进制。

第一次准备联网验签环境时运行：

```bash
cosign initialize
```

下载目标架构的 archive，以及 `SHA256SUMS`、`SHA256SUMS.sigstore.json` 和验签脚本。以 `0.1.0` 为例，先直接验证清单签名：

```bash
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity \
  https://github.com/owndock/owndock/.github/workflows/release.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --offline
```

只有这一步成功后，才信任清单中的哈希和随 Release 下载的脚本。随后可以执行严格的单包验证：

```bash
chmod 0755 verify-owndock-agent-release
./verify-owndock-agent-release \
  0.1.0 \
  owndock-agent_0.1.0_linux_amd64.tar.gz \
  SHA256SUMS \
  SHA256SUMS.sigstore.json
```

脚本会再次离线验证签名，要求版本与文件名完全一致，只接受清单中固定的四个安全文件名，再比较 archive 的实际 SHA-256。任何签名身份不符、版本错配、重复/额外清单项、符号链接输入或制品篡改都会失败关闭。

验签成功只证明下载制品与该 Tag 的正式发布一致。之后仍需按[Agent 安装、升级与回滚](agent-installation.md)执行安装和灰度验证。

## 隔离网络验签

Sigstore bundle 支持不访问 Fulcio 或 Rekor 的离线校验，但验签机仍需可信的 Sigstore root。先在联网可信机器运行 `cosign initialize`，再按组织的介质管控流程把下面的 root 和已验证的 Cosign 二进制送入隔离区：

```text
~/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json
```

隔离区内显式指定该文件：

```bash
export OWNDOCK_SIGSTORE_TRUSTED_ROOT=/secure/sigstore/trusted_root.json
./verify-owndock-agent-release \
  0.1.0 \
  owndock-agent_0.1.0_linux_amd64.tar.gz \
  SHA256SUMS \
  SHA256SUMS.sigstore.json
```

Sigstore root 会轮换。组织需要定期在联网可信机器通过 TUF 更新并重新导入，不能把 Release 页面中未经独立信任的任意 root 文件当作信任起点。

## 发布维护者操作

仓库管理员先在 GitHub 创建名为 `release` 的 Environment，并配置：

1. 仅允许受保护的 `v*` Tag 部署；
2. 至少一名非发布操作人的 required reviewer，并禁止自我审批；
3. 对发布 Tag 配置创建、更新和删除保护；
4. 保持 Actions 默认 Token 最小权限，不添加发布私钥 Secret。

工作流依赖均固定：Go `1.26.5`、Cosign `v3.0.6`、Cosign Installer 的不可变 commit SHA。正式版本从已经通过主分支门禁的 commit 创建签名 annotated Tag：

```bash
git tag -s v0.1.0 -m "OwnDock v0.1.0"
git push origin v0.1.0
```

`.github/workflows/release.yml` 会再次执行仓库内发布候选门禁，构建 linux/amd64 与 linux/arm64 确定性 Agent 包以及五个多架构后端镜像。工作流为镜像生成 SBOM/Provenance，分别签名镜像 digest，再生成并签名 `CONTAINER_IMAGES.txt`；Agent 的 `RELEASE.txt`/`SHA256SUMS` 仍执行在线与离线双重自校验。只有全部矩阵成功后才创建 GitHub Release。

工作流发现同名 Release 已存在时拒绝替换资产。正式资产有问题时应修复代码并发布新的 patch Tag，不能删除、覆盖或悄悄重签旧版本。

本地只能验证构建和清单生成，不能伪装成正式发行：

```bash
make package-agent-release \
  VERSION=0.1.0 \
  ALLOW_DIRTY_RELEASE=1
```

该命令不会生成 `SHA256SUMS.sigstore.json`。只有受保护 Tag 工作流生成的 bundle 才是正式发布签名。
