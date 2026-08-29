# Git-to-Deploy 安全验收

Git-to-Deploy 会执行仓库中的 Dockerfile，因此“字段校验通过”不等于“构建安全”。OwnDock 把源码执行放在独立 Build Worker 和 rootless BuildKit 中，并用下面的自动化门禁验证攻击、故障与秘密边界。

## 一条命令运行当前门禁

```bash
make test-build-security
```

该命令会运行 Build 模块竞态测试、真实 MongoDB Replica Set 恢复测试、真实 OwnDock Server 进程入口黑盒扫描，以及真实 mTLS rootless BuildKit/认证 Registry 测试。它需要本机 Docker Engine；CI 每周定时运行，也可手动触发，并在原生 Ubuntu 24.04 amd64 与 arm64 Runner 上分别执行。普通单元测试仍包含在 `make check` 中。

## 当前自动化证据

| 风险 | 验收行为 | 当前证据 |
| --- | --- | --- |
| Dockerfile 请求主机网络或 insecure entitlement | BuildKit 未授予任何 entitlement，构建安全失败且不推送 manifest | 真实 rootless BuildKit |
| 可变 Dockerfile frontend | `# syntax=` 只能等于固定 digest，其他值在 Solve 前拒绝 | 单元 + 真实固定 frontend |
| 超大或符号链接 Dockerfile/context | 1 MiB 上限与逐段 symlink 检查在秘密解析、Solve 前执行 | 单元测试 |
| checkout 填满工作区 | fetch 期间持续统计文件数和字节数，越界取消 Git 子进程 | 单元故障注入 |
| 工作区硬配额耗尽 | Worker 启动时拒绝共享目录和超过配置容量的文件系统；真实 Linux 容器使用独立 4 MiB tmpfs 写至内核 `ENOSPC`，清理后相邻 Build 可立即创建和写入工作区 | 配置/领域 + Docker 内核硬配额 |
| 高压缩 Git 对象在 checkout 后膨胀 | 真实 smart HTTPS 仓库的压缩 pack 可完成 fetch，但工作树展开超过字节上限后仍返回 `build_resource_limit`，不能进入 BuildKit | 真实 Git 协议 fixture |
| 大型不可压缩 Git pack | 真实随机二进制对象使 fetch 目录超过字节上限后返回 `build_resource_limit`，且不物化工作树文件 | 真实 smart HTTPS Git 协议 fixture |
| 海量小文件或异常深目录树 | checkout 前流式检查目标 Commit 的条目数、blob 展开字节和路径深度；越界时不物化工作树 | parser 边界测试 + 真实 smart HTTPS 仓库 |
| Worker 失联或旧 Worker 继续写 | Mongo lease generation fence 拒绝旧状态、digest 和 Artifact | Replica Set 集成 + 竞态 |
| Worker 进程被强制终止 | 完整 `owndock-build-worker` 在真实 Git checkout 后进入 BuildKit `RUN` 阶段并被 `SIGKILL`；lease 到期后第二个完整二进制以更高 generation 重新检出固定 Commit、完成认证 Registry push 和 Artifact 发布；进程输出扫描 Mongo URI 与 Registry 密码 | smart HTTPS Git + Replica Set + mTLS rootless BuildKit + 认证 Registry |
| BuildKit 网络中断 | Gateway 当前请求安全失败；完整 Worker 启动时 BuildKit 不可用则进程失败关闭且 Build 保持 `queued`/无 lease，BuildKit 恢复后新进程完成同一固定输入 | 真实容器网络故障注入 + 完整进程 |
| Dockerfile 绕过构建出口策略 | BuildKit 只连接无外网路由的内部 Build Boundary；唯一双网卡出口网关按精确 `host:port` 放行 HTTP/HTTPS。未授权域名返回稳定 `build_network_policy`，清空代理变量后的原始 TCP、metadata 地址以及网关断网均失败关闭 | 真实 rootless BuildKit + 双 Docker 网络 + HTTP/CONNECT 网关黑盒 |
| Registry 网络中断 | 完整 Worker 构建失败为稳定 `registry_push`，不发布 Artifact；网络恢复后基于原 Build 固定快照创建的不可变 Retry 成功 | 完整进程 + 真实认证 Registry 断网 |
| MongoDB 执行期中断 | Worker 在真实 BuildKit `RUN` 阶段失去 Replica Set，lease 续期失败并取消旧执行；MongoDB 恢复后同一完整进程以更高 generation 接管并发布 Artifact | 完整进程 + Replica Set pause/unpause |
| BuildKit cache 硬配额耗尽 | rootless BuildKit cache 使用独立 512 MiB tmpfs；写满后真实构建稳定归类 `resource_limit` 且无 Registry manifest，删除耗尽注入并 prune 后相邻构建成功 | 真实 rootless BuildKit + 内核硬配额 + 认证 Registry |
| Registry 凭据错误 | 只返回稳定 `registry_authentication` 类别，不暴露底层响应 | 单元 + 真实 Registry |
| Webhook 重放 | 每次请求先验签，再按 provider/Hook/delivery 长期去重；伪造的已知 delivery 仍被拒绝；GitLab Standard Webhooks 另要求签名时间戳在前后 5 分钟内 | 领域 + HTTP + Replica Set |
| Fork Pull/Merge Request | 四个平台只允许 Push event；签名正确的 PR/MR（包括 Fork）固定 ignored，不解析为 Build，也不接触 Repository/Registry Secret | provider allowlist + 签名后忽略测试 |
| Webhook 洪峰 | 新的签名有效 delivery 按 Hook 共享固定窗口计数；默认 120/分钟，超限返回 429/Retry-After，已认证重放不重复计数；真实 TCP HTTP fixture 以 64 路并发和有效 GitHub HMAC 严格验证 10 个 accepted、54 个 limited | 真实 HTTP + Handler + Replica Set |
| Webhook 跨 delivery 乱序 | 不信任不同 delivery 的到达顺序；每次 Push 在入队前将 payload Commit 与远端 ref 当前 Commit 对照，迟到旧 Commit 返回 `202 ignored` 且不创建 Build；真实 TCP、有效 HMAC 与 Replica Set 验证“当前 Push 后到达旧 Push”只产生一个当前 Build | 领域 + 真实 HTTP + Handler + Replica Set |
| API 回显 Secret 引用或请求秘密 | OpenAPI 中每个 operation 都有真实 Handler exchange；响应 body/header 会扫描本次请求中的密码、Token、签名、票据和 `secret://` 哨兵。另构建并启动真实 Server 二进制和 MongoDB Replica Set，通过 TCP 验证 bootstrap、登录、Bearer 拒绝、畸形 JSON、共享入口 429、`no-store` 以及进程日志均不泄漏哨兵。Registry/Runtime Target 只返回 `*_configured`，Environment 只返回排序后的变量名 | 全 OpenAPI contract + 真实进程/TCP/MongoDB 黑盒 |
| Registry 密码泄漏 | 扫描 Build 日志、BuildKit/Registry 容器日志、容器导出文件系统、OCI manifest/config 和解压 layer；另直接流式导出镜像声明的 BuildKit cache volume，对原始、gzip、zstd entry 做有界深扫 | 真实 Registry 制品、容器与 cache volume 扫描 |
| 推送后 Worker 中断 | 已保存 digest 的 Build 直接发布 Artifact/Release，不 checkout、不重建、不重复 push | Worker + Replica Set |
| 自动部署协调失败 | Artifact 保持 `release_pending`，已创建目标幂等复用，目标恢复后补齐 | 领域 + Replica Set |
| 架构或宿主能力漂移 | CI 在原生 `ubuntu-24.04` amd64 与 `ubuntu-24.04-arm` arm64 上先核对 Linux、CPU、Go 架构和 cgroup v2，记录内核、工作区/临时文件系统及 Docker 版本/架构/存储驱动，再执行同一套完整门禁 | GitHub Actions 双原生架构矩阵；首次远端运行结果仍需归档 |

## 仍未形成生产证据

以下项目仍是 BUILD-011 的发布阻断项，不能因为当前命令通过就宣称生产就绪：

- 客户等价内核和文件系统兼容矩阵；仓库已配置 Ubuntu 24.04 原生 amd64/arm64、cgroup v2 的同门禁 CI，但首次远端结果以及 ext4/xfs + 独立 LVM/云盘组合仍需归档。Git 自建 CA、无凭据企业 HTTPS CONNECT proxy 已由 BUILD-001 的 Server/Worker 真实协议矩阵覆盖；
- 客户等价部署中的制品保留/销毁验证；仓内全 OpenAPI Handler exchange、真实 Server 进程入口、MongoDB、审计、BuildKit/Registry 容器文件系统、BuildKit cache volume 原始/gzip/zstd 内容和 OCI 制品已有已知秘密哨兵扫描。

构建出口门禁已经完成生产拓扑等价的容器验证，但客户防火墙、DNS、私有 Registry/依赖源仍需按部署环境验收。硬配额自动化使用 Linux tmpfs 触发真实 `ENOSPC`；实际交付仍必须在目标内核与文件系统矩阵中验证独立 LVM/云盘挂载。其余项目完成前，构建 Worker 保持显式启用，文档继续使用 pre-release 表述。
