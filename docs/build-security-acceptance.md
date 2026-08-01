# Git-to-Deploy 安全验收

Git-to-Deploy 会执行仓库中的 Dockerfile，因此“字段校验通过”不等于“构建安全”。OwnDock 把源码执行放在独立 Build Worker 和 rootless BuildKit 中，并用下面的自动化门禁验证攻击、故障与秘密边界。

## 一条命令运行当前门禁

```bash
make test-build-security
```

该命令会运行 Build 模块竞态测试、真实 MongoDB Replica Set 恢复测试，以及真实 mTLS rootless BuildKit/认证 Registry 测试。它需要本机 Docker Engine；CI 每周定时运行，也可手动触发。普通单元测试仍包含在 `make check` 中。

## 当前自动化证据

| 风险 | 验收行为 | 当前证据 |
| --- | --- | --- |
| Dockerfile 请求主机网络或 insecure entitlement | BuildKit 未授予任何 entitlement，构建安全失败且不推送 manifest | 真实 rootless BuildKit |
| 可变 Dockerfile frontend | `# syntax=` 只能等于固定 digest，其他值在 Solve 前拒绝 | 单元 + 真实固定 frontend |
| 超大或符号链接 Dockerfile/context | 1 MiB 上限与逐段 symlink 检查在秘密解析、Solve 前执行 | 单元测试 |
| checkout 填满工作区 | fetch 期间持续统计文件数和字节数，越界取消 Git 子进程 | 单元故障注入 |
| Worker 失联或旧 Worker 继续写 | Mongo lease generation fence 拒绝旧状态、digest 和 Artifact | Replica Set 集成 + 竞态 |
| Worker 进程被强制终止 | 独立进程领取并推进 Build 后被 `SIGKILL`；lease 到期后新 Worker 以更高 generation 接管 | 真实进程 + Replica Set |
| BuildKit 网络中断 | 当前请求安全失败；网络恢复后同一固定输入可再次构建并得到 canonical digest | 真实容器网络故障注入 |
| Registry 凭据错误 | 只返回稳定 `registry_authentication` 类别，不暴露底层响应 | 单元 + 真实 Registry |
| Webhook 重放 | 每次请求先验签，再按 provider/Hook/delivery 长期去重；伪造的已知 delivery 仍被拒绝；GitLab Standard Webhooks 另要求签名时间戳在前后 5 分钟内 | 领域 + HTTP + Replica Set |
| Webhook 洪峰 | 新的签名有效 delivery 按 Hook 共享固定窗口计数；默认 120/分钟，超限返回 429/Retry-After，已认证重放不重复计数 | 领域 + HTTP + Replica Set |
| Registry 密码泄漏 | 扫描 Build 日志、BuildKit/Registry 容器日志、容器导出文件系统/BuildKit cache、OCI manifest/config 和解压 layer | 真实 Registry 制品与容器扫描 |
| 推送后 Worker 中断 | 已保存 digest 的 Build 直接发布 Artifact/Release，不 checkout、不重建、不重复 push | Worker + Replica Set |
| 自动部署协调失败 | Artifact 保持 `release_pending`，已创建目标幂等复用，目标恢复后补齐 | 领域 + Replica Set |

## 仍未形成生产证据

以下项目仍是 BUILD-011 的发布阻断项，不能因为当前命令通过就宣称生产就绪：

- 在独立、带硬配额的文件系统上注入 BuildKit cache/工作区磁盘耗尽，并验证相邻 Build 不受影响；
- 完整 `owndock-build-worker` 二进制执行真实 Git/BuildKit 时被终止，以及 MongoDB/Registry/BuildKit 分别中断时的端到端接管；当前 SIGKILL 门禁覆盖独立 Worker 控制进程与真实 Mongo lease，不冒充完整源码构建链；
- 超大 Git 仓库、压缩炸弹、Fork/PR 事件，以及 Webhook 乱序和真实网络洪峰系统场景；仓内已具备共享准入上限，但尚未完成生产压测；
- BuildKit 出站网络白名单或代理策略的生产等价验证；Dockerfile 默认仍可能发起网络请求；
- Git 自建 CA、企业代理、目标 amd64/arm64 内核和文件系统兼容矩阵；
- API 的全接口秘密扫描报告、压缩 cache 深层内容检查，以及制品保留/销毁验证；MongoDB、审计、BuildKit/Registry 容器文件系统和 OCI 制品已有已知秘密哨兵扫描。

这些项目完成前，构建 Worker 保持显式启用，文档继续使用 pre-release 表述。
