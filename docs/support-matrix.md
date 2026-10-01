# OwnDock 支持与认证矩阵

本文区分“仓库已锁定的工程基线”和“已经可以向客户承诺的生产支持”。依赖被固定、代码可以编译或测试已经编码，都不自动构成生产认证。

## 状态定义

| 状态 | 含义 |
| --- | --- |
| 已锁定 | 仓库使用不可变版本或 digest，并有自动化检查防止漂移 |
| 已验证 | 对应仓库门禁已经在所列环境真实执行并通过 |
| 认证候选 | 首发准备支持的精确环境；仍有生产等价门禁未完成 |
| 已认证 | 发布制品已经在精确环境完成安装、升级、回滚、故障和安全门禁，可写入正式版本支持声明 |
| 不支持 | 不进入首发支持范围 |

正式版本只能把发布制品附带的兼容性报告中状态为 `passed` 的组合声明为“已验证”。“认证候选”不得出现在销售合同、官网或安装器中作为无条件支持承诺。

## 首发客户环境

面向中小型公司的首发范围保持单一、可复现：

| 项目 | 首发选择 | 当前状态 | 认证出口条件 |
| --- | --- | --- | --- |
| Server/Worker 主机 | Ubuntu Server 24.04 LTS、systemd、cgroup v2 | 认证候选 | 原生双架构发布门禁、安装/升级/回滚、重启与资源压力全部通过 |
| CPU | `linux/amd64`、`linux/arm64` | 已锁定；远程证据待归档 | 两个平台使用同一正式 Tag 制品完成社区版和 Agent 门禁 |
| Docker Engine | 29.6.1，启用 API 协商 | 认证候选 | 两台生产等价主机完成远程 mTLS、部署切换、入口流量、网络中断和升级回归 |
| MongoDB Server | 8.3.7、FCV 8.3、Replica Set | 已锁定；生产拓扑待认证 | 客户等价存储完成备份恢复、Primary 故障转移、TLS/证书轮换和滚动维护 |
| Managed ingress | Caddy 2.11.4 | 已锁定；真实公网待认证 | HTTP/1.1、HTTP/2、WebSocket、IPv4/IPv6、DNS/ACME、端口冲突和回滚全部通过 |

Docker Engine 首发不声明一个未经验证的宽版本区间。29.6.1 是当前固定集成 Engine 和首个生产认证候选；后续补丁或大版本必须在独立兼容性 PR 中更新精确版本、执行相同矩阵并留下发布证据。客户端保留 API 协商只是连接机制，不代表所有可协商 Engine 都受支持。

## 仓库锁定基线

| 组件 | 精确基线 | 仓库来源 |
| --- | --- | --- |
| Go | 1.26.5 | `go.mod` 与所有构建/发布工作流 |
| Kratos | 2.9.2 | `go.mod` |
| MongoDB | `mongo:8.3.7-noble@sha256:8444a416f2fc991f15064df9f6ea31ee02877607a70fd352ea998e6dbb5714b3` | 社区 Compose、MongoDB 集成门禁 |
| MongoDB Go Driver | 2.8.0 | `go.mod` |
| Docker 集成 Engine | `docker:29.6.1-dind@sha256:66d292e5c26bd33a6f6f61cacb880de2186339a524ecba1ce098dbbaceed6515` | 双 Engine/双 Agent 门禁 |
| Managed ingress | `caddy:2.11.4-alpine@sha256:6aeddd44c3078b0f9a35206472a11420648a79c184603ef95957d0a20044cb2b` | Agent 安装包与 ingress 门禁 |
| Git CLI | 2.55.0 | Build Worker 启动检查和构建门禁 |
| BuildKit | 0.31.2 rootless | `go.mod`、Compose 与构建门禁 |

镜像必须继续使用 tag 与 OCI index digest 的组合；禁止 `latest`、仅主版本或仅次版本等浮动 tag。依赖升级不能顺带修改支持声明，必须同时更新对应 fixture、双架构门禁、升级/回滚结果和本文。

## 首发不支持

- 非 Linux、非 systemd 主机；
- Kubernetes、containerd 或其他运行时；
- Docker Desktop 作为生产 Runtime Target；
- 未认证的 Linux 发行版、CPU 或 Docker Engine 版本；
- MongoDB standalone 生产拓扑；
- 完全离线安装；
- 多控制面高可用和自动跨主机调度。

## 发布判定

正式 Tag 之前，发布负责人必须把以下证据关联到 Release：

1. Ubuntu 24.04 原生 `amd64` 与 `arm64` 的社区版完整门禁；
2. 两台独立主机上的 Agent mTLS、部署、Inventory、Terminal 和 ingress 流量切换；
3. MongoDB Replica Set 的备份、空库恢复、Primary 故障转移与证书轮换；
4. 当前版本升级、失败恢复和回滚；从第二个版本开始还必须覆盖相邻正式版本；
5. 兼容性报告中的实际内核、文件系统、Docker Engine、CPU、制品 digest 和结果。

缺少任一生产等价证据时，可以发布 pre-release，但不能把对应组合提升为“已认证”。具体自动门禁与人工阻断项见[社区版发布候选门禁](release-readiness.md)。
