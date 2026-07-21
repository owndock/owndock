# OwnDock

**Own your apps. Run them anywhere.**

OwnDock 是面向开发者和团队的自托管应用交付与运行平台，提供应用部署、运行和基础设施管理 API。项目采用 **Go + Kratos 的模块化单体**：在单进程内保持清晰的领域边界和可测试契约，并允许模块在出现独立扩缩容或故障隔离需求时演进为服务。

本仓库负责后端服务，不包含 Web 前端工程。

## 当前基线

- Go module：`github.com/owndock/owndock`
- Go：1.26.x
- Kratos：v2.9.2
- 依赖组装：composition root 手工组装，不使用 Google Wire
- 主服务进程：`owndock`
- 当前接口：`GET /livez`、`GET /readyz`、`GET /api/meta/version`

当前版本提供项目运行基线，业务能力会按领域模块逐步实现。

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
curl http://127.0.0.1:8000/api/meta/version
```

## 目录约定

```text
api/                 对外契约；后续放置 proto/OpenAPI 源文件
cmd/server/          API 服务进程 composition root
configs/             可提交的非敏感配置模板
docs/                项目架构和工程约束
internal/app/        Kratos 应用生命周期
internal/modules/    按领域垂直切分的业务模块
internal/platform/   配置、数据库、可观测性等平台能力
internal/server/     HTTP/gRPC transport 装配
```

项目架构约束见 [docs/architecture.md](docs/architecture.md)。
