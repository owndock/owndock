# 多语言与本地化

OwnDock 从首版按多语言产品设计。首批支持：

- `zh-CN`：简体中文；
- `en-US`：英语，也是无法匹配语言时的安全兜底语言。

支持多语言不仅是翻译按钮，还包括术语、日期时间、数字、校验提示、邮件、官网和客户文档的一致性。首版不加入繁体中文、日语等第三种语言，但结构上不能把语言写死在页面组件里。

## 控制台语言选择

语言解析顺序为：

1. 用户在 OwnDock 中明确保存的语言偏好；
2. 当前浏览器保存的本地选择；
3. 浏览器语言；
4. 安装级默认语言；
5. `en-US` 兜底。

未登录的 Setup/Login 页面使用浏览器语言；登录后使用用户偏好。切换语言不刷新业务数据、不改变资源 ID，也不修改 Project 或 Organization 数据。用户语言偏好接口尚未实现前，Web 可以只保存在浏览器本地；不能把它写入 Bearer Token。

## API 与 Web 的职责

API 返回稳定的机器错误码，例如：

```json
{
  "error": {
    "code": "terminal_target_unavailable",
    "message": "terminal target is not currently available",
    "request_id": "request-123"
  }
}
```

Web 使用 `error.code` 处理错误类型，并始终保留 Request ID。请求携带标准 `Accept-Language`，后端从 `zh-CN`、`en-US` 中选择安全 `message`，响应通过 `Content-Language` 明确实际语言；缺失、格式错误、过长或不支持的语言都回退到 `en-US`。例如中文请求会收到：

```json
{
  "error": {
    "code": "terminal_target_unavailable",
    "message": "终端目标当前不可用",
    "request_id": "request-123"
  }
}
```

`message` 方便人类直接阅读，但不是客户端分支契约。Web、CLI 和 SDK 必须按稳定的 `error.code` 判断行为，不能比较中英文句子。未知 code 只返回当前语言的通用安全提示，不回显底层错误。

HTTP 状态、error code、状态 enum、权限名和审计 action 永远不翻译。它们是协议数据；只在展示时映射成人类语言。

## 后端语言资源

后端语言文件统一放在一个目录：

```text
internal/platform/localization/
├── locales/
│   ├── en-US.json
│   └── zh-CN.json
├── catalog.go
├── http.go
└── locale.go
```

文件名使用标准 BCP 47 标签，所以简体中文是 `zh-CN`，不是 `zh-CH`。每个文件内部按 `api_errors`、未来的 `cli` 等命名空间组织；新增语言时必须补齐同一组 key。语言资源通过 Go `embed` 编入二进制，生产环境不依赖当前工作目录中的外部文件。

Service、Biz 和 Data 层返回类型化业务错误，不直接拼接面向客户的句子。HTTP 边界负责把业务错误映射为 code，再从语言目录生成安全 message。日志、Trace 和内部错误仍保留稳定技术信息，不能把敏感底层错误放入翻译参数。

## CLI 语言选择

正式客户 CLI 创建后使用同一组语言标签和回退规则，优先级为：

1. 命令行显式 `--locale`；
2. `OWNDOCK_LOCALE`；
3. `LC_ALL`；
4. `LC_MESSAGES`；
5. `LANG`；
6. `en-US`。

支持 `zh_CN.UTF-8` 这类常见系统值，并规范化为 `zh-CN`。CLI flag 名、配置键、JSON/YAML 字段、错误 code 和脚本输出格式不翻译；帮助说明、交互提示和给人阅读的结果可以翻译。显式指定不支持的语言时回退到 `en-US`，并应由正式 CLI 给出明确提示。

当前仓库尚未准入面向客户的管理 CLI。`owndock`、`owndock-agent` 和 `owndock-build-worker` 是常驻服务进程，其结构化运行日志不是 CLI 界面，暂不做机器翻译；语言解析能力已放在后端公共包中供正式 CLI 复用。

## 哪些内容不翻译

- 用户创建的 Organization、Project、Application、Environment 和资源名称；
- Git ref、Commit SHA、镜像地址、容器名称和 Secret alias；
- Build 工具产生的原始技术日志；
- API code、审计 action、指标 label 和 Trace attribute；
- 用户在终端中的输入输出。

Build 日志可以翻译 OwnDock 自己生成的阶段标签和解释文字，但不能机器翻译 Git、BuildKit 或客户构建脚本的输出，否则会影响搜索、复制和排障。

## 翻译资源规则

- Web 使用语义 key，例如 `terminal.session.targetUnavailable`；后端 API 错误使用稳定 error code 作为 `api_errors` key，不用整段中文或英文做 key；
- feature 模块拥有自己的 namespace，共享按钮和通用错误才进入 shared；
- `zh-CN` 与 `en-US` key 必须完全一致，测试和 CI 检查缺失 key、空值；公开 API 使用到的 error code 必须进入两份目录；
- 不通过字符串拼接组成句子，变量使用具名占位符；
- 复数、数字、相对时间和日期使用 `Intl`/ICU 语义，不手写语言规则；
- 所有时间在 API 中保持 UTC/RFC 3339，Web 按用户时区和 locale 展示，并提供精确时间；
- UI 为英文变长预留空间，不使用固定文本宽度；中文、英文都要做溢出和窄屏测试。

## 官网和客户文档

官网与开发文档使用独立语言页面和稳定 URL，例如 `/zh-CN/...`、`/en-US/...`。每个语言版本声明 `hreflang`，语言切换保持在同一主题；不存在对应翻译时明确回到该语言首页，不能静默显示混合语言页面。

产品术语表是两种语言的共同来源。Application、Release、Deployment、Runtime Target、Managed Host、Build、Artifact 和 Terminal Session 等领域名在 UI、官网、文档和支持材料中必须一致。代码标识和 API 字段保持英文，不因中文界面改变。

## 首版验收

- Setup、登录、导航、空状态、表单校验、错误页和核心 Git-to-Deploy 流程具有两种语言；
- 语言切换后当前路由和未提交的安全表单状态符合明确策略；
- API 未知错误码、翻译 key 缺失和资源加载失败有安全兜底；
- API 分别验证 `Accept-Language: zh-CN`、`en-US`、无效语言与缺失 header，并校验 `Content-Language`；
- 正式 CLI 创建时，分别验证显式参数、OwnDock 环境变量、POSIX locale 和脚本稳定输出；
- Playwright 分别运行 `zh-CN`、`en-US` 核心旅程；
- 截图检查英文文本扩展、中文换行、日期/数字和无障碍名称；
- 日志、审计、指标、URL 和缓存中不出现把 locale 当作高基数标签的实现。
