# FastjsonExpToolkit

Fastjson 探测 / PoC / WAF 绕过工具箱，提供 **Web UI** 与 **MCP（Agent）** 两种入口，引擎同源。

> 仅用于授权测试与本地靶场复现。密钥（如 `CEYE_TOKEN`）放在本地 `.env`，勿提交到 Git。

## 快速开始

```bash
# Python >= 3.10
pip install -e ".[dev]"

cd web && npm install && cd ..
```

一键启停 Web（不含 Docker 靶场；默认后端热更新）：

| 系统 | 启动 | 停止 |
|------|------|------|
| Windows | `scripts\start.bat` | `scripts\stop.bat` |
| Linux / macOS | `./scripts/start.sh` | `./scripts/stop.sh` |

| 服务 | 地址 |
|------|------|
| 前端 | http://127.0.0.1:3000（占用时提示手动指定） |
| 后端 API | http://127.0.0.1:8000（占用时提示手动指定；会写入 `web/.env.local` 供前端反代） |
| API 文档 | 同前端 `/api/docs`（经 Next 反代） |

日志：`.runtime/logs/`。关闭后端热更新：`scripts\start.ps1 -NoReload` 或 `BACKEND_RELOAD=0`。非交互环境可预设：`BACKEND_PORT=8001 FRONTEND_PORT=3001 ./scripts/start.sh`。

### CEYE DNSLog（可选）

识别 / 版本 DNS 确认依赖 CEYE。任选其一：

1. **Web** → `/settings`，填写 Token 与 Identifier（如 `hpdth2`），保存写入 `.env`
2. 手动：复制 `.env.example` 为 `.env` 后编辑

```env
CEYE_TOKEN=your_ceye_api_token
CEYE_DOMAIN=hpdth2.ceye.io
```

设置页可「测试连接」。MCP 工具自动读 `.env`，**不要**在工具参数里传 token。

---

## MCP（Agent 工具）

与 REST 同源，供 Cursor 等 MCP 客户端调用。

### 工具一览

| 工具 | 说明 |
|------|------|
| `detect_pipeline` | 识别 → 版本 → 期望类；根路径会尝试 `/api/health` 与常见反序列化点 |
| `deps_probe` | 依赖探测（`character` 自动降级 `class` MiscCodec；可选 `dns`） |
| `poc_catalog` | gadget / 回显引擎 / WAF 技巧目录 |
| `poc_run` | 生成或发送 PoC（`io_read_error` + `read_length` 可逐字节爆破） |
| `poc_script` | 取固定原脚本（LLM 按环境自行改）；不传参列目录 |
| `docs_list` | 漏洞文档标题与摘要 |
| `docs_get` | 按 slug 取 Markdown 正文 |

推荐工作流：`detect_pipeline` → `deps_probe` → `poc_catalog` / `poc_run`；脚本类用 `poc_script`；文档用 `docs_list` → `docs_get`。

注意：`target` 应为反序列化 POST 点（如 `/api/fastjson`）；SafeMode 为低置信启发式并与 AutoCloseable 交叉校验；本地 `18068` 为版本矩阵（瘦依赖），`18268` 为 gadget 靶场。

### 工具输入 / 输出示例

MCP 返回已对 Agent **精简**：去掉 `evidence` / `notes` / `raw` / 空字段等噪声；REST/Web 仍是完整结构。入参只需填有用的；默认值不必显式传 `null`。`ok: false` 时带 `error`。

#### `detect_pipeline`

```json
{ "target": "http://127.0.0.1:18268/api/fastjson" }
```

```json
{
  "ok": true,
  "effective_target": "http://127.0.0.1:18268/api/fastjson",
  "summary": "判定为 Fastjson；版本区间 <=1.2.68；存在期望类",
  "skipped": [],
  "next_actions": [
    "poc_run(family=…, expect_bypass=true, target='http://127.0.0.1:18268/api/fastjson')",
    "deps_probe(target='http://127.0.0.1:18268/api/fastjson')",
    "poc_catalog",
    "docs_list"
  ],
  "detect": {
    "is_fastjson": true,
    "confidence": 0.92,
    "primary_guess": "fastjson",
    "autotype_disabled_hint": true,
    "summary": "判定为 Fastjson"
  },
  "version": {
    "autotype_enabled": false,
    "version_range": "<=1.2.68",
    "version_detail": "1.2.48-1.2.68",
    "summary": "版本区间 <=1.2.68"
  },
  "expect": {
    "has_expect_class": true,
    "expect_not_map": true,
    "summary": "存在期望类"
  },
  "health": {
    "fastjson": "1.2.68",
    "autotype": false,
    "deps": { "commons_io": true }
  }
}
```

非 Fastjson：无 `version` / `expect`，`skipped` 含 `["version","expect"]`。可选：`include_dns_version`、`headers`、`proxy`、`base_body`。

#### `deps_probe`

```json
{
  "target": "http://127.0.0.1:18268/api/fastjson",
  "categories": ["commons-io", "spring"]
}
```

```json
{
  "ok": true,
  "result": {
    "method": "class",
    "scanned": 12,
    "present_count": 2,
    "absent_count": 10,
    "summary": "扫描 12 个类，发现 2 个依赖",
    "present": [
      {
        "clazz": "org.apache.commons.io.ByteOrderMark",
        "description": "commons-io（通用）",
        "category": "commons-io"
      }
    ],
    "notes": ["校准：已改用 Class MiscCodec"]
  }
}
```

默认 `method=character`（AutoType 关时降级 `class`）；无回显可 `method=dns`。只返回 `present`，不含全量 `results`。

#### `poc_catalog`

```json
{ "family": "1.2.68" }
```

```json
{
  "ok": true,
  "gadgets": {
    "1.2.68": [
      {
        "id": "io_read_error",
        "title": "commons-io 报错读文件/目录",
        "requires": ["commons-io", "jdk.nashorn.api.scripting.URLReader"],
        "input_fields": ["url", "read_length", "read_charset", "guess_byte", "bom_bytes"]
      }
    ]
  },
  "echo_engines": [{ "id": "auto", "title": "auto（按序探测）" }],
  "waf_techniques": [{ "id": "unicode", "title": "Unicode 编码" }],
  "expect_bypass_hint": {
    "1.2.68": "expect_bypass=true → wrap_currency=true"
  },
  "script_hint": "复杂逻辑改参用 poc_script；自动化爆破优先 poc_run(…)"
}
```

#### `poc_run`

仅生成：

```json
{
  "family": "1.2.68",
  "options": { "gadget": "io_read_error", "url": "file:///tmp/flag" }
}
```

```json
{
  "ok": true,
  "family": "1.2.68",
  "result": {
    "ok": true,
    "gadget": "io_read_error",
    "payload": "{\"abc\":{\"@type\":\"java.lang.AutoCloseable\",…}",
    "requires": ["commons-io", "jdk.nashorn.api.scripting.URLReader"],
    "summary": "已生成 … payload（未发送）"
  }
}
```

发送并爆破读：

```json
{
  "family": "1.2.68",
  "send": true,
  "target": "http://127.0.0.1:18268/api/fastjson",
  "options": {
    "gadget": "io_read_error",
    "url": "file:///tmp/flag",
    "read_length": 16,
    "read_charset": "mixed"
  }
}
```

```json
{
  "ok": true,
  "family": "1.2.68",
  "result": {
    "ok": true,
    "gadget": "io_read_error",
    "sent": true,
    "status_code": 200,
    "read_bytes": [70, 76, 65, 71],
    "read_content": "FLAG",
    "summary": "已读出 4 字节"
  }
}
```

`1.2.47` + 期望类绕过：`expect_bypass=true`，`options.gadget=jdbc_rowset`，`options.jndi_url=…`。WAF：`waf_techniques: ["unicode"]`。`cve-2026-16723` 始终执行，忽略 `send`。

#### `poc_script`

```json
{}
```

```json
{
  "ok": true,
  "scripts": [
    {
      "family": "1.2.68",
      "gadget": "io_read_error",
      "filename": "1.2.68_io_read_error.py",
      "title": "commons-io 报错读文件",
      "summary": "逐字节 BOM 爆破…请改 ERROR_MARKERS / TARGET / FILE_URL"
    }
  ],
  "hint": "传入 family 与 gadget 获取固定原脚本正文…"
}
```

```json
{ "family": "1.2.68", "gadget": "io_read_error" }
```

→ `script` 为完整 Python 原文（按环境自行改）。

#### `docs_list` / `docs_get`

```json
{}
```

```json
{
  "ok": true,
  "docs": [
    {
      "slug": "fastjson-detect",
      "title": "Fastjson 探测分析",
      "description": "识别 Fastjson、区分其他 JSON 库…",
      "order": 4
    }
  ],
  "hint": "使用 docs_get(slug=...) 获取正文"
}
```

```json
{ "slug": "fastjson-detect" }
```

→ `title` + `content`（Markdown 正文）。
### 方式一：stdio

```bash
pip install -e .
fjtoolkit mcp
```

Cursor `mcp.json`：

```json
{
  "mcpServers": {
    "fastjson-toolkit": {
      "command": "fjtoolkit",
      "args": ["mcp"]
    }
  }
}
```

### 方式二：HTTP（推荐在设置页启停）

1. 先启动 Web（见上）
2. 打开 `/settings` →「MCP HTTP」
3. 填写 Host / 端口 / 鉴权 Token，点「启动服务」
4. 「复制 Cursor 配置」粘贴到 `mcp.json`

默认地址：`http://127.0.0.1:8100/mcp`。

也可命令行：

```bash
fjtoolkit mcp --http --host 127.0.0.1 --port 8100 --token your-secret
```

配置写入 `.env`：

```env
MCP_HTTP_HOST=127.0.0.1
MCP_HTTP_PORT=8100
MCP_HTTP_TOKEN=your-secret
```

客户端鉴权：`Authorization: Bearer <token>` 或 `X-MCP-Token`。

Cursor `mcp.json`（HTTP）示例：

```json
{
  "mcpServers": {
    "fastjson-toolkit-http": {
      "url": "http://127.0.0.1:8100/mcp",
      "headers": {
        "Authorization": "Bearer your-secret"
      }
    }
  }
}
```

文档目录默认 `web/content/docs/`，可用环境变量 `FASTJSON_DOCS_DIR` 覆盖。

---

## Web 页面

技术栈：Next.js App Router + Tailwind CSS v4 + [shadcn/ui](https://ui.shadcn.com/)。顶栏入口如下。

| 路径 | 功能 |
|------|------|
| `/` | 首页：各功能入口与 API 文档链接 |
| `/detect` | Fastjson 探测 |
| `/poc` | 各版本证明 PoC |
| `/waf` | WAF 绕过变换（本地，不发包） |
| `/lab` | Docker 靶场启停 |
| `/docs` | 漏洞分析文档 |
| `/settings` | CEYE + MCP HTTP |

`/version`、`/expect`、`/deps` 已重定向到 `/detect`。

### `/detect` — 探测

- **识别 → 版本 → 期望类**：可按开关组合按序执行；识别非 Fastjson 时自动跳过后续两步
- **依赖探测**：同页独立阶段，可单独发起；默认 Character 报错回显，可选 DNS Locale
- 共用目标 URL / Headers / 超时等；期望类可填贴近业务的 `base_body`
- 结果按 Tab 展示得分、证据、建议与原始 JSON

### `/poc` — 证明 PoC

四个 Tab，均可「仅生成」或「POST 到目标」，并支持叠加 WAF 变换：

| Tab | 说明 |
|-----|------|
| ≤1.2.47 缓存绕过 | JNDI / BCEL / C3P0 / MyBatis / H2 等；可选回显、内存马、getter 触发 |
| ≤1.2.68 AutoCloseable | 写/截断文件、commons-io、读文件、JDBC 等 |
| ≤1.2.80 Exception | 多步缓存链（需共享 ParserConfig） |
| 1.2.83 CVE-2026-16723 | jar:http / fd-cache；回显或内存马 |

### `/waf` — WAF 绕过

对已有 Fastjson JSON payload 做本地变换：

- 模式：`variants`（每种变换各出一份）/ `stack`（顺序叠加）
- 变换：unicode / hex / `\u+`、多逗号、key `_`/`-`、填充、URL 编码等

PoC 页各生成 Tab 内也可勾选同一套技巧。

### `/lab` — 靶场

识别本机 Docker / Compose，按需启动 `lab/` 下指纹、版本、gadget、CVE 等复现环境；可改主机端口。靶场细节见 [`lab/README.md`](lab/README.md)。

### `/docs` — 文档

渲染 `web/content/docs/` 下的 Markdown（探测 / 版本 / 依赖等分析笔记）。与 MCP `docs_*` 同源。

### `/settings` — 设置

- **CEYE**：Token、Identifier；测试连接；写入 `.env`
- **MCP HTTP**：Host / 端口 / Token；启停服务；复制 Cursor 配置

### API 文档

顶栏「API 文档」或首页入口：

| 路径 | 说明 |
|------|------|
| `/api/docs` | Scalar（推荐） |
| `/api/swagger` | Swagger UI |
| `/api/redoc` | ReDoc |
