# FastjsonExpToolkit

Fastjson 探测 / PoC / WAF 绕过工具箱，提供 **Web UI**、**MCP（Agent）** 与可迁移的 **`tools/` CLI** 入口，引擎同源。

> 仅用于授权测试与本地靶场复现。密钥（如 `CEYE_TOKEN`）放在本地 `.env`，勿提交到 Git。

## 快速开始

需要 **Python >= 3.10**。建议先创建并激活虚拟环境，再安装依赖：

```bash
# 1. 创建虚拟环境（仓库根目录）
python3 -m venv .venv

# 2. 激活
# Linux / macOS:
source .venv/bin/activate
# Windows (PowerShell):
# .\.venv\Scripts\Activate.ps1
# Windows (cmd):
# .venv\Scripts\activate.bat

# 3. 安装本包（含开发依赖）
pip install -e ".[dev]"

# 4. 前端依赖
cd web && npm install && cd ..
```

退出虚拟环境：`deactivate`。`.venv/` 已在 `.gitignore` 中，勿提交。

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

设置页可「测试连接」。MCP / `tools/` CLI 自动读 `.env`，**不要**在工具参数里传 token。

---

## tools/ CLI（可迁移，对齐 MCP）

与 MCP **同名同语义** 的轻量入口，便于拷到其他项目作基础工具。不代发 exploit。单一入口 + 子命令。

### 初始化（必做）

CLI **不依赖** `mcp` / FastAPI；最少只需 `httpx` + `pydantic`。本仓库内建议与「快速开始」共用同一 venv：

```bash
# 仓库根目录；已激活 .venv（见上文「快速开始」）
pip install -e .
# 或仅最小依赖（不装本包时）：
# pip install "httpx>=0.27" "pydantic>=2.7"
```

校验（须与运行 `fjtool` 的是**同一个** Python）：

```bash
python tools/fjtool.py -h
python tools/fjtool.py docs_list
# 或：./tools/fjtool.sh docs_list
```

若 `ModuleNotFoundError: No module named 'fastjson_toolkit'` / `httpx` / `pydantic`：未激活 venv、未 `pip install`，或用了系统 `python3` 而依赖装在 `.venv`。处理：激活 `.venv` 后重装，或显式：

```bash
.venv/bin/python tools/fjtool.py -h          # Linux / macOS
# .venv\Scripts\python.exe tools\fjtool.py -h  # Windows
```

可选：复制 `.env.example` 为 `.env` 并填写 `CEYE_TOKEN` / `CEYE_DOMAIN`（探测 DNS 时自动读；**不要**在 CLI 参数里传 token）。

迁到其他项目、目录布局与精简依赖见 [`tools/README.md`](tools/README.md)。

### 用法示例

```bash
python tools/fjtool.py -h
python tools/fjtool.py docs_list
./tools/fjtool.sh poc_catalog --family 1.2.68
python tools/fjtool.py poc_get 1.2.68 mysql_jdbc --options '{"ldap_url":"ldap://..."}'
```

Handler 在 `tools/_lib/`，MCP 传输层复用同一套。

---

## MCP（Agent 工具）

### 初始化（必做）

MCP 依赖官方 Python SDK **1.x**（`mcp>=1.9.0,<2`，含 `FastMCP`），随本包装入。`pip install mcp` 默认会装到 **2.x**（`FastMCP` 已改名为 `MCPServer`），本仓库尚未迁移，故 `pyproject.toml` 上限钉在 `<2`。请先按「快速开始」创建并**激活**虚拟环境，再安装：

```bash
# 仓库根目录；已激活 .venv
pip install -e .
# 或含开发依赖：pip install -e ".[dev]"
```

校验当前解释器能导入 FastMCP（与即将运行 `fjtoolkit` 的是**同一个** Python）：

```bash
python -c "from mcp.server.fastmcp import FastMCP; print('ok')"
# Windows 也可用: py -c "from mcp.server.fastmcp import FastMCP; print('ok')"
which fjtoolkit   # Linux / macOS：应指向 .venv
where fjtoolkit   # Windows：应指向 .venv\Scripts
pip show mcp      # Version 应为 1.x（例如 1.29.x），不要是 2.x
```

若出现 `ModuleNotFoundError: No module named 'mcp.server.fastmcp'`：通常是未 `pip install -e .`、跑在系统 Python / 错误 venv，或装到了 **mcp 2.x**。处理：

```bash
pip uninstall mcp -y
pip install "mcp>=1.9.0,<2"
# 确认: pip show mcp → Version 1.x，Summary 含 Model Context Protocol
python -c "from mcp.server.fastmcp import FastMCP; print('ok')"
```

stdio 接入 Cursor 时，`mcp.json` 的 `command` 建议写 **venv 内 `fjtoolkit` 的绝对路径**（或同样带 `"env"` / 先激活再启动），避免 IDE 用到未装依赖的系统 Python。

### 方式一：stdio

```bash
fjtoolkit mcp
```

Cursor `mcp.json`（把 `command` 换成本机 venv 路径）：

```json
{
  "mcpServers": {
    "fastjson-toolkit": {
      "command": "/absolute/path/to/.venv/bin/fjtoolkit",
      "args": ["mcp"]
    }
  }
}
```

Windows 示例：`"command": "C:\\Users\\Admin\\Desktop\\FastjsonExpToolkit-main\\.venv\\Scripts\\fjtoolkit.exe"`。

### 方式二：HTTP（推荐在设置页启停）

1. 先完成上文「初始化」，再启动 Web（见「快速开始」）
2. 打开 `/settings` →「MCP HTTP」
3. 填写 Host / 端口 / 鉴权 Token，点「启动服务」
4. 「复制 Cursor 配置」粘贴到 `mcp.json`

默认地址：`http://127.0.0.1:8100/mcp`。

也可命令行（同一已安装依赖的 venv）：

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

与 REST 同源，供 Cursor 等 MCP 客户端调用。

**定位**：版本 / 依赖探测 + PoC 知识库检索 + 本地 WAF 混淆。MCP **不代发** exploit（已移除 `poc_run`）；发包由 LLM / 其它工具完成。

### 工具一览

| 工具 | 说明 |
|------|------|
| `detect_pipeline` | 识别 → 版本 → 期望类（精简决策字段） |
| `deps_probe` | 依赖探测（默认全量；`character` 自动降级 `class`） |
| `probe_catalog` | 探测探针**目录**（默认不含 payload） |
| `probe_get` | 取单条探测探针**完整 payload** |
| `poc_catalog` | 按版本列 gadget（id / title / requires / jdk / doc） |
| `poc_meta` | 某 gadget 的参数元数据（`flag` / `required` / `arg_type` / `help`） |
| `poc_get` | 成功时**直接返回** JSON payload 字符串（多步为数组） |
| `poc_script` | 固定原脚本正文；不传参列目录 |
| `waf_catalog` | WAF 技巧 id / title |
| `waf_apply` | 成功时**直接返回**混淆后的 payload 字符串（variants 为数组） |
| `docs_list` | 文档一级目录（仅 `slug` / `title`） |
| `docs_get` | `顶级 slug`=章节目录；`顶级/章节`=**单段** Markdown |

职责分离：目录 ≠ 正文。完整 payload → `poc_get` / `probe_get`；参数说明 → `poc_meta`；文档两级读取用 `docs_list` + `docs_get`；脚本 → `poc_script`。

推荐工作流：

```
detect_pipeline → deps_probe
  → [探测不准] probe_catalog → probe_get；docs_list → docs_get(fastjson-detect) → docs_get(fastjson-detect/…)
  → poc_catalog(family) → poc_meta(family, gadget) → poc_get(family, gadget, options)
  → [需要时] docs_get(章节) / poc_script / waf_apply → LLM 自行 POST
```

注意：`target` 应为反序列化 POST 点（如 `/api/fastjson`）；SafeMode 为低置信启发式并与 AutoCloseable 交叉校验；本地 `18068` 为版本矩阵（瘦依赖），`18268` 为 gadget 靶场。

### 工具输入 / 输出示例

MCP 返回刻意精简：去掉 `evidence` / `notes` / `raw` / 长描述；目录与正文分工具。`ok: false` 时带 `error`。

#### `detect_pipeline`

```json
{ "target": "http://127.0.0.1:18268/api/fastjson" }
```

```json
{
  "ok": true,
  "effective_target": "http://127.0.0.1:18268/api/fastjson",
  "detect": { "is_fastjson": true, "confidence": 0.92 },
  "version": {
    "autotype_enabled": false,
    "version_range": "<=1.2.68",
    "version_detail": "1.2.48-1.2.68"
  },
  "expect": { "has_expect_class": true },
  "next": [
    "poc_get(..., expect_bypass=true)",
    "deps_probe(target='http://127.0.0.1:18268/api/fastjson')",
    "poc_catalog"
  ]
}
```

#### `deps_probe`

```json
{ "target": "http://127.0.0.1:18268/api/fastjson" }
```

```json
{
  "ok": true,
  "result": {
    "method": "class",
    "present_count": 2,
    "present": [
      { "clazz": "org.apache.commons.io.ByteOrderMark", "category": "commons-io" }
    ]
  },
  "next": ["poc_catalog"]
}
```

#### `probe_catalog` / `probe_get`

```json
{ "kind": "detect" }
```

→ 探针 id / category / description（默认无 `payload`）。`include_payload=true` 可内嵌；推荐：

```json
{ "kind": "detect", "probe_id": "…" }
```

→ `probe_get` 返回完整 `payload`。`kind=deps` 时 `probe_catalog` 返回 `templates`。

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
        "jdk": "8–14（含 Nashorn）",
        "doc": "fastjson-1.2.68",
        "script": true
      }
    ]
  }
}
```

#### `poc_meta`

```json
{ "family": "1.2.68", "gadget": "mysql_jdbc" }
```

```json
{
  "ok": true,
  "family": "1.2.68",
  "gadget": "mysql_jdbc",
  "args": [
    {
      "flag": "host",
      "required": false,
      "arg_type": "str",
      "help": "MySQL/PG host",
      "default": null
    },
    {
      "flag": "outbound",
      "required": false,
      "arg_type": "bool",
      "help": "mysql_jdbc：true=出网连恶意 MySQL；false=NamedPipe 不出网",
      "default": true
    }
  ],
  "tool_args": [
    {
      "flag": "expect_bypass",
      "required": false,
      "arg_type": "bool",
      "help": "poc_get 顶层参数…",
      "default": false
    }
  ],
  "note": "args[].flag 即 poc_get.options 键名；tool_args 为 poc_get 顶层参数"
}
```

#### `poc_get`

```json
{
  "family": "1.2.68",
  "gadget": "io_read_error",
  "options": { "url": "file:///tmp/flag", "guess_byte": 70 }
}
```

成功时**直接返回** payload 字符串（不再包 `ok` / `family`）：

```json
"{\"abc\":{\"@type\":\"java.lang.AutoCloseable\",…}"
```

有期望类：`expect_bypass=true`。多步链（如部分 1.2.80）返回字符串数组。失败才是 `{ "ok": false, "error": "…" }`。参数先 `poc_meta`；文档 / 脚本请分别 `docs_get` / `poc_script`。

#### `poc_script`

```json
{ "family": "1.2.68", "gadget": "io_read_error" }
```

→ `{ "ok": true, "filename": "…", "script": "…" }`。不传参仅列目录。

#### `waf_catalog` / `waf_apply`

`waf_catalog`：`[{ "id", "title" }]`，详解 `docs_get(slug="waf-bypass/1-unicode-hex-编码")`。

```json
{
  "payload": "{\"@type\":\"java.lang.String\",\"val\":\"a\"}",
  "techniques": ["unicode", "multi_comma"],
  "mode": "stack"
}
```

→ 直接返回混淆后的 JSON 字符串。`mode=variants` 时返回字符串数组。

#### `docs_list` / `docs_get`

`docs_list` 第一步只返回顶级文档：

```json
{
  "ok": true,
  "docs": [
    { "slug": "fastjson-1.2.68", "title": "≤1.2.68 利用技巧" },
    { "slug": "fastjson-detect", "title": "Fastjson 探测分析" }
  ]
}
```

第二步 `docs_get(顶级 slug)` 返回该文档的章节目录（不返回正文）：

```json
{ "slug": "fastjson-1.2.68" }
```

```json
{
  "ok": true,
  "slug": "fastjson-1.2.68",
  "title": "≤1.2.68 利用技巧",
  "sections": [
    { "slug": "fastjson-1.2.68/13-mysqljdbc", "title": "13. MysqlJdbc", "has_payload": true },
    { "slug": "fastjson-1.2.68/13-1-出网", "title": "13.1 出网", "has_payload": true,
      "parent": "fastjson-1.2.68/13-mysqljdbc" }
  ]
}
```

第三步 `docs_get(顶级/章节)` 才返回章节正文：

```json
{ "slug": "fastjson-1.2.68/13-1-出网" }
```

→ `{ "ok": true, "slug": "…", "title": "13.1 出网", "content": "…" }`（**仅该段**）。

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
| CVE-2026-16723（1.2.68–1.2.83） | jar:http / fd-cache；回显或内存马；靶场用 1.2.83 |

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
