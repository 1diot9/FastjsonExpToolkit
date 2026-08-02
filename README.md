# FastjsonExpToolkit

Fastjson 识别 / 版本探测 / PoC 工具箱。

当前进度：**Phase 1 — Fastjson 识别**（Web + CLI + Docker 靶场）。后续阶段见 [`docs/design.md`](docs/design.md)。

> 仅用于授权测试与本地靶场复现。

## 功能概览

| 能力 | 状态 | 说明 |
|------|------|------|
| Fastjson 识别 | ✅ | 报错 / 解析特征 / `$ref` / DNS·CEYE / 与其他 JSON 库区分 |
| Web 识别页 | ✅ | `/detect`，对接真实 API |
| Web 设置页 | ✅ | `/settings`，配置 CEYE Token 与 Identifier |
| CLI | ✅ | `fjtoolkit detect` / `serve` / `ceye-check` / `probes` |
| Docker 靶场 | ✅ | 多解析器对照（Fastjson / Jackson / Gson / Hutool / org.json） |
| 版本识别 | ⏳ | 规划中 |
| 各版本 PoC / 自定义字节码 | ⏳ | 规划中 |
| 回显 / 内存马 | ⏳ | 规划中（内存马参考 [MemShellParty](https://github.com/ReaJason/MemShellParty)） |

## 快速开始（Web）

### 1. 安装依赖

```bash
# Python 后端（需 Python >= 3.10）
pip install -e ".[dev]"

# 前端
cd web
npm install
cd ..
```

### 2. 一键启停（不含 Docker 靶场）

默认开启**热更新**：

- 后端：`uvicorn --reload`，监听 `src/`（改 Python 代码自动重启）
- 前端：`next dev` HMR（改 `web/` 自动刷新）

关闭后端热更新：`scripts\start.ps1 -NoReload`，或环境变量 `BACKEND_RELOAD=0`。

**Windows**

```bat
scripts\start.bat
scripts\stop.bat
```

也可：`powershell -File scripts\start.ps1` / `scripts\stop.ps1`。

**Linux / macOS**

```bash
chmod +x scripts/start.sh scripts/stop.sh
./scripts/start.sh
./scripts/stop.sh
```

启动后：

| 服务 | 地址 |
|------|------|
| 前端 | http://127.0.0.1:3000 |
| 识别页 | http://127.0.0.1:3000/detect |
| 设置页 | http://127.0.0.1:3000/settings |
| 后端 API | http://127.0.0.1:8000 |
| API 文档（Scalar） | http://127.0.0.1:8000/api/docs 或经前端代理 `/api/docs` |
| Swagger UI | http://127.0.0.1:8000/api/swagger |
| ReDoc | http://127.0.0.1:8000/api/redoc |
| OpenAPI JSON | http://127.0.0.1:8000/api/openapi.json |

日志目录：`.runtime/logs/`。

手动启动：

```bash
# 默认 --reload；生产可加 --no-reload
fjtoolkit serve --host 127.0.0.1 --port 8000
cd web && npm run dev
```

### 3. 配置 CEYE DNSLog

两种方式任选其一：

1. **Web 设置页**：打开 `/settings`，填写 Token 与 Identifier 子域名（如 `hpdth2`），保存后写入项目 `.env`。
2. **手动 `.env`**：复制模板后编辑：

```bash
cp .env.example .env
```

```env
CEYE_TOKEN=your_ceye_api_token
CEYE_DOMAIN=hpdth2.ceye.io
```

验证：

```bash
fjtoolkit ceye-check --trigger
```

设置页也可点「测试连接」。

### 4. （可选）启动 Docker 靶场

```bash
cd lab
docker compose up --build -d
curl http://127.0.0.1:18080/api/health
```

停止：

```bash
cd lab
docker compose down
```

靶场端口：`18080`

| 端点 | 解析器 |
|------|--------|
| `POST /api/fastjson` | Fastjson 1.2.83（默认安全模式） |
| `POST /api/fastjson/autotype` | Fastjson（开启 autoType，便于 DNS 验证） |
| `POST /api/fastjson/person` | Fastjson 强类型 Person |
| `POST /api/jackson` | Jackson |
| `POST /api/jackson/person` | Jackson 强类型 Person |
| `POST /api/gson` | Gson |
| `POST /api/orgjson` | org.json |
| `POST /api/hutool` | Hutool JSON |

## CLI 用法

```bash
# 识别（默认启用 CEYE；autoType 关闭时通常无 DNS 记录）
fjtoolkit detect http://127.0.0.1:18080/api/fastjson --json
fjtoolkit detect http://127.0.0.1:18080/api/fastjson/autotype --json
fjtoolkit detect http://127.0.0.1:18080/api/jackson --json --no-dns

# 列出探针
fjtoolkit probes --dnslog xxx.hpdth2.ceye.io

# 启动 API（默认热重载；关闭：--no-reload）
fjtoolkit serve --host 127.0.0.1 --port 8000
```

常用选项：`--no-dns` / `--no-ceye` / `--ceye-token` / `--ceye-domain` / `--ceye-wait` / `--timeout`。

退出码：判定为 Fastjson 时为 `0`，否则 `1`。

## HTTP API

交互式文档（[Scalar](https://github.com/scalar/scalar) / Swagger / ReDoc）见上表；也可在 Web 顶栏点「API 文档」。

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/health` | 健康检查与 CEYE 配置状态 |
| `GET` | `/api/probes` | 探针列表 |
| `POST` | `/api/detect` | Fastjson 识别 |
| `GET` | `/api/settings` | 读取 CEYE 设置（Token 脱敏） |
| `PUT` | `/api/settings` | 保存 CEYE Token / Identifier → `.env` |
| `POST` | `/api/settings/ceye-test` | 测试 CEYE API |

`POST /api/detect` 返回结构化 `DetectResult`：`is_fastjson` / `confidence` / `primary_guess` / `scores` / `evidence` / `dns_confirmed` / `next_actions` 等，便于 Web 与 Agent 消费。

## Web 前端

目录：`web/`。技术栈：**Next.js App Router + Tailwind CSS v4 + [shadcn/ui](https://ui.shadcn.com/)（base-nova）**。

约定见 [`AGENTS.md`](AGENTS.md)：所有 UI 只用 shadcn 组件，图标用 `lucide-react`。

若本机访问 `ui.shadcn.com` 超时，在当前 shell 设置代理后再执行 `npx shadcn@latest add ...`：

```powershell
$env:HTTP_PROXY='http://127.0.0.1:10808'
$env:HTTPS_PROXY='http://127.0.0.1:10808'
$env:ALL_PROXY='http://127.0.0.1:10808'
$env:NODE_USE_ENV_PROXY='1'
```

## 识别原理（摘要）

1. **报错特征**：残缺 JSON、`@type` / autoType 相关异常文案  
2. **解析行为**：`new` / hex / 注释 / `Set` / `$ref` 等 Fastjson 特有或强相关语法  
3. **DNS / 时延**：`Inet4Address` 等；可结合 CEYE 轮询确认出网  
4. **差异探针**：与 Jackson / Gson / org.json / Hutool 行为对照，避免误报  

判定策略：依赖强特征命中，差异探针不单独定论。靶场验证结论：Fastjson → `is_fastjson=true`；Jackson / Gson / Hutool / org.json → `false`。

## 目录结构

```
├── scripts/start.* / stop.*  # 一键启停 Web（默认后端 --reload，不含靶场）
├── docs/design.md            # 设计与阶段规划
├── src/fastjson_toolkit/     # Python 后端（detect / api / cli / dnslog）
├── web/                      # Next.js + shadcn 前端
├── lab/                      # Docker 指纹靶场
├── tests/                    # 单元测试
├── AGENTS.md                 # Agent / shadcn 约定
└── .env.example              # CEYE 等配置模板
```

## 开发与测试

```bash
pip install -e ".[dev]"
pytest -q
```

## 许可与安全

本工具面向安全研究与授权渗透测试。请勿对未授权目标使用。密钥（如 `CEYE_TOKEN`）只放在本地 `.env`，勿提交到 Git。
