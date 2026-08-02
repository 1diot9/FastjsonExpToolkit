# FastjsonExpToolkit

Fastjson 识别 / 版本探测 / PoC 工具箱。

当前进度：**Phase 2 — 识别 + 版本探测**（Web + API + Docker 靶场）。后续阶段见 [`docs/design.md`](docs/design.md)。

> 仅用于授权测试与本地靶场复现。

## 功能概览

| 能力 | 状态 | 说明 |
|------|------|------|
| Fastjson 识别 | ✅ | 报错 / 解析特征 / `$ref` / DNS·CEYE / 与其他 JSON 库区分 |
| Fastjson 版本探测 | ✅ | AutoType / SafeMode / AutoCloseable 回显 / 不出网二分 / DNSLog |
| 依赖 / classpath 探测 | ✅ | Character 报错回显（推荐）/ DNS Locale（版本敏感） |
| Web 识别页 | ✅ | `/detect`，对接真实 API |
| Web 版本页 | ✅ | `/version`，对接 `/api/version` |
| Web 依赖页 | ✅ | `/deps`，对接 `/api/deps` |
| Web 设置页 | ✅ | `/settings`，配置 CEYE Token 与 Identifier |
| Docker 靶场 | ✅ | 多解析器对照（Fastjson / Jackson / Gson / Hutool / org.json） |
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
| 版本页 | http://127.0.0.1:3000/version |
| 依赖页 | http://127.0.0.1:3000/deps |
| 设置页 | http://127.0.0.1:3000/settings |
| 后端 API | http://127.0.0.1:8000 |
| API 文档（Scalar） | http://127.0.0.1:8000/api/docs 或经前端代理 `/api/docs` |
| Swagger UI | http://127.0.0.1:8000/api/swagger |
| ReDoc | http://127.0.0.1:8000/api/redoc |
| OpenAPI JSON | http://127.0.0.1:8000/api/openapi.json |

日志目录：`.runtime/logs/`。

手动启动：

```bash
# 默认 --reload；生产可去掉 --reload
python -m uvicorn fastjson_toolkit.api.app:app --host 127.0.0.1 --port 8000 --reload
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

验证：在设置页点「测试连接」，或调用 `POST /api/settings/ceye-test`。

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

指纹靶场端口：`18080`

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

版本矩阵（`lab/fastjson-version-lab`，`docker compose up -d fj-1-2-30 ...`）：

| 端口 | Fastjson |
|------|----------|
| `18030` | 1.2.30 |
| `18047` | 1.2.47 |
| `18068` | 1.2.68 |
| `18082` | 1.2.80 |

每个版本均提供 `POST /api/fastjson` 与 `POST /api/fastjson/autotype`。

## HTTP API

交互式文档（[Scalar](https://github.com/scalar/scalar) / Swagger / ReDoc）见上表；也可在 Web 顶栏点「API 文档」。

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/health` | 健康检查与 CEYE 配置状态 |
| `GET` | `/api/probes` | 探针列表 |
| `POST` | `/api/detect` | Fastjson 识别 |
| `GET` | `/api/version/probes` | 版本探针列表 |
| `POST` | `/api/version` | Fastjson 版本探测 |
| `GET` | `/api/deps/catalog` | 内置依赖探测类目录 |
| `POST` | `/api/deps` | 依赖 / classpath 探测 |
| `GET` | `/api/settings` | 读取 CEYE 设置（Token 脱敏） |
| `PUT` | `/api/settings` | 保存 CEYE Token / Identifier → `.env` |
| `POST` | `/api/settings/ceye-test` | 测试 CEYE API |

`POST /api/detect` 返回结构化 `DetectResult`：`is_fastjson` / `confidence` / `primary_guess` / `scores` / `evidence` / `dns_confirmed` / `next_actions` 等。

`POST /api/version` 返回 `VersionResult`：`version_range` / `reported_version` / `autotype_enabled` / `safemode_enabled` / `is_1_2_83_hint` / `evidence` / `dns_hits` 等。

`POST /api/deps` 返回 `DepsResult`：`present` / `results` / `method`（`character`|`dns`）/ `notes` 等。推荐 `method=character`（报错回显）；DNS Locale 链版本敏感，本地常无记录。

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

## 依赖探测原理（摘要）

1. **Character 报错（推荐）**：畸形 `@type:java.lang.Character` + `java.lang.Class`；类存在时响应含 `can not cast to char`，不存在常见 `No message available`
2. **DNS Locale（实验）**：`Locale` 加载目标类成功后才构造完整对象并触发 `Inet4Address` DNS；对版本 / autoType 极敏感，本地靶场经常无记录

CLI：`fjtoolkit deps http://127.0.0.1:18080/api/fastjson`

## 版本探测原理（摘要）

1. **AutoType**：`java.lang.Class` vs `Random.String` 报错组合判断是否开启  
2. **SafeMode**：`{"zero":{"@type":"java.lang.String"""}}}` 报错≈开启，不报错≈关闭  
3. **AutoCloseable 回显**：残缺 `{"@type":"java.lang.AutoCloseable"`，提取 `fastjson-version`（注意 1.2.76+ 可能写死）  
4. **1.2.83**：`Test.TestException` 仅在 1.2.83 通常不报错  
5. **不出网二分**：Exception / AutoCloseable / Class+Jdbc / Jdbc 四探针收敛区间  
6. **DNSLog**：<=1.2.47 / <=1.2.68 / 单 DNS≈1.2.80 / 双 DNS≈1.2.83

## 目录结构

```
├── scripts/start.* / stop.*  # 一键启停 Web（默认后端 --reload，不含靶场）
├── docs/design.md            # 设计与阶段规划
├── src/fastjson_toolkit/     # Python 后端（detect / version / api / dnslog）
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
