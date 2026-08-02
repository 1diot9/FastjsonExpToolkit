# FastjsonExpToolkit 设计文档

## 1. 目标

构建 Fastjson PoC 工具，覆盖：

1. **Fastjson 识别**（与 Jackson / Gson / org.json / Hutool 区分）
2. **Fastjson 版本识别**
3. **各版本 PoC**（支持加载自定义字节码）
4. **回显技术**
5. **内存马注入**（参考 [MemShellParty](https://github.com/ReaJason/MemShellParty)，本地路径 `D:\BaiduSyncdisk\CTF_tools\JavaTools\memShell\MemShellParty`）

**交付形态：Web 界面**。前端必须使用 **shadcn** 组件（现有 `web/` 为 Next.js + shadcn）。

---

## 2. 总体架构（规划）

```
Web (Next.js + shadcn)
  识别 / 版本 / 期望类 / 依赖 / PoC / WAF / 设置
        │ HTTP JSON API
        ▼
Backend (Python FastAPI)
  detect / version / expect / deps / poc / waf / CEYE
        │                │
        ▼                ▼
  目标 / Docker 靶场   MemShellParty / 字节码
```

- **前端**：只通过后端 API 操作；UI 一律基于 shadcn（Button / Card / Tabs / Table / Input / Select 等）。
- **后端**：编排探测与 PoC；结构化 JSON 输出，便于 Web 与后续扩展。
- **内存马 / 字节码**：对接或封装 MemShellParty 的生成能力，再由 Fastjson gadget 链投递。

---

## 3. 当前进度

### 3.1 已完成

| 项 | 说明 |
|----|------|
| 识别引擎 | `src/fastjson_toolkit/detect/`：报错、解析特征、`$ref`、与其他库差异探针 |
| 版本引擎 | `src/fastjson_toolkit/version/`：AutoType / SafeMode / AutoCloseable 回显 / 1.2.83 / 不出网二分 / DNS |
| 依赖引擎 | `src/fastjson_toolkit/deps/`：Character 报错 classpath 探测 + DNS Locale（实验性） |
| 期望类引擎 | `src/fastjson_toolkit/expect/`：Feature `@type` + 空键语法，判断是否绑定期望类 |
| 判定策略 | 仅强特征可判定 Fastjson；差异探针不单独定论，避免 Gson/Hutool 误报 |
| CEYE DNSLog | `hpdth2.ceye.io` + API 轮询确认出网（`.env` 配置 token） |
| WAF 绕过 | `src/fastjson_toolkit/waf/`：unicode/hex/`\u+`、多逗号、key `_`/`-`、填充、URL 编码；可叠到 PoC 生成 |
| Getter 触发 | `src/fastjson_toolkit/poc/getter.py`：`ref` / `json_key` / `currency` / `currency_json_key`；业务点有期望类时套 Currency |
| ≤1.2.47 PoC | `poc/v1_2_47/`：Class 缓存绕过（JdbcRowSet / BCEL×4 / C3P0 / MyBatis / H2） |
| ≤1.2.68 PoC | `poc/v1_2_68/`：AutoCloseable expectClass（JDK 写/截断、commons-io、MySQL/PG） |
| ≤1.2.80 PoC | `poc/v1_2_80/`：Exception 反序列化器缓存（jackson / commons-io / PG·MySQL / groovy / aspectj / jython） |
| CVE-2026-16723 | `poc/cve_2026_16723/`：jar:http / fd-cache / 回显 / 可选 MemShellParty |
| Docker 靶场 | 指纹对照、版本矩阵、各版本 gadget 依赖靶场、Undertow 1.2.83 |
| HTTP 性能 | 复用 `httpx.Client`，本地 detect ~1s 级 |
| Web | `/detect` `/version` `/expect` `/deps` `/poc` `/waf` `/settings` |

### 3.2 靶场验证结论

- Fastjson → `is_fastjson=true`
- Jackson / Gson / Hutool / org.json → `is_fastjson=false`
- autoType 开启端点可走 CEYE DNS 确认
- 版本探测：本地靶场 Fastjson 1.2.83 可由 offline + 1.2.83 探针收敛
- 证明 PoC：`scripts/lab_test_1247_gadgets.py` / `1268` / `1280` 可对专用依赖靶场落盘验证

### 3.3 Web 前后端

- 后端：FastAPI（`fjtoolkit serve` / `uvicorn`，默认 `http://127.0.0.1:8000`）
  - `GET /api/health`
  - `GET /api/probes` / `POST /api/detect`
  - `GET /api/version/probes` / `POST /api/version`
  - `GET /api/expect/probes` / `POST /api/expect`
  - `GET /api/deps/catalog` / `POST /api/deps`
  - `GET /api/poc/1.2.47/gadgets` / `POST /api/poc/1.2.47`
  - `GET /api/poc/1.2.68/gadgets` / `POST /api/poc/1.2.68`
  - `GET /api/poc/1.2.80/gadgets` / `POST /api/poc/1.2.80`
  - `POST /api/poc/cve-2026-16723`
  - `GET /api/waf/techniques` / `POST /api/waf`
  - `GET/PUT /api/settings`（CEYE Token / Identifier，写入 `.env`）
  - `POST /api/settings/ceye-test`
  - API 文档：`/api/docs`（Scalar）、`/api/swagger`、`/api/redoc`、`/api/openapi.json`
- CLI：`detect` / `deps` / `expect` / `poc-1247` / `poc-1268` / `poc-1280` / `poc-16723` / `waf` / `serve` 等
- 前端：Next.js + shadcn（`web/`，开发时 rewrite 代理 `/api/*` → 后端）
- 识别 / 版本 / 期望类 / 依赖 / PoC / WAF 页已对接真实 API
- PoC 页 Tab：≤1.2.47 / ≤1.2.68 / ≤1.2.80 / CVE-2026-16723；可勾选 WAF 变换叠加
- 设置页可配置 CEYE Token 与 Identifier 子域名

### 3.4 Docker 靶场一览

| 靶场 | 端口 | 用途 |
|------|------|------|
| `lab/json-fingerprint-lab`（compose 根） | `18080` | 多解析器对照 + `/api/fastjson/autotype` |
| `lab/fastjson-version-lab` | `18030` / `18047` / `18068` / `18082` | 版本矩阵（1.2.30 / 47 / 68 / 80） |
| `lab/fastjson-1247-lab` | `18247` | ≤1.2.47 全依赖（JDK8u242） |
| `lab/fastjson-1268-lab` | `18268` | ≤1.2.68 AutoCloseable 依赖（JDK11） |
| `lab/fastjson-1280-lab` | `18280` | ≤1.2.80 Exception 缓存依赖（JDK11，共享 ParserConfig） |
| `lab/cve-2026-16723` | `18083`（JDWP `18505`） | 1.2.83 Undertow fat jar |

### 3.5 未完成（相对最终目标）

- 通用自定义字节码上传 UI（1.2.47 BCEL/H2/C3P0 已支持 `--class-b64`；Web 侧尚未统一上传）
- ognl+io / ajt+xalan 等少见组合链（仅文档引用）
- 通用回显 / 内存马编排（1.2.83 证明 PoC 内已含专项实现）
- 按版本探测结果一键推荐 PoC 的工作流串联

---

## 4. 后续工作

### Phase 2 — 版本识别（已完成）

- AutoType 双探针、SafeMode（`java.lang.String"""`）探针、AutoCloseable `fastjson-version` 回显、1.2.83 探针
- 不出网二分（Exception / AutoCloseable / Class+Jdbc / Jdbc）
- 四档区间：`<=1.2.47` / `<=1.2.68` / `<=1.2.80` / `1.2.83`
  - DNSLog 双请求稳分 `1.2.83`；回显 `1.2.68` vs `1.2.76` 分 `<=68` / `<=80`；不出网 `Class+Jdbc` 分 `<=47`
  - 探针与微信笔记一致；DNS le47/le68 在 InetSocketAddress 可单独出网时会 overfire，推断会回退出网/回显
- 输出：版本区间 / 置信度 / 证据；Web：`/version`（不另做 CLI）

### Phase 3 — 各版本 PoC + 自定义字节码（主体已完成）

- ✅ CVE-2026-16723（1.2.83）：jar:http / fd-cache 证明 PoC + Undertow 靶场 + Web `/poc`
- ✅ ≤1.2.47 Class 缓存绕过：JdbcRowSet / BCEL(dbcp×4) / C3P0 / MyBatis / H2
  - 模块：`src/fastjson_toolkit/poc/v1_2_47/`；API：`GET/POST /api/poc/1.2.47`；CLI：`fjtoolkit poc-1247`
  - Web `/poc` Tab「≤1.2.47」；靶场：`lab/fastjson-1247-lab`（`:18247`）
- ✅ ≤1.2.68 AutoCloseable expectClass：JDK 写/截断、commons-io（io1–io5/ioFinal/读）、MySQL/PG
  - 模块：`src/fastjson_toolkit/poc/v1_2_68/`；API：`GET/POST /api/poc/1.2.68`；CLI：`fjtoolkit poc-1268`
  - Web `/poc` Tab「≤1.2.68」；靶场：`lab/fastjson-1268-lab`（`:18268`）
- ✅ ≤1.2.80 Exception expectClass + 反序列化器缓存：jackson→InputStream、commons-io 读写、PG/MySQL、groovy、aspectj、jython
  - 模块：`src/fastjson_toolkit/poc/v1_2_80/`；API：`GET/POST /api/poc/1.2.80`；CLI：`fjtoolkit poc-1280`
  - Web `/poc` Tab「≤1.2.80」；靶场：`lab/fastjson-1280-lab`（`:18280`）
- ✅ WAF 本地变换 + PoC 叠加（CLI `--waf` / API `waf_techniques` / Web `/waf` 与 PoC 页勾选）
- ✅ Getter 触发封装（期望类场景）
- ⏳ 通用自定义字节码上传 UI；少见组合链补齐
- ⏳ 版本探测结果 → 推荐 PoC 的一键工作流

### Phase 4 — 回显

- 实现常见回显手法，与 PoC 组合
- Web：命令输入、回显结果展示（shadcn Textarea / Alert）

### Phase 5 — 内存马注入

- 对接 MemShellParty：中间件类型、Shell 类型、密码/路径、打包格式
- 生成字节码后经 Fastjson 链投递
- Web：参数表单 + 生成结果（严格使用 shadcn 组件）

### Phase 6 — Web 整合与联调

- 打通识别 → 版本 → 期望类/依赖 → PoC/回显 → 内存马工作流
- FastAPI 补齐 `/api/memshell` 等
- Docker 靶场扩展：回显 / 内存马验证环境

---

## 5. 约束与约定

1. **前端强制 shadcn**：新 UI 不引入非 shadcn 的平行组件库；样式走项目既有 Tailwind + shadcn 体系（见 `AGENTS.md`）。
2. **安全使用范围**：仅用于授权测试 / 本地靶场复现。
3. **密钥**：CEYE token 等只放 `.env`，不入库。
4. **Agent 友好（次要）**：API 保持结构化 JSON（`is_fastjson` / `confidence` / `evidence` / `next_actions`）；主交付仍是 Web。

---

## 6. 关键目录

```
├── scripts/start.* / stop.*     # 一键启停 Web（默认后端 --reload，不含靶场）
├── scripts/lab_test_*.py        # 各版本 gadget 靶场落盘验证
├── docs/design.md               # 本文档
├── AGENTS.md                    # Agent / shadcn 约定
├── src/fastjson_toolkit/        # 后端核心
│   ├── detect / version / expect / deps
│   ├── poc/（v1_2_47 / v1_2_68 / v1_2_80 / cve_2026_16723 / getter）
│   ├── waf / dnslog / http / api / cli
├── web/                         # Next.js + shadcn
├── lab/                         # Docker 靶场（指纹 / 版本矩阵 / 1247 / 1268 / 1280 / 16723）
├── tests/                       # 单元测试
└── .env.example                 # CEYE 等配置模板
```

下一阶段：通用自定义字节码上传 UI、版本→PoC 推荐工作流，以及 Phase 4 回显 / Phase 5 内存马编排。
