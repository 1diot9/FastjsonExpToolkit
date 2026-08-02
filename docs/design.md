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
  识别 / 版本 / PoC / 回显 / 内存马
        │ HTTP JSON API
        ▼
Backend (Python)
  detect / version / poc / CEYE
        │                │
        ▼                ▼
  目标 / Docker 靶场   MemShellParty / 字节码
```

- **前端**：只通过后端 API 操作；UI 一律基于 shadcn（Button / Card / Tabs / Table / Input / Select 等）。
- **后端**：编排探测与 PoC；结构化 JSON 输出，便于 Web 与后续扩展。
- **内存马 / 字节码**：对接或封装 MemShellParty 的生成能力，再由 Fastjson gadget 链投递。

---

## 3. 当前进度（Phase 1：Fastjson 识别）

### 3.1 已完成

| 项 | 说明 |
|----|------|
| 识别引擎 | `src/fastjson_toolkit/detect/`：报错、解析特征、`$ref`、与其他库差异探针 |
| 判定策略 | 仅强特征可判定 Fastjson；差异探针不单独定论，避免 Gson/Hutool 误报 |
| CEYE DNSLog | `hpdth2.ceye.io` + API 轮询确认出网（`.env` 配置 token） |
| CLI | `fjtoolkit detect` / `ceye-check` / `probes` |
| Docker 靶场 | `lab/docker-compose.yml`，多解析器端点 + `/api/fastjson/autotype` |
| HTTP 性能 | 复用 `httpx.Client`，本地 detect ~1s 级 |
| Web 骨架 | `web/`：Next.js + 已安装部分 shadcn 组件（识别页草稿） |

### 3.2 靶场验证结论

- Fastjson → `is_fastjson=true`
- Jackson / Gson / Hutool / org.json → `is_fastjson=false`
- autoType 开启端点可走 CEYE DNS 确认

### 3.3 Web 前后端（进行中 / 已打通识别）

- 后端：FastAPI（`fjtoolkit serve`，默认 `http://127.0.0.1:8000`）
  - `GET /api/health`
  - `GET /api/probes`
  - `POST /api/detect`
  - `GET/PUT /api/settings`（CEYE Token / Identifier，写入 `.env`）
  - `POST /api/settings/ceye-test`
  - API 文档：`/api/docs`（Scalar）、`/api/swagger`、`/api/redoc`、`/api/openapi.json`
- 前端：Next.js + shadcn（`web/`，开发时 rewrite 代理 `/api/*` → 后端）
- 识别页已对接真实 API（靶场预设、DNS/CEYE 开关、得分/证据/JSON）
- 设置页可配置 CEYE Token 与 Identifier 子域名

### 3.4 未完成（相对最终目标）

- 版本识别、PoC、回显、内存马均未实现
- 对应 Web 页面与 API 尚未扩展（识别相关 API/页面已完成）

---

## 4. 后续工作

### Phase 2 — 版本识别

- 按版本差异构造探针（报错文案、autoType/expect 行为、已知 gadget 可达性等）
- 输出：版本区间 / 置信度 / 证据列表
- Web：版本识别页（shadcn Tabs / Table / Badge）

### Phase 3 — 各版本 PoC + 自定义字节码

- 覆盖常见版本链（按 Phase 2 结果推荐）
- PoC 支持注入 **自定义字节码**（上传 class / base64）
- 统一 payload 生成接口，供 Web 一键生成与复制

### Phase 4 — 回显

- 实现常见回显手法，与 PoC 组合
- Web：命令输入、回显结果展示（shadcn Textarea / Alert）

### Phase 5 — 内存马注入

- 对接 MemShellParty：中间件类型、Shell 类型、密码/路径、打包格式
- 生成字节码后经 Fastjson 链投递
- Web：参数表单 + 生成结果（严格使用 shadcn 组件）

### Phase 6 — Web 整合与联调

- FastAPI（或同类）暴露：`/api/detect`、`/api/version`、`/api/poc`、`/api/memshell` 等
- 前端页面：识别 → 版本 → PoC/回显 → 内存马 工作流
- Docker 靶场扩展：版本矩阵、回显/内存马验证环境

---

## 5. 约束与约定

1. **前端强制 shadcn**：新 UI 不引入非 shadcn 的平行组件库；样式走项目既有 Tailwind + shadcn 体系。
2. **安全使用范围**：仅用于授权测试 / 本地靶场复现。
3. **密钥**：CEYE token 等只放 `.env`，不入库。
4. **Agent 友好（次要）**：API 保持结构化 JSON（`is_fastjson` / `confidence` / `evidence` / `next_actions`）；主交付仍是 Web。

---

## 6. 关键目录

```
├── scripts/start.* / stop.*  # 一键启停 Web（不含靶场）
├── docs/design.md            # 本文档
├── src/fastjson_toolkit/     # 后端核心（detect / api / cli / dnslog）
├── web/                      # Next.js + shadcn
├── lab/                      # Docker 指纹靶场
└── tests/                    # 单元测试
```

下一阶段：版本识别（API + Web 页）。
