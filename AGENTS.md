# FastjsonExpToolkit — Agent 约定

## 仓库布局（scripts vs tests）

| 目录 | 放什么 | 不要放 |
|------|--------|--------|
| `scripts/` | 一键启停 Web：`start.*` / `stop.*` | Python 测试、靶场验证、一次性探针 |
| `tools/` | 与 MCP 对齐的可迁移 CLI（单一入口 `fjtool.py` / `fjtool.sh`）+ `_lib` handlers | 启停 Web、pytest、多入口散脚本 |
| `tests/` | pytest 单元测试：`test_*.py`（`pytest -q`） | 启停脚本 |
| `tests/lab/` | 需本地 Docker 靶场的**手动**验证 / 压测 / DNS 探针脚本 | 会被 `pytest` 默认收集的 `test_*.py` |

`tests/lab/` 命名刻意避开 `test_*.py` / `*_test.py`，避免被 pytest 自动收集。在仓库根目录、已 `pip install -e ".[dev]"` 后运行，例如：

```powershell
python tests/lab/lab_test_1247_gadgets.py
python tests/lab/lab_test_1268_gadgets.py
python tests/lab/lab_test_1280_gadgets.py
```

新增「对着 lab 跑一遍证明」类脚本 → 放 `tests/lab/`，并同步改 `README.md` / `lab/**/README.md` 引用；**不要**再往 `scripts/` 塞 `.py`。

后端探测逻辑在 `src/fastjson_toolkit/`（`detect` / `version` / `expect` / `deps` / `poc`）；Web 页面对接 API 时复用其结构化输出，勿在前端重写探针。

### MCP（Agent 工具调用）

实现位于 `src/fastjson_toolkit/mcp/`（传输）+ `tools/_lib/`（纯 handlers，与 `tools/fjtool.py` CLI 同源）：

| 传输 | 入口 |
|------|------|
| stdio | `fjtoolkit mcp` |
| HTTP | 设置页启停，或 `fjtoolkit mcp --http`（默认 `127.0.0.1:8100/mcp`，可配 Token） |
| CLI | `python tools/fjtool.py <command> -h` / `./tools/fjtool.sh …`（先按 README「tools/ CLI → 初始化」装好 `httpx`/`pydantic` 或 `pip install -e .`；见 `tools/README.md`） |

工具：`detect_pipeline`、`deps_probe`、`probe_catalog`、`probe_get`、`poc_catalog`、`poc_meta`、`poc_get`、`poc_script`、`waf_catalog`、`waf_apply`、`docs_list`、`docs_get`。
MCP / `tools/` CLI 定位：版本/依赖探测 + PoC 知识库检索 + 本地 WAF 混淆；**不代发** exploit（已移除 `poc_run`）。
MCP 的 DNS/CEYE 默认读项目 `.env`（`CEYE_TOKEN` / `CEYE_DOMAIN`，设置页可配），工具参数不暴露 token/domain。
`detect_pipeline` 的 `target` 应为反序列化点；根路径会尝试 `/api/health` 与常见路径。`deps_probe(method=character)` 在 AutoType 关闭时自动降级 Class MiscCodec。
输出刻意精简：目录不含正文；`poc_get` / `probe_get` / `waf_apply` 成功时直接返回 payload 字符串；`poc_meta` 返回 `flag/required/arg_type/help`；`docs_list` 仅顶级目录，`docs_get(父)` 返回章节目录，`docs_get(父/章节)` 只返回该段；脚本 `poc_script`。
自动化探测失败时用 `probe_catalog` → `probe_get` + `docs_list` → `docs_get(fastjson-detect)` → `docs_get(fastjson-detect/…)`。
工作流：`poc_catalog` → `poc_meta` → `poc_get`（payload）→ 需要时 `docs_list` → `docs_get(父)` → `docs_get(章节)` / `poc_script` / `waf_apply` → LLM 自行发包。
`poc_script` 只返回固定原脚本（如 `1.2.68/io_read_error`），由 LLM 按环境自行改；不传参可列目录。文档读 `web/content/docs/`（可用 `FASTJSON_DOCS_DIR` 覆盖）。细节见 `README.md`「MCP」节与 `tools/README.md`。

---

## Web 前端：shadcn/ui

文档：https://ui.shadcn.com/

前端目录：`web/`（Next.js App Router + Tailwind CSS v4 + shadcn **base-nova**）。

### 强制约定

- **所有 Web UI 只用 shadcn 组件**（`web/src/components/ui/*`），不要手写平行的 Button / Card / Dialog / Table / Form。
- 禁止引入 MUI、Ant Design、Chakra、naive-ui 等其它 UI 库。
- 新组件用 CLI 安装，不要从别处复制非官方实现。
- 图标用 `lucide-react`。
- 样式用 Tailwind + `cn()`（`@/lib/utils`），跟 shadcn CSS 变量 / design token 保持一致。
- 业务组合组件放 `web/src/components/`（非 `ui/`）；`ui/` 以 CLI 生成物为主，少做破坏性改动。

### 目录

```
web/
  components.json           # shadcn 配置（style: base-nova）
  src/app/                  # 页面路由
  src/components/ui/        # shadcn 组件
  src/components/           # 业务组合组件
  src/lib/utils.ts          # cn()
  src/app/globals.css       # 主题 CSS 变量
```

### 已安装组件

`alert` `badge` `button` `card` `input` `label` `select` `separator` `sonner` `table` `tabs` `textarea`

### 安装 / 新增组件

在 `web/` 下执行（本机访问 `ui.shadcn.com` 若超时，先走代理，见下节）：

```powershell
cd web
npx shadcn@latest add <component>
# 例：
npx shadcn@latest add dialog checkbox switch
```

查看可装组件：https://ui.shadcn.com/docs/components

### 命令行代理（本机 10808）

Node `fetch` / `npx shadcn` **默认不走系统代理**。超时或连不上 registry 时，在**当前 PowerShell 会话**设置：

```powershell
$env:HTTP_PROXY='http://127.0.0.1:10808'
$env:HTTPS_PROXY='http://127.0.0.1:10808'
$env:ALL_PROXY='http://127.0.0.1:10808'
$env:NO_PROXY='localhost,127.0.0.1'
$env:NODE_USE_ENV_PROXY='1'
```

然后同一会话再跑 `npx shadcn@latest add ...`。  
**不要**持久 `npm config set proxy`。更完整说明见全局 `~/.cursor/AGENTS.md`「命令行代理」一节。

### 使用方式

```tsx
import { Button } from "@/components/ui/button"
import { buttonVariants } from "@/components/ui/button"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { toast } from "sonner"
import { Loader2 } from "lucide-react"
import Link from "next/link"
import { cn } from "@/lib/utils"

// 普通按钮
<Button onClick={() => toast.success("ok")} disabled={loading}>
  {loading ? <Loader2 className="size-4 animate-spin" /> : null}
  提交
</Button>

// 链接按钮：本项目 base-nova 的 Button 无 asChild，用 buttonVariants + Link
<Link href="/detect" className={cn(buttonVariants())}>
  打开识别页
</Link>
```

`Toaster` 已挂在 `src/app/layout.tsx`；页面里直接 `toast(...)`。

### 场景 → 组件

| 场景 | 组件 |
|------|------|
| 操作按钮 | `Button` / `buttonVariants` |
| 表单 | `Input` `Textarea` `Select` `Label`（可再加 `Checkbox` `Switch`） |
| 分区 | `Card` |
| 结果表 | `Table` |
| 状态 | `Badge` `Alert` |
| 切换 | `Tabs` |
| 弹层 | `Dialog` / `AlertDialog`（按需 `add`） |
| 轻提示 | `sonner`（`toast`） |
| 加载占位 | `Skeleton` |

### 本地启动

```powershell
cd web
npm install
npm run dev
```
