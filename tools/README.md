# Portable Fastjson tools CLI（对齐 MCP）

与 MCP 同源：探测 + PoC/探针检索 + 本地 WAF 混淆；**不代发** exploit。

**单一入口**：`fjtool.py` / `fjtool.sh`，子命令与 MCP 工具同名。

## 初始化（必做）

需要 **Python >= 3.10**。CLI 仅依赖 `httpx` + `pydantic`（stdlib `argparse`），**不需要** typer / fastapi / mcp。

### 本仓库内

与主 README「快速开始」共用 venv：

```bash
# 仓库根目录
python3 -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1

pip install -e .
# 或：pip install -e ".[dev]"
# 最小依赖（不装本包）：pip install "httpx>=0.27" "pydantic>=2.7"
```

校验：

```bash
python tools/fjtool.py -h
python tools/fjtool.py docs_list
./tools/fjtool.sh docs_list
```

脚本会把 `<repo>/src` 与仓库根加入 `sys.path`（见 `_lib/bootstrap.py`）。若未 `pip install -e .`，也可用：

```bash
PYTHONPATH=src python tools/fjtool.py docs_list
```

常见问题：`ModuleNotFoundError`（`fastjson_toolkit` / `httpx` / `pydantic`）→ 激活错误的 Python，或未安装依赖。用 venv 内解释器显式运行：

```bash
.venv/bin/python tools/fjtool.py -h
```

可选 CEYE：仓库根 `.env` 中配置 `CEYE_TOKEN` / `CEYE_DOMAIN`（或复制 `.env.example`）。CLI **不**接受 token 参数。

### 迁到其他项目后

1. 按下方「迁到其他项目」拷贝 `tools/` + 引擎子集 + docs  
2. 安装 `httpx` `pydantic`  
3. 保证相对布局或设置 `PYTHONPATH` / 改 `_lib/bootstrap.py`  
4. 需要读文档时设置 `FASTJSON_DOCS_DIR`，或保留 `web/content/docs`  
5. 运行 `python tools/fjtool.py -h` 校验  

## 用法

```bash
python tools/fjtool.py -h
python tools/fjtool.py detect_pipeline -h
./tools/fjtool.sh -h

python tools/fjtool.py docs_list
python tools/fjtool.py poc_catalog --family 1.2.68
python tools/fjtool.py poc_meta 1.2.68 mysql_jdbc
python tools/fjtool.py poc_get 1.2.68 mysql_jdbc --options '{"ldap_url":"ldap://..."}'
python tools/fjtool.py waf_apply '{"@type":"..."}' -t unicode
```

| 子命令 | 说明 |
|--------|------|
| `detect_pipeline` | 识别 → 版本 → 期望类 |
| `deps_probe` | 依赖探测 |
| `probe_catalog` / `probe_get` | 探测探针目录 / 单条 payload |
| `poc_catalog` / `poc_meta` / `poc_get` / `poc_script` | PoC 目录 / 参数元数据 / payload / 脚本 |
| `waf_catalog` / `waf_apply` | WAF 技巧 / 本地混淆 |
| `docs_list` / `docs_get` | 文档目录 / 章节 |

- 默认 stdout 为 JSON；`poc_get` / `waf_apply` 成功时直接输出 payload 字符串（与 MCP 一致）。
- `ok: false` 时退出码为 `1`。
- DNS / CEYE：读环境变量或项目根 `.env`（`CEYE_TOKEN` / `CEYE_DOMAIN`），CLI **不**提供 token 参数。

`fjtool.sh` 为薄封装：`exec python3 "$(dirname)/fjtool.py" "$@"`。

## 迁到其他项目

拷贝下列内容即可作为基础工具：

| 必带 | 说明 |
|------|------|
| 整个 `tools/` | `fjtool.py` / `fjtool.sh` + `_lib`（handlers / docs_loader / cli_common / bootstrap） |
| `src/fastjson_toolkit/` 引擎子集 | `detect` `version` `expect` `deps` `poc` `waf` `dnslog` `http` `config.py` 及包 `__init__`；**可不带** `api` / `cli` / `mcp` / `lab` |
| 文档目录 | 拷贝 `web/content/docs`，或设置 `FASTJSON_DOCS_DIR` 指向 docs |
| pip | `httpx` `pydantic`（CLI 仅用 stdlib `argparse`，无需 typer / fastapi / mcp） |

目录相对关系需保持：

```
<project>/
  tools/          # 本目录
  src/fastjson_toolkit/...
  web/content/docs/...   # 或 FASTJSON_DOCS_DIR
```

若引擎不在 `../src`，改 `_lib/bootstrap.py` 中的 `src` 路径，或预先设置 `PYTHONPATH`。

## 与本仓库其它入口的关系

- **MCP**（`fjtoolkit mcp`）与本目录共用 `tools/_lib/handlers.py`。
- **人机 CLI**（`fjtoolkit detect` / `poc-* --send` 等）保留，可代发；本 `tools/` 对齐 MCP，不代发。
