# Portable Fastjson tools CLI（对齐 MCP）

与 MCP 同源：探测 + PoC/探针检索 + 本地 WAF 混淆；**不代发** exploit。

## 用法

```bash
python tools/detect_pipeline.py -h
./tools/detect_pipeline.sh -h

python tools/docs_list.py
python tools/poc_catalog.py --family 1.2.68
python tools/poc_meta.py 1.2.68 mysql_jdbc
python tools/poc_get.py 1.2.68 mysql_jdbc --options '{"ldap_url":"ldap://..."}'
python tools/waf_apply.py '{"@type":"..."}' -t unicode
```

| 脚本 | 对应 MCP 工具 |
|------|----------------|
| `detect_pipeline.py` | `detect_pipeline` |
| `deps_probe.py` | `deps_probe` |
| `probe_catalog.py` / `probe_get.py` | `probe_catalog` / `probe_get` |
| `poc_catalog.py` / `poc_meta.py` / `poc_get.py` / `poc_script.py` | 同名 |
| `waf_catalog.py` / `waf_apply.py` | 同名 |
| `docs_list.py` / `docs_get.py` | 同名 |

- 默认 stdout 为 JSON；`poc_get` / `waf_apply` 成功时直接输出 payload 字符串（与 MCP 一致）。
- `ok: false` 时退出码为 `1`。
- DNS / CEYE：读环境变量或项目根 `.env`（`CEYE_TOKEN` / `CEYE_DOMAIN`），CLI **不**提供 token 参数。

同名 `*.sh` 为薄封装：`exec python3 "$(dirname)/xxx.py" "$@"`。

## 依赖

本仓库内：已 `pip install -e ".[dev]"`（或至少 `httpx` + `pydantic`），在仓库根执行即可。

脚本会把 `<repo>/src` 与仓库根加入 `sys.path`（见 `_lib/bootstrap.py`）。

## 迁到其他项目

拷贝下列内容即可作为基础工具：

| 必带 | 说明 |
|------|------|
| 整个 `tools/` | 入口 + `_lib`（handlers / docs_loader / cli_common / bootstrap） |
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
