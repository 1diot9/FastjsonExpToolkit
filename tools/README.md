# Portable Fastjson tools CLI（对齐 MCP）

与 MCP 同源：探测 + PoC/探针检索 + 本地 WAF 混淆；**不代发** exploit。

**单一入口**：`fjtool.py` / `fjtool.sh`，子命令与 MCP 工具同名。

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

## 依赖

本仓库内：已 `pip install -e ".[dev]"`（或至少 `httpx` + `pydantic`），在仓库根执行即可。

脚本会把 `<repo>/src` 与仓库根加入 `sys.path`（见 `_lib/bootstrap.py`）。

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
