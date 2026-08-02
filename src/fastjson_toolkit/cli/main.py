"""CLI for FastjsonExpToolkit."""

from __future__ import annotations

import json
from typing import Optional

import typer
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table

from fastjson_toolkit.config import load_dotenv
from fastjson_toolkit.detect import FastjsonDetector
from fastjson_toolkit.dnslog import CeyeClient, CeyeConfig

app = typer.Typer(
    name="fjtoolkit",
    help="FastjsonExpToolkit — Fastjson 识别 / PoC 工具",
    add_completion=False,
    no_args_is_help=True,
)


def _parse_headers(header: Optional[list[str]]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in header or []:
        if ":" not in item:
            raise typer.BadParameter(f"非法 header: {item}")
        k, v = item.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


@app.command("detect")
def detect_cmd(
    target: str = typer.Argument(..., help="目标 URL，例如 http://127.0.0.1:18080/api/fastjson"),
    dnslog: Optional[str] = typer.Option(None, "--dnslog", help="自定义 DNSLog 域名（不含 CEYE 轮询）"),
    ceye_token: Optional[str] = typer.Option(
        None, "--ceye-token", help="CEYE API token；默认读 CEYE_TOKEN / .env"
    ),
    ceye_domain: Optional[str] = typer.Option(
        None, "--ceye-domain", help="CEYE 子域，默认 hpdth2.ceye.io"
    ),
    ceye_wait: float = typer.Option(8.0, "--ceye-wait", help="CEYE DNS 轮询等待秒数"),
    no_ceye: bool = typer.Option(False, "--no-ceye", help="禁用 CEYE DNSLog"),
    timeout: float = typer.Option(10.0, "--timeout", help="请求超时秒数"),
    no_dns: bool = typer.Option(False, "--no-dns", help="跳过 DNS/时延探针"),
    timing_threshold: float = typer.Option(800.0, "--timing-threshold", help="DNS 时延判定阈值(ms)"),
    header: Optional[list[str]] = typer.Option(
        None,
        "--header",
        "-H",
        help="额外请求头，格式 Key:Value，可重复",
    ),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP 代理"),
    insecure: bool = typer.Option(False, "--insecure", help="跳过 TLS 校验"),
    json_out: bool = typer.Option(False, "--json", help="输出完整 JSON（便于 Agent 消费）"),
) -> None:
    """对目标做 Fastjson 指纹识别。"""
    load_dotenv()
    headers = _parse_headers(header)

    ceye_cfg = None
    if not no_ceye and not no_dns:
        env_cfg = CeyeConfig.from_env()
        token = ceye_token or (env_cfg.token if env_cfg else None)
        domain = ceye_domain or (env_cfg.domain if env_cfg else "hpdth2.ceye.io")
        if token:
            ceye_cfg = CeyeConfig(token=token, domain=domain)

    detector = FastjsonDetector(
        timeout=timeout,
        headers=headers or None,
        proxy=proxy,
        verify_tls=not insecure,
        dnslog_host=dnslog,
        ceye=ceye_cfg,
        ceye_wait=ceye_wait,
        timing_threshold_ms=timing_threshold,
    )
    try:
        result = detector.detect(target, include_dns=not no_dns)
    finally:
        detector.close()

    if json_out:
        typer.echo(result.model_dump_json(indent=2))
        raise typer.Exit(0 if result.is_fastjson else 1)

    color = "green" if result.is_fastjson else "yellow"
    rprint(Panel(result.summary, title="Fastjson 识别结果", border_style=color))

    table = Table(title="库得分")
    table.add_column("Library")
    table.add_column("Score", justify="right")
    for name, score in sorted(result.scores.items(), key=lambda x: x[1], reverse=True):
        table.add_row(name, f"{score:.2f}")
    rprint(table)

    if result.dns_filter is not None:
        rprint(
            f"CEYE filter=[bold]{result.dns_filter}[/bold] confirmed={result.dns_confirmed} "
            f"records={len(result.dns_records)}"
        )

    ev_table = Table(title="关键证据（节选）")
    ev_table.add_column("Probe")
    ev_table.add_column("Hint")
    ev_table.add_column("Status")
    ev_table.add_column("Matched")
    for ev in result.evidence:
        if not ev.matched and ev.score_delta <= 0:
            continue
        ev_table.add_row(
            ev.probe_id,
            ev.library_hint or "-",
            str(ev.status_code),
            ", ".join(ev.matched[:3]) or "-",
        )
    rprint(ev_table)

    if result.next_actions:
        rprint("[bold]下一步建议[/bold]")
        for i, action in enumerate(result.next_actions, 1):
            rprint(f"  {i}. {action}")

    raise typer.Exit(0 if result.is_fastjson else 1)


@app.command("ceye-check")
def ceye_check_cmd(
    filter_text: Optional[str] = typer.Option(None, "--filter", help="CEYE filter（<=20）"),
    trigger: bool = typer.Option(False, "--trigger", help="本机触发一次 DNS 解析用于连通性验证"),
    wait: float = typer.Option(5.0, "--wait", help="触发后等待秒数"),
    token: Optional[str] = typer.Option(None, "--token", help="CEYE token"),
    domain: Optional[str] = typer.Option(None, "--domain", help="CEYE domain"),
) -> None:
    """查询 / 验证 CEYE DNSLog。"""
    import socket
    import time

    load_dotenv()
    cfg = None
    if token:
        cfg = CeyeConfig(token=token, domain=domain or "hpdth2.ceye.io")
    else:
        cfg = CeyeConfig.from_env()
        if cfg and domain:
            cfg = CeyeConfig(token=cfg.token, domain=domain)
    if cfg is None:
        raise typer.BadParameter("未配置 CEYE_TOKEN（可用 --token 或 .env）")

    filt = filter_text or CeyeClient.new_filter("ck")
    with CeyeClient(cfg) as client:
        host = client.build_host(filt)
        if trigger:
            try:
                socket.getaddrinfo(host, None)
            except socket.gaierror:
                pass
            time.sleep(wait)
        rows = client.query("dns", filt)
        typer.echo(
            json.dumps(
                {
                    "domain": cfg.domain,
                    "filter": filt,
                    "host": host,
                    "count": len(rows),
                    "records": [
                        {"name": r.name, "remote_addr": r.remote_addr, "created_at": r.created_at}
                        for r in rows
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )


@app.command("probes")
def probes_cmd(
    dnslog: Optional[str] = typer.Option(None, "--dnslog", help="DNSLog 域名"),
) -> None:
    """列出内置识别探针（Agent 可用来规划探测顺序）。"""
    from fastjson_toolkit.detect.probes import all_probes

    data = [
        {
            "id": p.id,
            "category": p.category,
            "description": p.description,
            "prefer_typed": p.prefer_typed,
            "dns_related": p.dns_related,
            "payload": p.payload,
            "weight": p.weight,
        }
        for p in all_probes(dnslog)
    ]
    typer.echo(json.dumps(data, ensure_ascii=False, indent=2))


@app.command("deps")
def deps_cmd(
    target: str = typer.Argument(..., help="目标 URL"),
    method: str = typer.Option(
        "character",
        "--method",
        help="character（报错回显，推荐）或 dns（Locale+Inet4）",
    ),
    category: Optional[list[str]] = typer.Option(
        None, "--category", "-c", help="按类别过滤，可重复"
    ),
    clazz: Optional[list[str]] = typer.Option(
        None, "--class", help="仅扫描指定全限定类名，可重复"
    ),
    dnslog: Optional[str] = typer.Option(None, "--dnslog", help="自定义 DNSLog 域名"),
    ceye_token: Optional[str] = typer.Option(None, "--ceye-token"),
    ceye_domain: Optional[str] = typer.Option(None, "--ceye-domain"),
    ceye_wait: float = typer.Option(10.0, "--ceye-wait"),
    no_ceye: bool = typer.Option(False, "--no-ceye"),
    timeout: float = typer.Option(10.0, "--timeout"),
    concurrency: int = typer.Option(6, "--concurrency"),
    header: Optional[list[str]] = typer.Option(None, "--header", "-H"),
    proxy: Optional[str] = typer.Option(None, "--proxy"),
    insecure: bool = typer.Option(False, "--insecure"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """依赖 / classpath 探测（Character 报错或 DNS Locale）。"""
    from fastjson_toolkit.deps import FastjsonDepsDetector

    load_dotenv()
    headers = _parse_headers(header)
    method_norm = method.strip().lower()
    if method_norm not in ("character", "dns"):
        raise typer.BadParameter("method 仅支持 character 或 dns")

    ceye_cfg = None
    if method_norm == "dns" and not no_ceye:
        env_cfg = CeyeConfig.from_env()
        token = ceye_token or (env_cfg.token if env_cfg else None)
        domain = ceye_domain or (env_cfg.domain if env_cfg else "hpdth2.ceye.io")
        if token:
            ceye_cfg = CeyeConfig(token=token, domain=domain)

    detector = FastjsonDepsDetector(
        timeout=timeout,
        headers=headers or None,
        proxy=proxy,
        verify_tls=not insecure,
        dnslog_host=dnslog,
        ceye=ceye_cfg,
        ceye_wait=ceye_wait,
        concurrency=concurrency,
    )
    try:
        result = detector.scan(
            target,
            method=method_norm,
            classes=clazz or None,
            categories=category or None,
        )
    finally:
        detector.close()

    if json_out:
        typer.echo(result.model_dump_json(indent=2))
        raise typer.Exit(0 if result.present_count else 1)

    color = "green" if result.present_count else "yellow"
    rprint(Panel(result.summary, title="依赖探测结果", border_style=color))
    for note in result.notes:
        rprint(f"[dim]{note}[/dim]")

    table = Table(title="命中依赖")
    table.add_column("Description")
    table.add_column("Class")
    table.add_column("Category")
    for hit in result.present:
        table.add_row(hit.description, hit.clazz, hit.category)
    if result.present:
        rprint(table)
    else:
        rprint("[yellow]未发现命中依赖[/yellow]")

    if result.next_actions:
        rprint("[bold]下一步建议[/bold]")
        for i, action in enumerate(result.next_actions, 1):
            rprint(f"  {i}. {action}")

    raise typer.Exit(0 if result.present_count else 1)


@app.command("serve")
def serve_cmd(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    reload: bool = typer.Option(
        True,
        "--reload/--no-reload",
        help="监听源码变更并自动重启（默认开启）",
    ),
) -> None:
    """启动 Web 后端 API（FastAPI / Uvicorn）。"""
    load_dotenv()
    import uvicorn
    from pathlib import Path

    # package root: .../src/fastjson_toolkit/cli/main.py → project/src
    src_dir = Path(__file__).resolve().parents[2]
    kwargs: dict = {
        "app": "fastjson_toolkit.api.app:app",
        "host": host,
        "port": port,
        "reload": reload,
    }
    if reload:
        kwargs["reload_dirs"] = [str(src_dir)]
        kwargs["reload_includes"] = ["*.py"]

    uvicorn.run(**kwargs)


if __name__ == "__main__":
    app()
