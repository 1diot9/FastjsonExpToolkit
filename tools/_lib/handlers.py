"""Pure tool handlers (no transport). Reuses detect / deps / poc / waf engines.

定位：版本与依赖探测 + PoC 知识库检索 + 本地 WAF 混淆。
不代发 exploit；LLM / CLI 调用方自行对目标 HTTP 发包。
不依赖 FastAPI / MCP 传输层。
"""

from __future__ import annotations

from typing import Any, Literal, Optional, Union, get_args, get_origin

from pydantic import BaseModel, ValidationError

from fastjson_toolkit.config import load_dotenv
from fastjson_toolkit.deps import FastjsonDepsDetector, default_catalog
from fastjson_toolkit.deps import probes as deps_probes
from fastjson_toolkit.detect import FastjsonDetector
from fastjson_toolkit.detect.probes import all_probes as all_detect_probes
from fastjson_toolkit.dnslog import CeyeConfig
from fastjson_toolkit.expect import FastjsonExpectClassDetector
from fastjson_toolkit.expect.probes import all_expect_probes
from .docs_loader import get_doc_or_section, list_docs
from fastjson_toolkit.poc import (
    Poc1247GenerateOptions,
    Poc1268GenerateOptions,
    Poc1280GenerateOptions,
    generate_poc_1247,
    generate_poc_1268,
    generate_poc_1280,
    list_poc_1247_gadgets,
    list_poc_1268_gadgets,
    list_poc_1280_gadgets,
)
from fastjson_toolkit.poc.v1_2_47.catalog import get_gadget as get_gadget_1247
from fastjson_toolkit.poc.v1_2_68.catalog import get_gadget as get_gadget_1268
from fastjson_toolkit.poc.v1_2_80.catalog import get_gadget as get_gadget_1280
from fastjson_toolkit.version import FastjsonVersionDetector
from fastjson_toolkit.version.probes import all_version_probes, offline_probes
from fastjson_toolkit.waf import WafOptions, WafRequest, list_techniques, run_waf

PocFamily = Literal["1.2.47", "1.2.68", "1.2.80", "cve-2026-16723"]
ProbeKind = Literal["detect", "version", "expect", "deps", "all"]
WafMode = Literal["stack", "variants"]

_FAMILY_DOC = {
    "1.2.47": "fastjson-1.2.47",
    "1.2.68": "fastjson-1.2.68",
    "1.2.80": "fastjson-1.2.80",
    "cve-2026-16723": "fastjson-1.2.83",
}

# MCP 面向 Agent：只保留决策字段。
_DETECT_KEEP = (
    "is_fastjson",
    "confidence",
)
_VERSION_KEEP = (
    "autotype_enabled",
    "safemode_enabled",
    "version_range",
    "version_detail",
    "is_1_2_83_hint",
    "confidence",
)
_EXPECT_KEEP = (
    "has_expect_class",
)
def _dump(model: BaseModel | None) -> dict[str, Any] | None:
    if model is None:
        return None
    return model.model_dump(mode="json")


def _pick(data: dict[str, Any] | None, keys: tuple[str, ...]) -> dict[str, Any] | None:
    if not data:
        return None
    out: dict[str, Any] = {}
    for key in keys:
        if key not in data:
            continue
        value = data[key]
        if value is None or value == "" or value == [] or value == {}:
            continue
        out[key] = value
    return out or None


def _omit_empty(data: dict[str, Any]) -> dict[str, Any]:
    """去掉 null / 空串 / 空容器；保留 False / 0。"""
    out: dict[str, Any] = {}
    for key, value in data.items():
        if value is None or value == "" or value == [] or value == {}:
            continue
        if isinstance(value, dict):
            nested = _omit_empty(value)
            if nested:
                out[key] = nested
            continue
        out[key] = value
    return out


def _slim_detect(data: dict[str, Any] | None) -> dict[str, Any] | None:
    return _pick(data, _DETECT_KEEP)


def _slim_deps_result(data: dict[str, Any]) -> dict[str, Any]:
    present = [
        {"clazz": h.get("clazz"), "category": h.get("category")}
        for h in (data.get("present") or [])
        if isinstance(h, dict)
    ]
    out: dict[str, Any] = {
        "method": data.get("method"),
        "present_count": data.get("present_count"),
        "present": present,
    }
    notes = data.get("notes") or []
    useful_notes = [
        n
        for n in notes
        if isinstance(n, str)
        and any(tip in n for tip in ("校准", "降级", "Class", "CEYE", "未配置"))
    ]
    if useful_notes:
        out["notes"] = useful_notes[:3]
    return _omit_empty(out)


def _slim_gadget(entry: dict[str, Any], *, family: str) -> dict[str, Any]:
    """目录条目：只留选型字段；正文见 docs_get / poc_get / poc_script。"""
    out: dict[str, Any] = {"id": entry.get("id")}
    for key in ("title", "requires", "jdk", "modes"):
        if entry.get(key):
            out[key] = entry[key]
    slug = _FAMILY_DOC.get(family)
    if slug:
        out["doc"] = slug
    return out


def _payload_only(data: dict[str, Any]) -> str | list[str]:
    """poc_get / waf_apply 成功时只返回可发包 JSON 字符串（多步则为列表）。"""
    steps = data.get("steps")
    if isinstance(steps, list) and len(steps) > 1:
        return [str(s) for s in steps]
    payload = data.get("payload")
    if payload is None or payload == "":
        raise ValueError("生成结果无 payload")
    return str(payload)


def _ceye_from_env(*, enabled: bool = True) -> CeyeConfig | None:
    """CEYE 一律读项目 .env / 环境变量；MCP 不暴露 token/domain 覆盖参数。"""
    if not enabled:
        return None
    load_dotenv()
    return CeyeConfig.from_env()


def _err(message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": message, **extra}


def _merge_options(base: dict[str, Any], options: dict[str, Any] | None) -> dict[str, Any]:
    merged = dict(base)
    if options:
        for key, value in options.items():
            if value is not None:
                merged[key] = value
    return merged


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

    DNS / CEYE：有 ``CEYE_TOKEN``（及可选 ``CEYE_DOMAIN``）时自动轮询。
    """
    target = (target or "").strip()
    if not target:
        return _err("target 不能为空")

    headers = headers or {}
    skipped: list[str] = []
    content_type = "application/json"
    ceye_wait_detect = 8.0
    ceye_wait_version = 10.0
    timing_threshold_ms = 800.0

    ceye_cfg = _ceye_from_env(enabled=include_dns_detect)
    detector = FastjsonDetector(
        timeout=timeout,
        headers=headers or None,
        proxy=proxy,
        verify_tls=not insecure,
        ceye=ceye_cfg,
        ceye_wait=ceye_wait_detect,
        timing_threshold_ms=timing_threshold_ms,
        content_type=content_type,
    )
    try:
        detect_result = detector.detect(target, include_dns=include_dns_detect)
    except Exception as exc:  # noqa: BLE001
        return _err(f"识别失败: {exc}")
    finally:
        detector.close()

    version_result = None
    expect_result = None
    effective_target = (
        (detect_result.raw or {}).get("resolved_url")
        or detect_result.target
        or target
    )

    if not detect_result.is_fastjson:
        skipped.extend(["version", "expect"])
        return {
            "ok": True,
            "detect": _slim_detect(_dump(detect_result)),
            "skipped": skipped,
            "effective_target": effective_target,
            "summary": detect_result.summary
            or "未判定为 Fastjson，已跳过版本与期望类探测",
            "next": ["probe_catalog(kind='detect')", "docs_get(slug='fastjson-detect')"],
        }

    v_ceye = _ceye_from_env(enabled=include_dns_version)
    version_detector = FastjsonVersionDetector(
        timeout=timeout,
        headers=headers or None,
        proxy=proxy,
        verify_tls=not insecure,
        ceye=v_ceye,
        ceye_wait=ceye_wait_version,
        content_type=content_type,
    )
    try:
        version_result = version_detector.detect(
            effective_target, include_dns=include_dns_version
        )
    except Exception as exc:  # noqa: BLE001
        skipped.append("version")
        version_error = str(exc)
    else:
        version_error = None
    finally:
        version_detector.close()

    expect_detector = FastjsonExpectClassDetector(
        timeout=timeout,
        headers=headers or None,
        proxy=proxy,
        verify_tls=not insecure,
        content_type=content_type,
    )
    try:
        expect_result = expect_detector.detect(
            effective_target, base_body=base_body
        )
    except Exception as exc:  # noqa: BLE001
        skipped.append("expect")
        expect_error = str(exc)
    else:
        expect_error = None
    finally:
        expect_detector.close()

    next_hints = [f"deps_probe(target={effective_target!r})", "poc_catalog"]
    if "version" in skipped:
        next_hints = ["probe_catalog(kind='version')", "docs_get(slug='fastjson-detect')"] + next_hints
    if expect_result is not None and getattr(expect_result, "has_expect_class", None):
        next_hints.insert(0, "poc_get(..., expect_bypass=true)")

    out: dict[str, Any] = {
        "ok": True,
        "effective_target": effective_target,
        "detect": _slim_detect(_dump(detect_result)),
        "version": _pick(_dump(version_result), _VERSION_KEEP),
        "expect": _pick(_dump(expect_result), _EXPECT_KEEP),
        "skipped": skipped or None,
        "next": next_hints,
    }
    if version_error:
        out["version_error"] = version_error
    if expect_error:
        out["expect_error"] = expect_error
    return _omit_empty(out)


# ---------------------------------------------------------------------------
# deps_probe
# ---------------------------------------------------------------------------


def deps_probe(
    target: str,
    *,
    method: str = "character",
    classes: list[str] | None = None,
    timeout: float = 10.0,
    concurrency: int = 6,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
    insecure: bool = False,
) -> dict[str, Any]:
    """依赖探测。默认扫全量内置目录。"""
    target = (target or "").strip()
    if not target:
        return _err("target 不能为空")

    method = (method or "character").strip().lower()
    if method not in ("character", "class", "dns"):
        return _err("method 仅支持 character、class 或 dns")

    class_list = list(classes or [])
    ceye_cfg = _ceye_from_env(enabled=method == "dns")
    detector = FastjsonDepsDetector(
        timeout=timeout,
        headers=headers or None,
        proxy=proxy,
        verify_tls=not insecure,
        ceye=ceye_cfg,
        ceye_wait=10.0,
        content_type="application/json",
        concurrency=concurrency,
    )
    try:
        result = detector.scan(
            target,
            method=method,
            classes=class_list or None,
            categories=None,
        )
    except Exception as exc:  # noqa: BLE001
        return _err(f"依赖探测失败: {exc}")
    finally:
        detector.close()

    return {
        "ok": True,
        "result": _slim_deps_result(_dump(result) or {}),
        "next": ["poc_catalog"],
    }


# ---------------------------------------------------------------------------
# probe_catalog — 探测 payload 知识库（自动化失败时供 LLM 手改）
# ---------------------------------------------------------------------------


def _probe_row(probe: Any, *, include_payload: bool) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": getattr(probe, "id", None),
        "category": getattr(probe, "category", None),
        "description": getattr(probe, "description", None),
    }
    if include_payload:
        row["payload"] = getattr(probe, "payload", None)
    if getattr(probe, "dns_related", False):
        row["dns"] = True
    expect_fj = getattr(probe, "expect_fastjson", None) or ()
    if expect_fj:
        row["hit"] = list(expect_fj)[:4]
    return _omit_empty(row)


def probe_catalog(
    kind: ProbeKind = "all",
    *,
    dnslog_host: str | None = None,
    base_body: str | None = None,
    include_deps_classes: bool = False,
    include_payload: bool = False,
) -> dict[str, Any]:
    """列探测探针目录。默认不含 payload；完整 payload 用 include_payload=true 或 probe_get。"""
    kind = (kind or "all").strip().lower()  # type: ignore[assignment]
    if kind not in ("detect", "version", "expect", "deps", "all"):
        return _err("kind 仅支持 detect / version / expect / deps / all")

    host = (dnslog_host or "").strip() or None
    out: dict[str, Any] = {"ok": True, "doc": "fastjson-detect"}

    if kind in ("detect", "all"):
        out["detect"] = [
            _probe_row(p, include_payload=include_payload) for p in all_detect_probes(host)
        ]
    if kind in ("version", "all"):
        if host:
            probes = all_version_probes(
                {"le47": host, "le68": host, "d80a": host, "d80b": host}
            )
        else:
            probes = offline_probes()
        out["version"] = [_probe_row(p, include_payload=include_payload) for p in probes]
        if not host:
            out["version_note"] = "离线探针；DNS 探针请传 dnslog_host"
    if kind in ("expect", "all"):
        out["expect"] = [
            _probe_row(p, include_payload=include_payload)
            for p in all_expect_probes(base_body)
        ]
        out["expect_doc"] = "getter-trigger"
    if kind in ("deps", "all"):
        deps_block: dict[str, Any] = {
            "templates": {
                "character": deps_probes.CHARACTER_PAYLOAD_TEMPLATE,
                "class": deps_probes.CLASS_PAYLOAD_TEMPLATE,
                "dns": deps_probes.DNS_LOCALE_PAYLOAD_TEMPLATE,
            },
            "hit": {
                "character_present": list(deps_probes.CAST_MARKERS)[:4],
                "class_present": "带引号类名 JSON 字符串",
                "class_absent": "null",
                "dns": "CEYE/DNSLog 命中",
            },
        }
        if include_deps_classes:
            deps_block["classes"] = [
                {"class": e.clazz, "category": e.category} for e in default_catalog()
            ]
        out["deps"] = deps_block

    return out


def probe_get(
    kind: Literal["detect", "version", "expect"],
    probe_id: str,
    *,
    dnslog_host: str | None = None,
    base_body: str | None = None,
) -> dict[str, Any]:
    """取单条探测探针的完整 payload。"""
    kind = (kind or "").strip().lower()  # type: ignore[assignment]
    probe_id = (probe_id or "").strip()
    if kind not in ("detect", "version", "expect"):
        return _err("kind 仅支持 detect / version / expect（deps 用 templates）")
    if not probe_id:
        return _err("probe_id 不能为空")

    host = (dnslog_host or "").strip() or None
    if kind == "detect":
        probes = list(all_detect_probes(host))
    elif kind == "version":
        if host:
            probes = list(
                all_version_probes(
                    {"le47": host, "le68": host, "d80a": host, "d80b": host}
                )
            )
        else:
            probes = list(offline_probes())
    else:
        probes = list(all_expect_probes(base_body))

    for probe in probes:
        if getattr(probe, "id", None) == probe_id:
            return {
                "ok": True,
                "kind": kind,
                **_probe_row(probe, include_payload=True),
            }
    return _err(
        f"未找到探针: {kind}/{probe_id}",
        ids=[getattr(p, "id", None) for p in probes],
    )


def _arg_type_name(annotation: Any) -> str:
    """Map a typing annotation to a short arg_type string."""
    if annotation is None or annotation is type(None):
        return "any"
    origin = get_origin(annotation)
    if origin is Union:
        args = [a for a in get_args(annotation) if a is not type(None)]
        if len(args) == 1:
            return _arg_type_name(args[0])
        return "|".join(_arg_type_name(a) for a in args)
    if origin is list:
        args = get_args(annotation)
        inner = _arg_type_name(args[0]) if args else "any"
        return f"list[{inner}]"
    if origin is Literal:
        vals = get_args(annotation)
        return "str" if vals and all(isinstance(v, str) for v in vals) else "any"
    if annotation is str:
        return "str"
    if annotation is int:
        return "int"
    if annotation is float:
        return "float"
    if annotation is bool:
        return "bool"
    if isinstance(annotation, type):
        return annotation.__name__.lower()
    return "any"


def _field_default(field: Any) -> tuple[Any, bool]:
    """Return ``(default, has_default)`` for JSON meta."""
    if field.is_required():
        return None, False
    default = field.default
    if type(default).__name__ in ("PydanticUndefinedType", "UndefinedType"):
        return None, False
    # factory defaults (list/dict) — skip concrete value
    if field.default_factory is not None:
        return None, False
    if isinstance(default, (str, int, float, bool)) or default is None:
        return default, True
    return None, False


def _options_args_meta(model: type[BaseModel], field_names: tuple[str, ...] | list[str]) -> list[dict[str, Any]]:
    """Build autopoc-style arg meta for poc_get options keys."""
    fields = model.model_fields
    args: list[dict[str, Any]] = []
    for name in field_names:
        info = fields.get(name)
        if info is None:
            args.append(
                {
                    "flag": name,
                    "required": False,
                    "arg_type": "any",
                    "help": name,
                }
            )
            continue
        row: dict[str, Any] = {
            "flag": name,
            "required": bool(info.is_required()),
            "arg_type": _arg_type_name(info.annotation),
            "help": (info.description or name).strip(),
        }
        default, has_default = _field_default(info)
        if has_default:
            row["default"] = default
        args.append(row)
    return args


# ---------------------------------------------------------------------------
# poc_catalog / poc_meta / poc_get / poc_script
# ---------------------------------------------------------------------------


def poc_catalog(family: Optional[PocFamily] = None) -> dict[str, Any]:
    """按版本列 gadget 目录（选型用）；payload → poc_get，文档 → docs_get，脚本 → poc_script。"""
    from fastjson_toolkit.poc.scripts import list_scripts

    families: dict[str, Any] = {
        "1.2.47": list_poc_1247_gadgets(),
        "1.2.68": list_poc_1268_gadgets(),
        "1.2.80": list_poc_1280_gadgets(),
        "cve-2026-16723": [
            {
                "id": "cve-2026-16723",
                "title": "CVE-2026-16723",
                "modes": ["http", "fd"],
                "requires": ("1.2.68–1.2.83", "Spring Boot fat-jar"),
            }
        ],
    }
    if family is not None:
        if family not in families:
            return _err(f"未知 family: {family}", families=list(families))
        families = {family: families[family]}

    script_keys = {(m.family, m.gadget) for m in list_scripts()}
    slim_gadgets: dict[str, list[dict[str, Any]]] = {}
    for name, gadgets in families.items():
        rows = []
        for g in gadgets:
            if g.get("hidden"):
                continue
            row = _slim_gadget(g, family=name)
            gid = row.get("id")
            if gid and (name, gid) in script_keys:
                row["script"] = True
            rows.append(row)
        slim_gadgets[name] = rows

    return {"ok": True, "gadgets": slim_gadgets}


def poc_meta(family: PocFamily, gadget: str) -> dict[str, Any]:
    """返回某 gadget 的 options 参数元数据（供 poc_get 填写）。

    每项形如 ``{flag, required, arg_type, help[, default]}``；
    ``flag`` 与 ``poc_get(..., options={flag: ...})`` 的键名完全一致。
    """
    gadget = (gadget or "").strip()
    if not gadget:
        return _err("gadget 不能为空")

    doc_slug = _FAMILY_DOC.get(family)

    if family == "cve-2026-16723":
        return {
            "ok": True,
            "family": family,
            "gadget": "cve-2026-16723",
            "doc": doc_slug,
            "args": [],
            "note": "不生成 payload；无 options。请 docs_get 读构造后自行发包",
        }

    try:
        if family == "1.2.47":
            entry = get_gadget_1247(gadget)
            model = Poc1247GenerateOptions
        elif family == "1.2.68":
            entry = get_gadget_1268(gadget)
            model = Poc1268GenerateOptions
        elif family == "1.2.80":
            entry = get_gadget_1280(gadget)
            model = Poc1280GenerateOptions
        else:
            return _err(f"未知 family: {family}")
    except KeyError as exc:
        return _err(str(exc))

    args = _options_args_meta(model, entry.input_fields)
    tool_args = [
        {
            "flag": "expect_bypass",
            "required": False,
            "arg_type": "bool",
            "help": (
                "poc_get 顶层参数。有期望类时绕过：1.2.47→currency；"
                "1.2.68/1.2.80→wrap_currency。默认 false。"
            ),
            "default": False,
        }
    ]
    return {
        "ok": True,
        "family": family,
        "gadget": entry.id,
        "title": entry.title,
        "doc": doc_slug,
        "args": args,
        "tool_args": tool_args,
        "note": "args[].flag 即 poc_get.options 键名；tool_args 为 poc_get 顶层参数",
    }


def poc_get(
    family: PocFamily,
    gadget: str,
    *,
    expect_bypass: bool = False,
    options: dict[str, Any] | None = None,
) -> str | list[str] | dict[str, Any]:
    """生成单个 gadget 的 JSON payload（不发包）。成功时直接返回 payload 字符串；多步返回 list。"""
    gadget = (gadget or "").strip()
    if not gadget:
        return _err("gadget 不能为空")

    doc_slug = _FAMILY_DOC.get(family)

    if family == "cve-2026-16723":
        return _err(
            "此 family 不生成 payload；请 docs_get 读构造细节后自行发包",
            doc=doc_slug,
            sections_hint=f"docs_list → docs_get('{doc_slug}/…')",
        )

    opts = _merge_options({"gadget": gadget}, options)
    opts.pop("waf_techniques", None)
    opts.pop("waf_options", None)
    opts.pop("target", None)
    opts.pop("send", None)

    try:
        if family == "1.2.47":
            if expect_bypass and "getter_trigger" not in opts:
                opts["getter_trigger"] = "currency"
            result = generate_poc_1247(Poc1247GenerateOptions.model_validate(opts))
        elif family == "1.2.68":
            if expect_bypass and "wrap_currency" not in opts:
                opts["wrap_currency"] = True
            result = generate_poc_1268(Poc1268GenerateOptions.model_validate(opts))
        elif family == "1.2.80":
            if expect_bypass and "wrap_currency" not in opts:
                opts["wrap_currency"] = True
            result = generate_poc_1280(Poc1280GenerateOptions.model_validate(opts))
        else:
            return _err(f"未知 family: {family}")
    except ValidationError as exc:
        return _err(f"参数校验失败: {exc}")
    except (KeyError, ValueError) as exc:
        return _err(str(exc))
    except Exception as exc:  # noqa: BLE001
        return _err(f"生成 payload 失败: {exc}")

    dumped = _dump(result) or {}
    try:
        return _payload_only(dumped)
    except ValueError as exc:
        return _err(str(exc), doc=doc_slug)


def poc_script(
    family: str | None = None,
    gadget: str | None = None,
) -> dict[str, Any]:
    """固定原脚本。不传参列目录；传 family+gadget 返回正文。"""
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
                }
                for m in items
            ],
        }

    try:
        meta, script = get_script(family, gadget)
    except FileNotFoundError as exc:
        return _err(
            str(exc),
            scripts=[
                {"family": m.family, "gadget": m.gadget}
                for m in list_scripts()
            ],
        )
    return {
        "ok": True,
        "family": meta.family,
        "gadget": meta.gadget,
        "filename": meta.filename,
        "script": script,
    }


# ---------------------------------------------------------------------------
# waf
# ---------------------------------------------------------------------------


def waf_catalog() -> dict[str, Any]:
    """WAF 技巧目录（选型）；详解 docs_get(slug='waf-bypass')。"""
    return {
        "ok": True,
        "techniques": [
            {"id": t.id, "title": t.title} for t in list_techniques()
        ],
        "doc": "waf-bypass",
    }


def waf_apply(
    payload: str,
    *,
    techniques: list[str] | None = None,
    mode: WafMode = "stack",
    options: dict[str, Any] | None = None,
) -> str | list[str] | dict[str, Any]:
    """对 payload 做本地 WAF 混淆（不发包）。成功时直接返回 payload；variants 返回 list。"""
    text = payload if isinstance(payload, str) else ""
    if not text.strip():
        return _err("payload 不能为空")

    mode = (mode or "stack").strip().lower()  # type: ignore[assignment]
    if mode not in ("stack", "variants"):
        return _err("mode 仅支持 stack 或 variants")

    waf_opts = None
    if options is not None:
        try:
            waf_opts = WafOptions.model_validate(options)
        except ValidationError as exc:
            return _err(f"options 无效: {exc}")

    try:
        result = run_waf(
            WafRequest(
                payload=text,
                techniques=list(techniques or []),
                mode=mode,
                options=waf_opts,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return _err(f"WAF 变换失败: {exc}")

    dumped = _dump(result) or {}
    if mode == "variants":
        variants = dumped.get("variants") or []
        payloads = [
            str(v.get("payload"))
            for v in variants
            if isinstance(v, dict) and v.get("payload")
        ]
        if not payloads:
            return _err("未生成任何变体")
        return payloads if len(payloads) > 1 else payloads[0]

    out = dumped.get("payload")
    if out is None or out == "":
        return _err("变换结果无 payload")
    return str(out)


# ---------------------------------------------------------------------------
# docs
# ---------------------------------------------------------------------------


def docs_list() -> dict[str, Any]:
    """文档一级目录：仅返回 top-level slug/title，不含 sections。"""
    try:
        items = list_docs()
    except FileNotFoundError as exc:
        return _err(str(exc))
    return {
        "ok": True,
        "docs": [{"slug": d.slug, "title": d.title} for d in items],
    }


def docs_get(slug: str) -> dict[str, Any]:
    """按 slug 取文档：父文档返回 sections；``父/章节`` 返回该段正文。"""
    try:
        data = get_doc_or_section(slug)
    except FileNotFoundError as exc:
        return _err(str(exc))
    return {"ok": True, **data}
