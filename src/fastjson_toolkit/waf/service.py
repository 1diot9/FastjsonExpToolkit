"""WAF 绕过编排。"""

from __future__ import annotations

from typing import Iterable, Optional

from fastjson_toolkit.waf.models import WafOptions, WafRequest, WafResult, WafVariant
from fastjson_toolkit.waf.transforms import (
    apply_stack,
    apply_technique,
    get_technique,
    list_techniques,
)


def apply_waf_payload(
    payload: str,
    techniques: Optional[Iterable[str]] = None,
    options: Optional[WafOptions] = None,
) -> tuple[str, list[str], list[str]]:
    """对单条 payload 按顺序叠加 WAF 变换。

    Returns:
        (transformed_payload, applied_technique_ids, notes)
        techniques 为空时原样返回。
    """
    techs = [t.strip() for t in (techniques or []) if t and str(t).strip()]
    if not techs:
        return payload, [], []
    opts = options or WafOptions()
    for tid in techs:
        if get_technique(tid) is None:
            known = ", ".join(t.id for t in list_techniques())
            raise ValueError(f"未知 waf technique: {tid}；可选: {known}")
    out = apply_stack(payload, techs, opts)
    notes = [f"已叠加 WAF: {' → '.join(techs)}"]
    for tid in techs:
        info = get_technique(tid)
        if info:
            notes.extend(info.notes)
    return out, techs, notes


def apply_waf_payloads(
    payloads: list[str],
    techniques: Optional[Iterable[str]] = None,
    options: Optional[WafOptions] = None,
) -> tuple[list[str], list[str], list[str]]:
    """对多步 payload 逐步叠加同一组 WAF 变换。"""
    techs = [t.strip() for t in (techniques or []) if t and str(t).strip()]
    if not techs or not payloads:
        return list(payloads), [], []
    opts = options or WafOptions()
    applied: list[str] = []
    notes: list[str] = []
    out: list[str] = []
    for i, p in enumerate(payloads):
        transformed, used, n = apply_waf_payload(p, techs, opts)
        out.append(transformed)
        if i == 0:
            applied = used
            notes = n
    return out, applied, notes


def run_waf(req: WafRequest) -> WafResult:
    payload = (req.payload or "").strip()
    if not payload:
        raise ValueError("payload 不能为空")

    opts = req.options or WafOptions()
    mode = (req.mode or "stack").strip().lower()
    if mode not in ("stack", "variants"):
        raise ValueError("mode 仅支持 stack 或 variants")

    all_ids = [t.id for t in list_techniques()]
    techniques = [t.strip() for t in (req.techniques or []) if t and t.strip()]

    notes: list[str] = [
        "变换产物面向 Fastjson 解析器，不一定是标准 JSON。",
        "仅用于授权测试 / 本地靶场。",
    ]

    if mode == "variants" or not techniques:
        ids = techniques or all_ids
        variants: list[WafVariant] = []
        for tid in ids:
            info = get_technique(tid)
            if info is None:
                raise ValueError(f"未知 technique: {tid}")
            transformed = apply_technique(payload, tid, opts)
            variants.append(
                WafVariant(
                    technique=tid,
                    title=info.title,
                    payload=transformed,
                    description=info.description,
                )
            )
            notes.extend(info.notes)
        # variants 模式下 payload 取第一项，便于一键复制
        first = variants[0].payload if variants else payload
        summary = f"已生成 {len(variants)} 种 WAF 绕过变体"
        return WafResult(
            original=payload,
            payload=first,
            techniques=[v.technique for v in variants],
            variants=variants,
            notes=_uniq(notes),
            summary=summary,
        )

    # stack
    for tid in techniques:
        if get_technique(tid) is None:
            raise ValueError(f"未知 technique: {tid}")
    stacked = apply_stack(payload, techniques, opts)
    titles = []
    for tid in techniques:
        info = get_technique(tid)
        assert info is not None
        titles.append(info.title)
        notes.extend(info.notes)
    summary = "已叠加: " + " → ".join(titles)
    return WafResult(
        original=payload,
        payload=stacked,
        techniques=list(techniques),
        variants=[
            WafVariant(
                technique="+".join(techniques),
                title=summary,
                payload=stacked,
                description="按顺序叠加变换",
            )
        ],
        notes=_uniq(notes),
        summary=summary,
    )


def _uniq(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out
