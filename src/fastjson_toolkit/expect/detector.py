"""Detect whether a Fastjson deserialization point has an expected class."""

from __future__ import annotations

from typing import Mapping, Optional
from urllib.parse import urlparse

from fastjson_toolkit.expect.models import ExpectClassResult, ExpectEvidence
from fastjson_toolkit.expect.probes import (
    DEFAULT_BASE_BODY,
    ExpectProbe,
    all_expect_probes,
    parse_base_body,
)
from fastjson_toolkit.http.client import HttpClient, HttpResponse

_ERROR_MARKERS = (
    "autoType is not support",
    "com.alibaba.fastjson.JSONException",
    "com.alibaba.fastjson2.JSONException",
    "syntax error",
    "type not match",
    "illegal character",
    "Illegal syntax",
    "can not cast",
    "deserialize",
    "parseException",
    "JSONException",
)


def _excerpt(text: str, limit: int = 400) -> str:
    text = (text or "").replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _resolve_url(target: str) -> str:
    parsed = urlparse(target)
    if not parsed.scheme:
        return "http://" + target
    return target


def response_errored(resp: HttpResponse) -> bool:
    if resp.status_code >= 400:
        return True
    text = resp.text or ""
    lower = text.lower()
    if any(m.lower() in lower for m in _ERROR_MARKERS):
        return True
    if '"error"' in lower and ("exception" in lower or "syntax" in lower):
        return True
    return False


class FastjsonExpectClassDetector:
    def __init__(
        self,
        timeout: float = 10.0,
        headers: Optional[Mapping[str, str]] = None,
        proxy: Optional[str] = None,
        verify_tls: bool = True,
        content_type: str = "application/json",
    ) -> None:
        self.client = HttpClient(
            timeout=timeout, headers=headers, proxy=proxy, verify=verify_tls
        )
        self.content_type = content_type

    def close(self) -> None:
        self.client.close()

    def detect(
        self,
        target: str,
        *,
        base_body: Optional[str] = None,
    ) -> ExpectClassResult:
        url = _resolve_url(target)
        body = (base_body or "").strip() or DEFAULT_BASE_BODY
        # Validate early for clear API errors.
        parse_base_body(body)

        notes = [
            "Feature 探针类自 1.2.68 引入；版本更低时也会因类不存在报错，需结合空键探针解读。",
            "空键根级探针报错且类型不是 Map/其子类时，倾向存在期望类。",
            "请尽量使用接近真实业务的原始请求参数作为 base_body。",
        ]
        methods: list[str] = []
        evidence: list[ExpectEvidence] = []
        flags: dict[str, Optional[bool]] = {}

        for probe in all_expect_probes(body):
            methods.append(probe.id)
            ev, errored = self._run_probe(url, probe)
            evidence.append(ev)
            flags[probe.id] = errored

        baseline_err = flags.get("baseline")
        feature_err = flags.get("feature_type")
        empty_err = flags.get("empty_key_root")
        nested_err = flags.get("empty_key_nested")

        has_expect, expect_not_map, lt68, confidence, interpretation = self._infer(
            baseline_err=baseline_err,
            feature_err=feature_err,
            empty_err=empty_err,
            nested_err=nested_err,
        )

        # Attach inference note onto last meaningful evidence via summary.
        summary, next_actions = self._build_summary(
            has_expect_class=has_expect,
            expect_not_map=expect_not_map,
            version_lt_1_2_68_hint=lt68,
            confidence=confidence,
            baseline_err=baseline_err,
            nested_err=nested_err,
            interpretation=interpretation,
        )

        return ExpectClassResult(
            target=target,
            has_expect_class=has_expect,
            expect_not_map=expect_not_map,
            version_lt_1_2_68_hint=lt68,
            confidence=round(confidence, 3),
            base_body=body,
            methods_used=methods,
            evidence=evidence,
            summary=summary,
            next_actions=next_actions,
            notes=notes,
            raw={
                "resolved_url": url,
                "flags": flags,
                "interpretation": interpretation,
                "probe_ids": [p.id for p in all_expect_probes(body)],
            },
        )

    def _run_probe(
        self, url: str, probe: ExpectProbe
    ) -> tuple[ExpectEvidence, Optional[bool]]:
        try:
            resp = self.client.post_raw(url, probe.payload, self.content_type)
        except Exception as exc:  # noqa: BLE001
            return (
                ExpectEvidence(
                    probe_id=probe.id,
                    category=probe.category,
                    description=probe.description,
                    payload=probe.payload,
                    matched=[f"request_error:{type(exc).__name__}"],
                    interpretation=str(exc),
                ),
                None,
            )
        errored = response_errored(resp)
        return (
            ExpectEvidence(
                probe_id=probe.id,
                category=probe.category,
                description=probe.description,
                payload=probe.payload,
                status_code=resp.status_code,
                elapsed_ms=round(resp.elapsed_ms, 2),
                errored=errored,
                matched=["errored"] if errored else ["ok"],
                response_excerpt=_excerpt(resp.text),
                interpretation="解析/运行异常" if errored else "未见异常",
            ),
            errored,
        )

    @staticmethod
    def _infer(
        *,
        baseline_err: Optional[bool],
        feature_err: Optional[bool],
        empty_err: Optional[bool],
        nested_err: Optional[bool],
    ) -> tuple[Optional[bool], Optional[bool], Optional[bool], float, str]:
        """Return (has_expect, expect_not_map, lt68_hint, confidence, interpretation)."""
        if None in (baseline_err, feature_err, empty_err, nested_err):
            return None, None, None, 0.0, "探针请求失败，无法判定"

        if baseline_err:
            return (
                None,
                None,
                None,
                0.2,
                "基线参数已报错，期望类信号不可信；请更换接近业务的合法 base_body",
            )

        # Nested control should usually succeed; if it fails, parser may reject empty-key syntax.
        if nested_err and empty_err:
            # Both empty-key forms fail → likely syntax rejected, not expect-class signal.
            if feature_err:
                return (
                    None,
                    None,
                    True,
                    0.45,
                    "空键语法均报错且 Feature 报错：可能版本 <1.2.68 或目标拒绝空键语法，期望类无法确认",
                )
            return (
                None,
                None,
                False,
                0.35,
                "空键语法均报错：目标可能拒绝该语法，期望类无法确认",
            )

        # Primary matrix (baseline ok):
        # feature_err + empty_err → has expect class (not Map)
        # feature_err + empty ok  → Feature missing → <1.2.68，无期望类（或 Map）
        # feature ok  + empty_err → has expect class (not Map)；Feature 可赋值/被忽略
        # feature ok  + empty ok  → 无期望类，或期望类型为 Map
        if feature_err and empty_err and not nested_err:
            return True, True, False, 0.9, "Feature 与根级空键均报错，嵌套对照正常 → 存在期望类且非 Map"
        if feature_err and not empty_err:
            return (
                False,
                False,
                True,
                0.8,
                "仅 Feature 报错而空键正常 → 倾向版本 <1.2.68（Feature 类不存在），未见期望类（或期望为 Map）",
            )
        if (not feature_err) and empty_err and not nested_err:
            return True, True, False, 0.75, "根级空键报错且嵌套对照正常 → 存在期望类且非 Map"
        if (not feature_err) and (not empty_err):
            return (
                False,
                False,
                False,
                0.85,
                "Feature 与空键均不报错 → 倾向无期望类，或期望类型为 Map/其子类",
            )

        # nested ok but empty not err, feature err already covered; leftover edge cases
        if empty_err and nested_err is False:
            return True, True, None, 0.7, "根级空键报错、嵌套对照正常 → 倾向存在期望类且非 Map"
        return None, None, None, 0.3, "探针结果组合无法归入已知矩阵"

    @staticmethod
    def _build_summary(
        *,
        has_expect_class: Optional[bool],
        expect_not_map: Optional[bool],
        version_lt_1_2_68_hint: Optional[bool],
        confidence: float,
        baseline_err: Optional[bool],
        nested_err: Optional[bool],
        interpretation: str,
    ) -> tuple[str, list[str]]:
        parts = [interpretation, f"置信度 {confidence:.2f}"]
        if has_expect_class is True:
            parts.insert(0, "判定存在期望类")
        elif has_expect_class is False:
            parts.insert(0, "判定不存在期望类（或期望为 Map）")
        else:
            parts.insert(0, "未能判定是否存在期望类")

        if expect_not_map is True:
            parts.append("期望类型不像 Map")
        if version_lt_1_2_68_hint is True:
            parts.append("版本可能 <1.2.68")
        if baseline_err:
            parts.append("基线异常")
        if nested_err:
            parts.append("嵌套空键对照也报错")

        next_actions: list[str] = []
        if has_expect_class is True:
            next_actions.append("存在期望类时优先评估 expectClass / 高版本利用面（需授权）")
            next_actions.append("可打开版本页确认是否 ≥1.2.68，避免 Feature 探针误判")
        elif has_expect_class is False and version_lt_1_2_68_hint:
            next_actions.append("Feature 类可能不存在：结合 /version 确认是否 <1.2.68")
            next_actions.append("无期望类时，AutoType 关闭场景下可继续依赖/版本侧信道")
        elif has_expect_class is False:
            next_actions.append("无期望类（或 Map）时，经典 @type gadget 面更大；请先确认 AutoType/SafeMode")
        else:
            next_actions.append("更换合法业务 base_body 后重测；确认端点会回显解析错误")
        if nested_err:
            next_actions.append("目标似乎拒绝空键语法，可仅参考 Feature 探针并人工复核")
        return "；".join(parts), next_actions
