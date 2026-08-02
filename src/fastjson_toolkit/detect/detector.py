"""Fastjson fingerprint detector."""

from __future__ import annotations

import re
from typing import Mapping, Optional
from urllib.parse import urljoin, urlparse

from fastjson_toolkit.detect.models import DetectResult, Evidence, LibraryGuess
from fastjson_toolkit.detect.probes import Probe, all_probes, baseline_timing_payload
from fastjson_toolkit.dnslog import CeyeClient, CeyeConfig
from fastjson_toolkit.http.client import HttpClient, HttpResponse

# Only these probe outcomes can establish Fastjson identity.
_STRONG_FJ_PROBES = frozenset({
    "error_broken_json",
    "error_autotype",
    "parse_features",
    "parse_ref",
})


def _excerpt(text: str, limit: int = 400) -> str:
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _contains_any(text: str, needles: tuple[str, ...]) -> list[str]:
    hit: list[str] = []
    lower = text.lower()
    for n in needles:
        if n.lower() in lower:
            hit.append(n)
    return hit


def _resolve_url(target: str, prefer_typed: bool) -> str:
    parsed = urlparse(target)
    if not parsed.scheme:
        target = "http://" + target
        parsed = urlparse(target)

    path = parsed.path.rstrip("/")
    if prefer_typed:
        if path.endswith("/person"):
            return target
        if re.search(r"/api/(fastjson|jackson)$", path):
            return target.rstrip("/") + "/person"
        if path in ("", "/"):
            return urljoin(target if target.endswith("/") else target + "/", "api/fastjson/person")
    return target


class FastjsonDetector:
    def __init__(
        self,
        timeout: float = 10.0,
        headers: Optional[Mapping[str, str]] = None,
        proxy: Optional[str] = None,
        verify_tls: bool = True,
        dnslog_host: Optional[str] = None,
        ceye: Optional[CeyeConfig] = None,
        ceye_wait: float = 8.0,
        timing_threshold_ms: float = 800.0,
        content_type: str = "application/json",
    ) -> None:
        self.client = HttpClient(timeout=timeout, headers=headers, proxy=proxy, verify=verify_tls)
        self.dnslog_host = dnslog_host
        self.ceye_config = ceye
        self.ceye_wait = ceye_wait
        self.timing_threshold_ms = timing_threshold_ms
        self.content_type = content_type
        self._ceye: Optional[CeyeClient] = CeyeClient(ceye) if ceye else None

    def detect(self, target: str, include_dns: bool = True) -> DetectResult:
        dns_filter: Optional[str] = None
        dns_host: Optional[str] = None

        if include_dns and self._ceye is not None:
            dns_filter = CeyeClient.new_filter("fj")
            dns_host = self._ceye.build_host(dns_filter)
        elif include_dns and self.dnslog_host:
            dns_host = self.dnslog_host

        probes = all_probes(dns_host)

        scores: dict[str, float] = {
            LibraryGuess.FASTJSON.value: 0.0,
            LibraryGuess.JACKSON.value: 0.0,
            LibraryGuess.GSON.value: 0.0,
            LibraryGuess.ORG_JSON.value: 0.0,
            LibraryGuess.HUTOOL.value: 0.0,
        }
        evidence: list[Evidence] = []
        autotype_disabled: Optional[bool] = None
        dns_timing_suspicious: Optional[bool] = None
        dns_confirmed: Optional[bool] = None
        dns_records: list[dict] = []
        baseline_ms: Optional[float] = None
        dns_probe_ms: Optional[float] = None
        strong_fj_hits = 0
        sent_dns_probe = False

        try:
            base_url = _resolve_url(target, prefer_typed=False)
            base_resp = self.client.post_raw(base_url, baseline_timing_payload(), self.content_type)
            baseline_ms = base_resp.elapsed_ms
        except Exception:
            baseline_ms = None

        for probe in probes:
            url = _resolve_url(target, prefer_typed=probe.prefer_typed)
            try:
                resp = self.client.post_raw(url, probe.payload, self.content_type)
            except Exception as exc:
                evidence.append(
                    Evidence(
                        probe_id=probe.id,
                        category=probe.category,
                        description=probe.description,
                        matched=[f"request_error:{type(exc).__name__}"],
                        score_delta=0.0,
                        response_excerpt=str(exc),
                        payload=probe.payload,
                    )
                )
                continue

            ev, strong = self._score_probe(probe, resp, scores)
            evidence.append(ev)
            if strong:
                strong_fj_hits += 1

            if probe.id == "error_autotype":
                body = resp.text
                if "autoType is not support" in body:
                    autotype_disabled = True
                elif "com.alibaba.fastjson" in body:
                    autotype_disabled = False

            if probe.dns_related:
                sent_dns_probe = True
                if baseline_ms is not None:
                    dns_probe_ms = max(dns_probe_ms or 0.0, resp.elapsed_ms)
                    delta = resp.elapsed_ms - baseline_ms
                    if delta >= self.timing_threshold_ms:
                        dns_timing_suspicious = True
                        scores[LibraryGuess.FASTJSON.value] += 0.5
                        evidence.append(
                            Evidence(
                                probe_id=f"{probe.id}_timing",
                                category="dns_timing",
                                description="DNS/network side-channel via response delay",
                                matched=[f"delta_ms={delta:.1f}", f"threshold_ms={self.timing_threshold_ms}"],
                                score_delta=0.5,
                                library_hint=LibraryGuess.FASTJSON.value,
                                status_code=resp.status_code,
                                elapsed_ms=resp.elapsed_ms,
                                response_excerpt=_excerpt(resp.text),
                                payload=probe.payload,
                            )
                        )

        # Poll CEYE after DNS payloads are delivered.
        if sent_dns_probe and self._ceye is not None and dns_filter:
            try:
                records = self._ceye.wait_for_dns(dns_filter, timeout=self.ceye_wait, interval=1.0)
                dns_records = [
                    {
                        "name": r.name,
                        "remote_addr": r.remote_addr,
                        "created_at": r.created_at,
                    }
                    for r in records
                ]
                dns_confirmed = len(records) > 0
                if dns_confirmed:
                    scores[LibraryGuess.FASTJSON.value] += 3.0
                    strong_fj_hits += 1
                    evidence.append(
                        Evidence(
                            probe_id="ceye_dns_confirm",
                            category="dns",
                            description="CEYE DNSLog confirmed outbound DNS",
                            matched=[r.name for r in records[:5]],
                            score_delta=3.0,
                            library_hint=LibraryGuess.FASTJSON.value,
                            response_excerpt=f"filter={dns_filter}; hits={len(records)}",
                            payload=dns_host or "",
                        )
                    )
                else:
                    evidence.append(
                        Evidence(
                            probe_id="ceye_dns_confirm",
                            category="dns",
                            description="CEYE DNSLog polled, no record yet",
                            matched=[],
                            score_delta=0.0,
                            response_excerpt=f"filter={dns_filter}; wait={self.ceye_wait}s",
                            payload=dns_host or "",
                        )
                    )
            except Exception as exc:
                evidence.append(
                    Evidence(
                        probe_id="ceye_dns_confirm",
                        category="dns",
                        description="CEYE DNSLog query failed",
                        matched=[f"error:{type(exc).__name__}"],
                        score_delta=0.0,
                        response_excerpt=str(exc),
                        payload=dns_host or "",
                    )
                )
                dns_confirmed = False

        primary = max(scores.items(), key=lambda kv: kv[1])
        primary_guess = LibraryGuess(primary[0]) if primary[1] > 0 else LibraryGuess.UNKNOWN
        fj_score = scores[LibraryGuess.FASTJSON.value]
        second = sorted(scores.values(), reverse=True)[1] if len(scores) > 1 else 0.0
        margin = fj_score - second
        confidence = 0.0
        if strong_fj_hits:
            confidence = max(
                0.0,
                min(0.99, 0.35 * strong_fj_hits + min(fj_score, 12.0) / 16.0 + min(margin, 4.0) / 10.0),
            )

        is_fastjson = strong_fj_hits >= 1 and fj_score >= 2.0 and (
            primary_guess == LibraryGuess.FASTJSON or margin >= 1.0 or dns_confirmed is True
        )
        if is_fastjson:
            primary_guess = LibraryGuess.FASTJSON
            confidence = max(confidence, 0.55)
            if dns_confirmed:
                confidence = max(confidence, 0.9)
        elif primary[1] > 0:
            primary_guess = LibraryGuess(primary[0])
            confidence = 0.0

        summary, next_actions = self._build_summary(
            is_fastjson=is_fastjson,
            confidence=confidence,
            primary_guess=primary_guess,
            autotype_disabled=autotype_disabled,
            dns_timing_suspicious=dns_timing_suspicious,
            dns_confirmed=dns_confirmed,
            scores=scores,
            strong_fj_hits=strong_fj_hits,
        )

        return DetectResult(
            target=target,
            is_fastjson=is_fastjson,
            confidence=round(confidence, 3),
            autotype_disabled_hint=autotype_disabled,
            primary_guess=primary_guess,
            scores={k: round(v, 3) for k, v in scores.items()},
            evidence=evidence,
            dns_timing_suspicious=dns_timing_suspicious,
            dns_confirmed=dns_confirmed,
            dns_filter=dns_filter,
            dns_records=dns_records,
            baseline_ms=baseline_ms,
            dns_probe_ms=dns_probe_ms,
            summary=summary,
            next_actions=next_actions,
            raw={
                "probe_count": len(probes),
                "dnslog_host": dns_host,
                "strong_fj_hits": strong_fj_hits,
                "ceye_domain": self.ceye_config.domain if self.ceye_config else None,
            },
        )

    def close(self) -> None:
        self.client.close()
        if self._ceye is not None:
            self._ceye.close()

    def _score_probe(
        self, probe: Probe, resp: HttpResponse, scores: dict[str, float]
    ) -> tuple[Evidence, bool]:
        text = resp.text
        matched: list[str] = []
        score_delta = 0.0
        library_hint: Optional[str] = None
        strong = False

        if not probe.non_exclusive and probe.expect_fastjson:
            matched_fj = _contains_any(text, probe.expect_fastjson)
            if matched_fj:
                if probe.id == "parse_features":
                    markers = _contains_any(text, ('"a":1', '"b":"EQ=="', '"c":[{}]'))
                    if len(markers) >= 2 and resp.status_code == 200:
                        delta = probe.weight + 1.5
                        scores[LibraryGuess.FASTJSON.value] += delta
                        score_delta += delta
                        matched.extend(markers)
                        library_hint = LibraryGuess.FASTJSON.value
                        strong = True
                else:
                    delta = probe.weight * (0.8 + 0.15 * len(matched_fj))
                    scores[LibraryGuess.FASTJSON.value] += delta
                    score_delta += delta
                    matched.extend(matched_fj)
                    library_hint = LibraryGuess.FASTJSON.value
                    if probe.id in _STRONG_FJ_PROBES:
                        strong = True

        if probe.id == "parse_ref" and resp.status_code == 200:
            compact = text.replace(" ", "")
            if '"name":"blue"' in compact and "$ref" not in compact:
                delta = probe.weight + 1.5
                scores[LibraryGuess.FASTJSON.value] += delta
                score_delta += delta
                matched.append('"name":"blue"')
                library_hint = LibraryGuess.FASTJSON.value
                strong = True

        for lib, needles in probe.expect_other.items():
            hits = _contains_any(text, needles)
            if not hits:
                continue
            if probe.id == "diff_gson_hash_comment" and lib == "gson" and resp.status_code != 200:
                continue
            if probe.id == "diff_hutool_permissive" and lib == "hutool" and resp.status_code != 200:
                continue
            if probe.id == "diff_jackson_precision" and lib == "jackson":
                if "20.111111111111111111111111111" in text:
                    continue
            matched.extend([f"{lib}:{h}" for h in hits])
            delta = probe.weight * 0.9
            if lib == "fastjson":
                scores[LibraryGuess.FASTJSON.value] += delta * 0.3
                score_delta += delta * 0.3
                if library_hint is None:
                    library_hint = LibraryGuess.FASTJSON.value
            else:
                scores[lib] = scores.get(lib, 0.0) + delta
                score_delta += delta
                if library_hint is None:
                    library_hint = lib

        if probe.id == "diff_jackson_extra_field" and resp.status_code == 200 and "Bob" in text:
            scores[LibraryGuess.JACKSON.value] = max(0.0, scores[LibraryGuess.JACKSON.value] - 0.3)

        if probe.id == "diff_jackson_single_quote" and resp.status_code == 200 and "Bob" in text:
            scores[LibraryGuess.JACKSON.value] = max(0.0, scores[LibraryGuess.JACKSON.value] - 0.3)

        return (
            Evidence(
                probe_id=probe.id,
                category=probe.category,
                description=probe.description,
                matched=matched,
                score_delta=round(score_delta, 3),
                library_hint=library_hint,
                status_code=resp.status_code,
                elapsed_ms=round(resp.elapsed_ms, 2),
                response_excerpt=_excerpt(text),
                payload=probe.payload,
            ),
            strong,
        )

    def _build_summary(
        self,
        is_fastjson: bool,
        confidence: float,
        primary_guess: LibraryGuess,
        autotype_disabled: Optional[bool],
        dns_timing_suspicious: Optional[bool],
        dns_confirmed: Optional[bool],
        scores: dict[str, float],
        strong_fj_hits: int,
    ) -> tuple[str, list[str]]:
        if is_fastjson:
            parts = [f"判定为 Fastjson（置信度 {confidence:.2f}，强特征 {strong_fj_hits}）"]
            if autotype_disabled is True:
                parts.append("响应提示 autoType 未开启")
            elif autotype_disabled is False:
                parts.append("存在 Fastjson 异常特征，autoType 状态未明确禁用")
            if dns_confirmed is True:
                parts.append("CEYE DNSLog 已确认出网解析")
            elif dns_confirmed is False:
                parts.append("CEYE DNSLog 未收到记录（可能未出网或 autoType 未触发）")
            if dns_timing_suspicious:
                parts.append("DNS 探针耗时明显增加")
            next_actions = [
                "打开版本识别页 /version，收敛版本区间",
                "若 autoType 关闭，优先考虑 expect/其它绕过链",
                "可对 /api/fastjson/autotype 类开启点复测 DNSLog",
            ]
            return "；".join(parts), next_actions

        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        top_name, top_score = ranked[0]
        summary = (
            f"未达到 Fastjson 判定阈值（强特征 {strong_fj_hits}）；"
            f"当前更像 {top_name}（score={top_score:.2f}），主猜测={primary_guess.value}"
        )
        if dns_confirmed is False:
            summary += "；CEYE 无 DNS 记录"
        next_actions = [
            "确认请求是否真正打到 JSON 反序列化点",
            "尝试调整 Content-Type / 参数位置（body/query/header）",
            "对照 jackson/gson/org.json/hutool 特征探针结果",
        ]
        return summary, next_actions
