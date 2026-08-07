"""Fastjson fingerprint detector."""

from __future__ import annotations

import json
import re
from typing import Any, Mapping, Optional
from urllib.parse import urljoin, urlparse, urlunparse

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

_COMMON_DESER_PATHS = (
    "/api/fastjson",
    "/json",
    "/api/json",
    "/fastjson",
)

_FJ_HINT_MARKERS = (
    "fastjson",
    "JSONException",
    "autoType",
    "autotype is not support",
    "syntax error",
    "not close json text",
)

# Cheap broken-JSON probe used only for path discovery.
_PATH_PROBE_PAYLOAD = '{"@type":"java.lang.AutoCloseable"'


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


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def _is_rootish_path(path: str) -> bool:
    p = (path or "").rstrip("/")
    return p in ("",) or p.endswith("/index.html") or p.endswith("/index.htm")


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

        resolved_url, path_meta = self._resolve_deser_target(target)
        if path_meta.get("resolved") and resolved_url != target:
            evidence.append(
                Evidence(
                    probe_id="path_discovery",
                    category="path",
                    description="根路径/非反序列化点 → 自动发现候选端点",
                    matched=path_meta.get("tried") or [],
                    score_delta=0.0,
                    response_excerpt=_excerpt(
                        json.dumps(path_meta.get("health") or {}, ensure_ascii=False)
                    ),
                    payload=resolved_url,
                )
            )

        try:
            base_url = _resolve_url(resolved_url, prefer_typed=False)
            base_resp = self.client.post_raw(
                base_url, baseline_timing_payload(), self.content_type
            )
            baseline_ms = base_resp.elapsed_ms
        except Exception:
            baseline_ms = None

        for probe in probes:
            url = _resolve_url(resolved_url, prefer_typed=probe.prefer_typed)
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
            path_meta=path_meta,
            original_target=target,
            resolved_url=resolved_url,
        )

        return DetectResult(
            target=resolved_url,
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
                "original_target": target,
                "resolved_url": resolved_url,
                "path_discovery": path_meta,
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

    def _resolve_deser_target(self, target: str) -> tuple[str, dict[str, Any]]:
        """If target looks like a site root, try /api/health + common deser paths."""
        raw = (target or "").strip()
        if not raw:
            return raw, {"resolved": False}
        if "://" not in raw:
            raw = "http://" + raw
        parsed = urlparse(raw)
        meta: dict[str, Any] = {
            "resolved": False,
            "original": raw,
            "tried": [],
            "health": None,
        }
        if not _is_rootish_path(parsed.path):
            return raw, meta

        origin = _origin(raw)
        candidates: list[str] = []
        health_url = urljoin(origin + "/", "api/health")
        try:
            health_resp = self.client.get_raw(health_url)
            if health_resp.status_code == 200 and health_resp.text:
                try:
                    health_obj = json.loads(health_resp.text)
                except json.JSONDecodeError:
                    health_obj = None
                if isinstance(health_obj, dict):
                    meta["health"] = health_obj
                    endpoints = health_obj.get("endpoints") or []
                    if isinstance(endpoints, list):
                        for ep in endpoints:
                            if not isinstance(ep, str):
                                continue
                            path = ep.strip()
                            if not path.startswith("/"):
                                path = "/" + path
                            # Prefer real deser points; skip health/markers/attack assets
                            low = path.lower()
                            if any(
                                x in low
                                for x in (
                                    "health",
                                    "marker",
                                    "attack",
                                    "reset",
                                    "silent",
                                )
                            ):
                                continue
                            candidates.append(urljoin(origin + "/", path.lstrip("/")))
                else:
                    meta["health"] = {"raw": _excerpt(health_resp.text, 200)}
        except Exception as exc:  # noqa: BLE001
            meta["health_error"] = f"{type(exc).__name__}: {exc}"

        for path in _COMMON_DESER_PATHS:
            candidates.append(urljoin(origin + "/", path.lstrip("/")))

        # Prefer the original root URL (vulhub etc. deserialize on `/`)
        root_url = origin + "/"
        candidates.insert(0, root_url)

        # Dedupe preserve order
        seen: set[str] = set()
        ordered: list[str] = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                ordered.append(c)

        best: Optional[str] = None
        best_score = -1
        for cand in ordered:
            meta["tried"].append(cand)
            try:
                resp = self.client.post_raw(
                    cand, _PATH_PROBE_PAYLOAD, self.content_type
                )
            except Exception:
                continue
            if resp.status_code == 404:
                continue
            text = resp.text or ""
            score = 0
            if any(m.lower() in text.lower() for m in _FJ_HINT_MARKERS):
                score += 3
            if resp.status_code >= 400:
                score += 1
            if resp.status_code == 200 and text.strip() not in ("", "{}"):
                score += 1
            if score > best_score:
                best_score = score
                best = cand
            if score >= 3:
                break

        if best and best_score > 0:
            meta["resolved"] = True
            meta["resolved_url"] = best
            meta["score"] = best_score
            return best, meta

        # Keep the original root rather than a known-404 common path
        meta["resolved"] = False
        meta["resolved_url"] = raw
        return raw, meta

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
        path_meta: Optional[dict[str, Any]] = None,
        original_target: str = "",
        resolved_url: str = "",
    ) -> tuple[str, list[str]]:
        path_meta = path_meta or {}
        if is_fastjson:
            parts = [f"判定为 Fastjson（置信度 {confidence:.2f}，强特征 {strong_fj_hits}）"]
            if path_meta.get("resolved") and original_target and resolved_url != original_target:
                parts.append(f"已将探测点解析为 {resolved_url}")
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
                "继续使用当前 target 跑 deps_probe（自动校准 Character/Class）",
                "poc_catalog 按版本选 family；AutoType 关时 poc_get(expect_bypass=true)",
                "docs_list → docs_get 查阅对应版本分析",
            ]
            if autotype_disabled is True:
                next_actions.insert(
                    1,
                    "AutoType 关闭：优先 expectClass / 1.2.68 AutoCloseable / 1.2.80 Exception 链",
                )
            return "；".join(parts), next_actions

        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        top_name, top_score = ranked[0]
        summary = (
            f"未达到 Fastjson 判定阈值（强特征 {strong_fj_hits}）；"
            f"当前更像 {top_name}（score={top_score:.2f}），主猜测={primary_guess.value}"
        )
        if path_meta.get("health") and isinstance(path_meta["health"], dict):
            eps = path_meta["health"].get("endpoints")
            if eps:
                summary += f"；health 列出 endpoints={eps}（根路径 404≠无 Fastjson）"
        if dns_confirmed is False:
            summary += "；CEYE 无 DNS 记录"
        next_actions = [
            "确认 target 为 JSON 反序列化 POST 点（如 /api/fastjson），不要只用站点根路径",
            "可先 GET /api/health 查看 endpoints，再 detect_pipeline(target=完整反序列化 URL)",
            "尝试调整 Content-Type / 参数位置（body/query/header）",
        ]
        if path_meta.get("tried"):
            next_actions.insert(
                1,
                f"已尝试候选：{', '.join(path_meta['tried'][:6])}；请改用明确反序列化 URL 重试",
            )
        return summary, next_actions
