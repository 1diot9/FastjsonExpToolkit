"""Fastjson version detector."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import urlparse

from fastjson_toolkit.dnslog import CeyeClient, CeyeConfig
from fastjson_toolkit.http.client import HttpClient, HttpResponse
from fastjson_toolkit.version.models import VersionEvidence, VersionResult
from fastjson_toolkit.version.probes import (
    AUTOCLOSEABLE_EXACT,
    AUTOTYPE_CLASS,
    AUTOTYPE_RANDOM,
    BASELINE_OK,
    NEGATIVE_CONTROL,
    OFFLINE_AUTOCLOSEABLE,
    OFFLINE_CLASS_JDBC,
    OFFLINE_EXCEPTION,
    OFFLINE_JDBC,
    PROBE_1_2_83,
    SAFEMODE_STRING,
    VersionProbe,
    all_version_probes,
    build_dns_version_probes,
    validate_dns_host,
)

_VERSION_RE = re.compile(r"fastjson-version\s+(\d+\.\d+(?:\.\d+)?)", re.I)
_ERROR_MARKERS = (
    "autoType is not support",
    "com.alibaba.fastjson.JSONException",
    "com.alibaba.fastjson2.JSONException",
    "syntax error",
    "type not match",
    "illegal character",
    "Illegal syntax",
)

# Explicit SafeMode refusal (stronger than generic parse errors).
_SAFEMODE_MARKERS = (
    "safeMode not support autoType",
    "safemode not support autotype",
)

_OPAQUE_OK_FALSE_RE = re.compile(r'^\s*\{\s*"ok"\s*:\s*false\s*\}\s*$', re.I)
_OPAQUE_ERROR_OBJ_RE = re.compile(r'^\s*\{\s*"error"\s*:', re.I)


@dataclass(frozen=True)
class ResponseSig:
    """Fingerprint for opaque 500 / bare-error handlers."""

    status_code: int
    body: str


def _excerpt(text: str, limit: int = 400) -> str:
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _resolve_url(target: str) -> str:
    """Normalize scheme only; do not rewrite empty paths (align with detect)."""
    parsed = urlparse(target)
    if not parsed.scheme:
        return "http://" + target
    return target


def response_sig(resp: HttpResponse, *, body_limit: int = 300) -> ResponseSig:
    return ResponseSig(resp.status_code, (resp.text or "").strip()[:body_limit])


def response_errored(
    resp: HttpResponse,
    *,
    error_sig: Optional[ResponseSig] = None,
) -> bool:
    """Judge whether the target treated the payload as a parse/runtime error.

    Covers stack-trace echo, HTTP >=400, and production opaque handlers
    (bare ``error`` / ``{"ok":false}`` / same fingerprint as negative control).
    """
    if resp.status_code >= 400:
        return True
    text = resp.text or ""
    lower = text.lower()
    if any(m.lower() in lower for m in _ERROR_MARKERS):
        return True
    stripped = text.strip()
    stripped_l = stripped.lower()
    if stripped_l in {"error", '"error"', "'error'"}:
        return True
    if _OPAQUE_OK_FALSE_RE.match(stripped):
        return True
    if _OPAQUE_ERROR_OBJ_RE.match(stripped) and (
        len(stripped) < 200 or "exception" in lower or "syntax" in lower
    ):
        return True
    if '"error"' in lower and ("exception" in lower or "syntax" in lower):
        return True
    if error_sig is not None and response_sig(resp) == error_sig:
        return True
    return False


class FastjsonVersionDetector:
    def __init__(
        self,
        timeout: float = 10.0,
        headers: Optional[Mapping[str, str]] = None,
        proxy: Optional[str] = None,
        verify_tls: bool = True,
        dnslog_host: Optional[str] = None,
        ceye: Optional[CeyeConfig] = None,
        ceye_wait: float = 10.0,
        content_type: str = "application/json",
    ) -> None:
        self.client = HttpClient(timeout=timeout, headers=headers, proxy=proxy, verify=verify_tls)
        self.dnslog_host = dnslog_host
        self.ceye_config = ceye
        self.ceye_wait = ceye_wait
        self.content_type = content_type
        self._ceye: Optional[CeyeClient] = CeyeClient(ceye) if ceye else None
        self._error_sig: Optional[ResponseSig] = None

    def close(self) -> None:
        self.client.close()
        if self._ceye is not None:
            self._ceye.close()

    def detect(self, target: str, include_dns: bool = True) -> VersionResult:
        url = _resolve_url(target)
        evidence: list[VersionEvidence] = []
        methods: list[str] = []
        dns_filter: Optional[str] = None
        dns_hosts: dict[str, str] = {}
        dns_records: list[dict] = []
        dns_hits: dict[str, bool] = {}
        self._error_sig = None

        dns_skip_reason: Optional[str] = None
        if include_dns and self._ceye is not None:
            dns_filter = CeyeClient.new_filter("ver")
            # Suffix keeps records distinguishable while filter prefix still matches.
            for tag, suffix in (("le47", "47"), ("le68", "68"), ("d80a", "8a"), ("d80b", "8b")):
                dns_hosts[tag] = self._ceye.build_host(dns_filter, tag=suffix)
        elif include_dns and self.dnslog_host:
            try:
                base = validate_dns_host(self.dnslog_host)
            except ValueError as exc:
                dns_skip_reason = str(exc)
            else:
                for tag in ("le47", "le68", "d80a", "d80b"):
                    dns_hosts[tag] = f"{tag}.{base}"
        elif include_dns:
            dns_skip_reason = "已请求 DNS 探针，但未配置 CEYE Token 且未提供 dnslog"

        methods.append("control")
        error_surface = self._probe_error_surface(url, evidence)

        methods.append("autotype")
        autotype_enabled = self._probe_autotype(url, evidence)

        methods.append("safemode")
        # 笔记：String""" 探针仅在有报错回显时有意义；报错≠必然 SafeMode
        safemode_enabled = self._probe_safemode(
            url, evidence, error_surface=error_surface
        )

        methods.append("autoclosable_exact")
        reported_version, reported_note = self._probe_exact(url, evidence)

        methods.append("probe_1_2_83")
        is_83 = self._probe_1_2_83(url, evidence)

        methods.append("offline")
        offline_flags = self._run_offline(url, evidence)

        version_range, version_detail, confidence = self._infer_band(
            reported_version=reported_version,
            is_83=is_83,
            offline=offline_flags,
            error_surface=error_surface,
            autotype_enabled=autotype_enabled,
            dns_hits=None,
        )

        safemode_enabled = self._crosscheck_safemode(
            safemode_enabled,
            offline_flags=offline_flags,
            reported_version=reported_version,
            autotype_enabled=autotype_enabled,
            error_surface=error_surface,
            version_range=version_range,
            evidence=evidence,
        )

        if dns_skip_reason:
            evidence.append(
                VersionEvidence(
                    probe_id="dns_skipped",
                    category="dns",
                    description="DNS 版本探针未发送",
                    matched=[],
                    interpretation=dns_skip_reason,
                )
            )

        if dns_hosts:
            methods.append("dns")
            for probe in build_dns_version_probes(dns_hosts):
                evidence.append(self._send_evidence(url, probe))

            if self._ceye is not None and dns_filter:
                try:
                    # Settle full wait so late second DNS (1.2.83) is not missed.
                    records = self._ceye.wait_for_dns(
                        dns_filter,
                        timeout=self.ceye_wait,
                        interval=1.0,
                        settle=True,
                    )
                    dns_records = [
                        {
                            "name": r.name,
                            "remote_addr": r.remote_addr,
                            "created_at": r.created_at,
                        }
                        for r in records
                    ]
                    dns_hits = self._match_dns_hits(dns_hosts, records)
                    version_range, version_detail, confidence = self._infer_band(
                        reported_version=reported_version,
                        is_83=is_83,
                        offline=offline_flags,
                        error_surface=error_surface,
                        autotype_enabled=autotype_enabled,
                        dns_hits=dns_hits,
                    )
                    dns_range = version_range
                    if any(dns_hits.values()):
                        evidence.append(
                            VersionEvidence(
                                probe_id="ceye_dns_version",
                                category="dns",
                                description="CEYE DNSLog 版本侧信道汇总",
                                matched=[k for k, v in dns_hits.items() if v],
                                interpretation=f"band={dns_range}",
                                response_excerpt=f"filter={dns_filter}; hits={dns_hits}",
                                payload=",".join(dns_hosts.values()),
                            )
                        )
                    else:
                        evidence.append(
                            VersionEvidence(
                                probe_id="ceye_dns_version",
                                category="dns",
                                description="CEYE DNSLog 无版本相关记录",
                                matched=[],
                                interpretation="无 DNS 命中（可能未出网 / AutoType 未触发）",
                                response_excerpt=f"filter={dns_filter}; wait={self.ceye_wait}s",
                                payload=",".join(dns_hosts.values()),
                            )
                        )
                except Exception as exc:  # noqa: BLE001
                    evidence.append(
                        VersionEvidence(
                            probe_id="ceye_dns_version",
                            category="dns",
                            description="CEYE DNSLog 查询失败",
                            matched=[f"error:{type(exc).__name__}"],
                            interpretation=str(exc),
                            payload=",".join(dns_hosts.values()),
                        )
                    )
            else:
                evidence.append(
                    VersionEvidence(
                        probe_id="dns_manual",
                        category="dns",
                        description="已发送 DNS 版本探针（未配置 CEYE，请人工查看 DNSLog）",
                        matched=list(dns_hosts.keys()),
                        interpretation="手动核对 le47/le68/d80a/d80b 子域解析",
                        payload=",".join(f"{k}={v}" for k, v in dns_hosts.items()),
                    )
                )

        version_range = self.normalize_band(version_range) or version_range

        summary, next_actions = self._build_summary(
            autotype_enabled=autotype_enabled,
            safemode_enabled=safemode_enabled,
            reported_version=reported_version,
            reported_note=reported_note,
            is_83=is_83,
            version_range=version_range,
            version_detail=version_detail,
            confidence=confidence,
            dns_hits=dns_hits,
            error_surface=error_surface,
            dns_skip_reason=dns_skip_reason,
        )

        return VersionResult(
            target=target,
            autotype_enabled=autotype_enabled,
            safemode_enabled=safemode_enabled,
            reported_version=reported_version,
            reported_version_note=reported_note,
            is_1_2_83_hint=is_83,
            version_range=version_range,
            version_detail=version_detail,
            confidence=round(confidence, 3),
            methods_used=methods,
            evidence=evidence,
            dns_filter=dns_filter,
            dns_records=dns_records,
            dns_hits=dns_hits,
            summary=summary,
            next_actions=next_actions,
            raw={
                "resolved_url": url,
                "dns_hosts": dns_hosts,
                "offline_flags": offline_flags,
                "error_surface": error_surface,
                "error_sig": (
                    {"status_code": self._error_sig.status_code, "body": self._error_sig.body}
                    if self._error_sig
                    else None
                ),
                "dns_skip_reason": dns_skip_reason,
                "ceye_domain": self.ceye_config.domain if self.ceye_config else None,
                "probe_ids": [p.id for p in all_version_probes(dns_hosts or None)],
            },
        )

    def _errored(self, resp: HttpResponse) -> bool:
        return response_errored(resp, error_sig=self._error_sig)

    def _send(self, url: str, probe: VersionProbe) -> HttpResponse:
        return self.client.post_raw(url, probe.payload, self.content_type)

    def _send_evidence(self, url: str, probe: VersionProbe) -> VersionEvidence:
        try:
            resp = self._send(url, probe)
        except Exception as exc:  # noqa: BLE001
            return VersionEvidence(
                probe_id=probe.id,
                category=probe.category,
                description=probe.description,
                payload=probe.payload,
                matched=[f"request_error:{type(exc).__name__}"],
                interpretation=str(exc),
            )
        errored = self._errored(resp)
        return VersionEvidence(
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
        )

    def _probe_error_surface(self, url: str, evidence: list[VersionEvidence]) -> Optional[bool]:
        """Establish opaque-error fingerprint via baseline vs negative control."""
        baseline_sig: Optional[ResponseSig] = None
        try:
            base_resp = self._send(url, BASELINE_OK)
        except Exception as exc:  # noqa: BLE001
            evidence.append(
                VersionEvidence(
                    probe_id=BASELINE_OK.id,
                    category="control",
                    description=BASELINE_OK.description,
                    payload=BASELINE_OK.payload,
                    matched=[f"request_error:{type(exc).__name__}"],
                    interpretation=str(exc),
                )
            )
            base_resp = None
        else:
            baseline_sig = response_sig(base_resp)
            base_classic_err = response_errored(base_resp)
            evidence.append(
                VersionEvidence(
                    probe_id=BASELINE_OK.id,
                    category="control",
                    description=BASELINE_OK.description,
                    payload=BASELINE_OK.payload,
                    status_code=base_resp.status_code,
                    elapsed_ms=round(base_resp.elapsed_ms, 2),
                    errored=base_classic_err,
                    matched=["baseline_error"] if base_classic_err else ["baseline_ok"],
                    response_excerpt=_excerpt(base_resp.text),
                    interpretation=(
                        "合法 JSON 也被判错，后续侧信道可能不可靠"
                        if base_classic_err
                        else "合法 JSON 正常"
                    ),
                )
            )
            if base_classic_err:
                # Everything looks like an error — do not use fingerprint matching.
                self._error_sig = None
                return None

        try:
            resp = self._send(url, NEGATIVE_CONTROL)
        except Exception as exc:  # noqa: BLE001
            evidence.append(
                VersionEvidence(
                    probe_id=NEGATIVE_CONTROL.id,
                    category="control",
                    description=NEGATIVE_CONTROL.description,
                    payload=NEGATIVE_CONTROL.payload,
                    matched=[f"request_error:{type(exc).__name__}"],
                    interpretation=str(exc),
                )
            )
            return None

        neg_sig = response_sig(resp)
        classic_err = response_errored(resp)
        differs = baseline_sig is not None and neg_sig != baseline_sig
        errored = classic_err or differs
        if errored:
            self._error_sig = neg_sig
        evidence.append(
            VersionEvidence(
                probe_id=NEGATIVE_CONTROL.id,
                category="control",
                description=NEGATIVE_CONTROL.description,
                payload=NEGATIVE_CONTROL.payload,
                status_code=resp.status_code,
                elapsed_ms=round(resp.elapsed_ms, 2),
                errored=errored,
                matched=["error_surface"] if errored else ["silent_ok"],
                response_excerpt=_excerpt(resp.text),
                interpretation=(
                    "目标对解析错误有可区分侧信道（500 / 裸 error / 与 baseline 不同），"
                    "offline 布尔二分可信"
                    if errored
                    else "残缺 JSON 与合法 JSON 响应无差异，offline「不报错」不可作为版本信号"
                ),
            )
        )
        return errored

    def _probe_autotype(self, url: str, evidence: list[VersionEvidence]) -> Optional[bool]:
        try:
            class_resp = self._send(url, AUTOTYPE_CLASS)
            rand_resp = self._send(url, AUTOTYPE_RANDOM)
        except Exception as exc:  # noqa: BLE001
            evidence.append(
                VersionEvidence(
                    probe_id="autotype",
                    category="autotype",
                    description="AutoType 探测失败",
                    matched=[f"request_error:{type(exc).__name__}"],
                    interpretation=str(exc),
                )
            )
            return None

        class_err_msg = "autoType is not support. java.lang.Class" in (class_resp.text or "")
        rand_err_msg = "autoType is not support. Random.String" in (rand_resp.text or "")
        class_errored = self._errored(class_resp)
        rand_errored = self._errored(rand_resp)

        enabled: Optional[bool] = None
        interpretation = "无法判定 AutoType 状态"
        # 开启：payload1 报错，payload2 不报错（无回显时仅看状态码 / 指纹）
        if class_errored and not rand_errored:
            enabled = True
            interpretation = (
                "AutoType 疑似开启（Class 报错且 Random.String 不报错）"
                if class_err_msg
                else "AutoType 疑似开启（Class 异常 / Random.String 正常，无文案回显）"
            )
        # 关闭：payload1 不报错，payload2 报错
        elif (not class_errored) and rand_errored:
            enabled = False
            interpretation = (
                "AutoType 疑似关闭（Random.String 报 autoType is not support）"
                if rand_err_msg
                else "AutoType 疑似关闭（Random.String 异常 / Class 正常，无文案回显）"
            )

        evidence.append(
            VersionEvidence(
                probe_id=AUTOTYPE_CLASS.id,
                category="autotype",
                description=AUTOTYPE_CLASS.description,
                payload=AUTOTYPE_CLASS.payload,
                status_code=class_resp.status_code,
                elapsed_ms=round(class_resp.elapsed_ms, 2),
                errored=class_errored,
                matched=["class_autotype_msg"] if class_err_msg else (["errored"] if class_errored else ["ok"]),
                response_excerpt=_excerpt(class_resp.text),
                interpretation=interpretation,
            )
        )
        evidence.append(
            VersionEvidence(
                probe_id=AUTOTYPE_RANDOM.id,
                category="autotype",
                description=AUTOTYPE_RANDOM.description,
                payload=AUTOTYPE_RANDOM.payload,
                status_code=rand_resp.status_code,
                elapsed_ms=round(rand_resp.elapsed_ms, 2),
                errored=rand_errored,
                matched=["random_autotype_msg"] if rand_err_msg else (["errored"] if rand_errored else ["ok"]),
                response_excerpt=_excerpt(rand_resp.text),
                interpretation=interpretation,
            )
        )
        return enabled

    def _probe_safemode(
        self,
        url: str,
        evidence: list[VersionEvidence],
        *,
        error_surface: Optional[bool],
    ) -> Optional[bool]:
        """SafeMode String\"\"\" probe — only meaningful with error echo.

        Note checklist: SafeMode ON → this payload errors. The converse is false:
        AutoType-off / pure syntax errors also trip it, so callers must cross-check.
        """
        if error_surface is False:
            evidence.append(
                VersionEvidence(
                    probe_id=SAFEMODE_STRING.id,
                    category="safemode",
                    description=SAFEMODE_STRING.description,
                    payload=SAFEMODE_STRING.payload,
                    matched=["skipped_no_error_surface"],
                    interpretation=(
                        "目标不回显解析错误，笔记中的 SafeMode String 探针不适用 → 未知"
                    ),
                )
            )
            return None

        try:
            resp = self._send(url, SAFEMODE_STRING)
        except Exception as exc:  # noqa: BLE001
            evidence.append(
                VersionEvidence(
                    probe_id=SAFEMODE_STRING.id,
                    category="safemode",
                    description="SafeMode 探测失败",
                    payload=SAFEMODE_STRING.payload,
                    matched=[f"request_error:{type(exc).__name__}"],
                    interpretation=str(exc),
                )
            )
            return None

        text = resp.text or ""
        lower = text.lower()
        safemode_msg = any(m.lower() in lower for m in _SAFEMODE_MARKERS)
        errored = self._errored(resp)

        if safemode_msg:
            enabled: Optional[bool] = True
            matched = ["safemode_marker"]
            interpretation = "响应含 safeMode not support autoType → SafeMode 疑似开启"
        elif not errored:
            enabled = False
            matched = ["ok"]
            interpretation = "SafeMode 疑似关闭（String 畸形 payload 不报错）"
        else:
            # Tentative; _crosscheck_safemode decides. Syntax-only is often a FP.
            enabled = True
            matched = ["errored_pending_crosscheck"]
            interpretation = (
                "String 畸形 payload 报错（待交叉校验；"
                "常见于纯语法错误 / AutoType 关闭，≠ 必然 SafeMode）"
            )

        evidence.append(
            VersionEvidence(
                probe_id=SAFEMODE_STRING.id,
                category="safemode",
                description=SAFEMODE_STRING.description,
                payload=SAFEMODE_STRING.payload,
                status_code=resp.status_code,
                elapsed_ms=round(resp.elapsed_ms, 2),
                errored=errored,
                matched=matched,
                response_excerpt=_excerpt(text),
                interpretation=interpretation,
            )
        )
        return enabled

    def _crosscheck_safemode(
        self,
        safemode_enabled: Optional[bool],
        *,
        offline_flags: dict[str, Optional[bool]],
        reported_version: Optional[str],
        autotype_enabled: Optional[bool],
        error_surface: Optional[bool],
        version_range: Optional[str],
        evidence: list[VersionEvidence],
    ) -> Optional[bool]:
        """Finalize SafeMode: require error echo; downgrade when @type still works."""
        if error_surface is False:
            return None
        if safemode_enabled is not True:
            return safemode_enabled

        # SafeMode 自 1.2.68 引入；已收敛到更低版本则不可能开启
        if version_range == "<=1.2.47":
            evidence.append(
                VersionEvidence(
                    probe_id="safemode_crosscheck",
                    category="safemode",
                    description="SafeMode 与版本区间交叉校验",
                    matched=["version_range<=1.2.47"],
                    interpretation=(
                        "版本区间 ≤1.2.47（SafeMode 尚未引入）→ 判定为非 SafeMode"
                    ),
                )
            )
            return False

        reasons: list[str] = []
        if offline_flags.get("autoclosable_ok") is True:
            reasons.append("AutoCloseable 双 @type 不报错")
        if reported_version:
            reasons.append(f"AutoCloseable 回显版本 {reported_version}")
        # AutoType 关闭形态：java.lang.Class @type 仍可用 → 绝非全面禁用 @type 的 SafeMode
        if autotype_enabled is False:
            reasons.append("AutoType 关闭形态（java.lang.Class @type 仍可用）")

        probe_ev = next(
            (e for e in reversed(evidence) if e.probe_id == SAFEMODE_STRING.id),
            None,
        )
        has_safemode_marker = bool(
            probe_ev and "safemode_marker" in (probe_ev.matched or [])
        )
        excerpt = (probe_ev.response_excerpt or "") if probe_ev else ""
        syntax_only = (
            not has_safemode_marker
            and "not close json text" in excerpt.lower()
        )

        if reasons:
            interpretation = (
                "SafeMode 探针假阳性："
                + "；".join(reasons)
                + " → 判定为非 SafeMode"
            )
            evidence.append(
                VersionEvidence(
                    probe_id="safemode_crosscheck",
                    category="safemode",
                    description="SafeMode 交叉校验",
                    matched=reasons,
                    interpretation=interpretation,
                )
            )
            return False

        if syntax_only:
            evidence.append(
                VersionEvidence(
                    probe_id="safemode_crosscheck",
                    category="safemode",
                    description="SafeMode 交叉校验",
                    matched=["syntax_only_not_close_json"],
                    interpretation=(
                        "仅有 not close json text 语法错误、无 safeMode 特征文案、"
                        "且无 @type 全面失效证据 → SafeMode 未知"
                    ),
                )
            )
            return None

        if has_safemode_marker:
            return True

        evidence.append(
            VersionEvidence(
                probe_id="safemode_crosscheck",
                category="safemode",
                description="SafeMode 交叉校验",
                matched=["low_confidence_errored"],
                interpretation=(
                    "String 畸形报错且无反证，仍仅作低置信 SafeMode 疑似开启"
                ),
            )
        )
        return True

    def _probe_exact(
        self, url: str, evidence: list[VersionEvidence]
    ) -> tuple[Optional[str], Optional[str]]:
        try:
            resp = self._send(url, AUTOCLOSEABLE_EXACT)
        except Exception as exc:  # noqa: BLE001
            evidence.append(
                VersionEvidence(
                    probe_id=AUTOCLOSEABLE_EXACT.id,
                    category="exact",
                    description=AUTOCLOSEABLE_EXACT.description,
                    payload=AUTOCLOSEABLE_EXACT.payload,
                    matched=[f"request_error:{type(exc).__name__}"],
                    interpretation=str(exc),
                )
            )
            return None, None

        text = resp.text or ""
        match = _VERSION_RE.search(text)
        version = match.group(1) if match else None
        note = None
        interpretation = "未回显 fastjson-version"
        if version:
            interpretation = f"回显 fastjson-version {version}"
            if version == "1.2.76":
                note = "1.2.76 之后（含 1.2.80）源码写死，回显可能仍为 1.2.76"
                interpretation += "（可能实际为 1.2.76-1.2.80）"
        evidence.append(
            VersionEvidence(
                probe_id=AUTOCLOSEABLE_EXACT.id,
                category="exact",
                description=AUTOCLOSEABLE_EXACT.description,
                payload=AUTOCLOSEABLE_EXACT.payload,
                status_code=resp.status_code,
                elapsed_ms=round(resp.elapsed_ms, 2),
                errored=self._errored(resp),
                matched=[f"version:{version}"] if version else [],
                response_excerpt=_excerpt(text),
                interpretation=interpretation,
            )
        )
        return version, note

    def _probe_1_2_83(self, url: str, evidence: list[VersionEvidence]) -> Optional[bool]:
        try:
            resp = self._send(url, PROBE_1_2_83)
        except Exception as exc:  # noqa: BLE001
            evidence.append(
                VersionEvidence(
                    probe_id=PROBE_1_2_83.id,
                    category="exact",
                    description=PROBE_1_2_83.description,
                    payload=PROBE_1_2_83.payload,
                    matched=[f"request_error:{type(exc).__name__}"],
                    interpretation=str(exc),
                )
            )
            return None

        errored = self._errored(resp)
        is_83 = False if errored else True
        evidence.append(
            VersionEvidence(
                probe_id=PROBE_1_2_83.id,
                category="exact",
                description=PROBE_1_2_83.description,
                payload=PROBE_1_2_83.payload,
                status_code=resp.status_code,
                elapsed_ms=round(resp.elapsed_ms, 2),
                errored=errored,
                matched=["ok_suggest_1.2.83"] if is_83 else ["errored_not_only_1.2.83"],
                response_excerpt=_excerpt(resp.text),
                interpretation="不报错，倾向 1.2.83" if is_83 else "报错，不太像单独的 1.2.83 特征",
            )
        )
        return is_83

    def _run_offline(self, url: str, evidence: list[VersionEvidence]) -> dict[str, Optional[bool]]:
        flags: dict[str, Optional[bool]] = {}
        mapping = {
            "exception_ok": OFFLINE_EXCEPTION,
            "autoclosable_ok": OFFLINE_AUTOCLOSEABLE,
            "class_jdbc_ok": OFFLINE_CLASS_JDBC,
            "jdbc_ok": OFFLINE_JDBC,
        }
        for key, probe in mapping.items():
            try:
                resp = self._send(url, probe)
            except Exception as exc:  # noqa: BLE001
                flags[key] = None
                evidence.append(
                    VersionEvidence(
                        probe_id=probe.id,
                        category="offline",
                        description=probe.description,
                        payload=probe.payload,
                        matched=[f"request_error:{type(exc).__name__}"],
                        interpretation=str(exc),
                    )
                )
                continue
            errored = self._errored(resp)
            flags[key] = not errored
            evidence.append(
                VersionEvidence(
                    probe_id=probe.id,
                    category="offline",
                    description=probe.description,
                    payload=probe.payload,
                    status_code=resp.status_code,
                    elapsed_ms=round(resp.elapsed_ms, 2),
                    errored=errored,
                    matched=["ok"] if not errored else ["errored"],
                    response_excerpt=_excerpt(resp.text),
                    interpretation="不报错" if not errored else "报错",
                )
            )
        return flags

    # Canonical bands the toolkit aims to distinguish for PoC routing.
    BANDS = ("<=1.2.47", "<=1.2.68", "<=1.2.80", "1.2.83")

    @staticmethod
    def _match_dns_hits(
        dns_hosts: dict[str, str],
        records: list,
    ) -> dict[str, bool]:
        """Exact FQDN / label match — avoid substring false positives."""
        names: list[str] = []
        for r in records:
            if hasattr(r, "name"):
                raw = getattr(r, "name") or ""
            elif isinstance(r, dict):
                raw = r.get("name") or ""
            else:
                raw = str(r)
            names.append(str(raw).lower().rstrip("."))
        hits: dict[str, bool] = {}
        for tag, host in dns_hosts.items():
            host_l = host.lower().rstrip(".")
            label = host_l.split(".", 1)[0]
            hits[tag] = any(n == host_l or n.startswith(label + ".") for n in names)
        return hits

    @classmethod
    def normalize_band(cls, label: Optional[str]) -> Optional[str]:
        """Map any raw label into one of the four milestone bands."""
        if not label:
            return None
        text = label.strip()
        if text in cls.BANDS:
            return text
        if text == "1.2.83" or text.startswith("1.2.83；") or text.startswith("1.2.83("):
            return "1.2.83"
        if any(tok in text for tok in ("1.2.70", "1.2.76", "≈1.2.80", "<=1.2.80")):
            return "<=1.2.80"
        if "1.2.80" in text and "1.2.83" not in text:
            return "<=1.2.80"
        if any(tok in text for tok in ("1.2.48-1.2.68", "<=1.2.68")):
            return "<=1.2.68"
        if re.search(r"1\.2\.68(\D|$)", text) and "1.2.80" not in text:
            return "<=1.2.68"
        if any(tok in text for tok in ("1.2.25-1.2.47", "<=1.2.47", "≈1.2.24")):
            return "<=1.2.47"
        if re.search(r"1\.2\.(24|30|47)(\D|$)", text):
            return "<=1.2.47"
        return None

    @classmethod
    def _band_from_echo(
        cls, reported_version: Optional[str]
    ) -> tuple[Optional[str], Optional[str]]:
        """Note §2: AutoCloseable fastjson-version；1.2.76+ 常写死 1.2.76 → <=1.2.80."""
        if not reported_version:
            return None, None
        if reported_version == "1.2.83":
            return "1.2.83", "1.2.83"
        if reported_version == "1.2.76":
            return "<=1.2.80", "1.2.76-1.2.80"
        try:
            parts = [int(x) for x in reported_version.split(".")]
        except ValueError:
            band = cls.normalize_band(reported_version)
            return band, reported_version
        if len(parts) >= 3 and parts[0] == 1 and parts[1] == 2:
            patch = parts[2]
            if patch <= 24:
                return "<=1.2.47", "≈1.2.24"
            if patch <= 47:
                return "<=1.2.47", "1.2.25-1.2.47"
            if patch <= 68:
                return "<=1.2.68", "1.2.48-1.2.68"
            if patch <= 72:
                return "<=1.2.80", "1.2.70-1.2.72"
            if patch <= 80:
                return "<=1.2.80", "1.2.73-1.2.80"
            if patch >= 83:
                return "1.2.83", "1.2.83"
        band = cls.normalize_band(reported_version)
        return band, reported_version

    @classmethod
    def _band_from_offline(
        cls,
        offline: dict[str, Optional[bool]],
        *,
        trust: bool,
    ) -> tuple[Optional[str], Optional[str], float]:
        """布尔报错表 → PoC band + 细粒度 detail（无法再分 1.2.70 与 1.2.73）。"""
        e = offline.get("exception_ok")
        a = offline.get("autoclosable_ok")
        c = offline.get("class_jdbc_ok")
        j = offline.get("jdbc_ok")
        if None in (e, a, c, j) or not trust:
            return None, None, 0.0
        pattern = (e, a, c, j)
        # (exception_ok, autoclosable_ok, class_jdbc_ok, jdbc_ok) → band, detail, conf
        table = {
            (True, True, True, True): ("<=1.2.47", "≈1.2.24", 0.8),
            (False, True, True, True): ("<=1.2.47", "1.2.25-1.2.47", 0.75),
            (False, True, True, False): ("<=1.2.47", "1.2.25-1.2.47", 0.85),
            (False, True, False, False): ("<=1.2.68", "1.2.48-1.2.68", 0.85),
            # AutoCloseable 报错：1.2.70-1.2.80（含无链 70-72 与 Exception 绕过 73-80）
            (False, False, False, False): ("<=1.2.80", "1.2.70-1.2.80", 0.85),
            (True, False, False, False): ("1.2.83", "1.2.83", 0.9),
            # 实测 1.2.83 上 AutoCloseable 二分常仍不报错
            (True, True, False, False): ("1.2.83", "1.2.83", 0.85),
        }
        hit = table.get(pattern)
        if not hit:
            return None, None, 0.0
        return hit

    @classmethod
    def _dns_overfired(cls, dns_hits: dict[str, bool]) -> bool:
        """le47 与 80/83 探针同时命中 → InetSocketAddress 单独出网，§4 低档门闩失效."""
        return bool(dns_hits.get("le47")) and bool(dns_hits.get("d80a"))

    @classmethod
    def _band_from_dns(
        cls,
        dns_hits: dict[str, bool],
        *,
        autotype_enabled: Optional[bool],
    ) -> tuple[Optional[str], float]:
        """Note §4 DNSLog bands.

        Stable signal: d80a+d80b → 1.2.83；d80a only → <=1.2.80（仅当未 overfire）.
        le47 / le68 仅在互斥命中时采信。
        """
        le47 = bool(dns_hits.get("le47"))
        le68 = bool(dns_hits.get("le68"))
        d80a = bool(dns_hits.get("d80a"))
        d80b = bool(dns_hits.get("d80b"))

        if d80a and d80b:
            return "1.2.83", 0.92

        # Overfire: all low/high probes light up — do not guess 47/68/80 from DNS alone.
        if cls._dns_overfired(dns_hits):
            return None, 0.0

        if d80a and not d80b:
            return "<=1.2.80", 0.8
        if le68 and not le47:
            return "<=1.2.68", 0.8
        if le47 and not le68 and not d80a:
            return "<=1.2.47", 0.8
        if le68:
            return "<=1.2.68", 0.7
        if le47:
            return "<=1.2.47", 0.7
        return None, 0.0

    @classmethod
    def _infer_band(
        cls,
        reported_version: Optional[str],
        is_83: Optional[bool],
        offline: dict[str, Optional[bool]],
        error_surface: Optional[bool] = True,
        autotype_enabled: Optional[bool] = None,
        dns_hits: Optional[dict[str, bool]] = None,
    ) -> tuple[Optional[str], Optional[str], float]:
        """Four bands via note §2 echo / §3 83 / §4 DNS / §5 offline.

        Returns (version_range, version_detail, confidence).
        DNSLog 开启时：双 DNS 优先定 1.2.83；其余在 DNS overfire 时回退出网二分与回显。
        """
        trust_offline = error_surface is not False and autotype_enabled is not True
        echo_band, echo_detail = cls._band_from_echo(reported_version)
        offline_band, offline_detail, offline_conf = cls._band_from_offline(
            offline, trust=trust_offline
        )
        dns_band, dns_conf = (None, 0.0)
        if dns_hits is not None:
            dns_band, dns_conf = cls._band_from_dns(
                dns_hits, autotype_enabled=autotype_enabled
            )

        # 1) AutoCloseable 回显（§2）；1.2.76 用双 DNS 排除真 83
        if echo_band == "1.2.83":
            return "1.2.83", echo_detail or "1.2.83", 0.95
        if reported_version == "1.2.76" or echo_band == "<=1.2.80":
            if dns_band == "1.2.83" or is_83 is True:
                return "1.2.83", "1.2.83", 0.92
            if echo_band:
                return "<=1.2.80", echo_detail or "1.2.70-1.2.80", 0.92
        if echo_band in ("<=1.2.47", "<=1.2.68"):
            return echo_band, echo_detail, 0.95

        # 2) DNS 双请求 → 1.2.83（§4，DNSLog 主路径）
        if dns_band == "1.2.83":
            return "1.2.83", "1.2.83", dns_conf
        if is_83 is True and autotype_enabled is not True:
            return "1.2.83", "1.2.83", 0.88

        # 3) 不出网二分（§5）—— DNS overfire 或未开 DNS 时的主路径
        if trust_offline and offline_band:
            if offline_band == "1.2.83":
                return "1.2.83", offline_detail or "1.2.83", offline_conf
            return offline_band, offline_detail, offline_conf

        # 4) 互斥 DNS 档（仅当未 overfire）
        if dns_band:
            return dns_band, dns_band, dns_conf

        # 5) silent / AT-on：offline 不可信时的弱信号
        if not trust_offline and dns_hits is not None and cls._dns_overfired(dns_hits):
            if bool(dns_hits.get("d80a")) and not bool(dns_hits.get("d80b")):
                return "<=1.2.80", "1.2.70-1.2.80", 0.5
        if is_83 is True:
            return "1.2.83", "1.2.83", 0.65
        if echo_band:
            return echo_band, echo_detail, 0.7
        return None, None, 0.0

    # Back-compat for unit tests that still call old helpers.
    @classmethod
    def _infer_range(
        cls,
        reported_version: Optional[str],
        is_83: Optional[bool],
        offline: dict[str, Optional[bool]],
        error_surface: Optional[bool] = True,
        autotype_enabled: Optional[bool] = None,
    ) -> tuple[Optional[str], float]:
        band, _detail, conf = cls._infer_band(
            reported_version=reported_version,
            is_83=is_83,
            offline=offline,
            error_surface=error_surface,
            autotype_enabled=autotype_enabled,
            dns_hits=None,
        )
        return band, conf

    @classmethod
    def _infer_from_dns(
        cls,
        dns_hits: dict[str, bool],
        autotype_enabled: Optional[bool] = None,
    ) -> tuple[Optional[str], float]:
        return cls._band_from_dns(dns_hits, autotype_enabled=autotype_enabled)

    @staticmethod
    def _build_summary(
        autotype_enabled: Optional[bool],
        reported_version: Optional[str],
        reported_note: Optional[str],
        is_83: Optional[bool],
        version_range: Optional[str],
        confidence: float,
        dns_hits: dict[str, bool],
        error_surface: Optional[bool] = True,
        dns_skip_reason: Optional[str] = None,
        safemode_enabled: Optional[bool] = None,
        version_detail: Optional[str] = None,
    ) -> tuple[str, list[str]]:
        parts: list[str] = []
        if version_range:
            if version_detail and version_detail != version_range:
                parts.append(
                    f"版本区间 {version_range}（细分为 {version_detail}，置信度 {confidence:.2f}）"
                )
            else:
                parts.append(f"版本区间 {version_range}（置信度 {confidence:.2f}）")
        else:
            parts.append("未能收敛出版本区间")
        if error_surface is False:
            parts.append("目标不回显解析错误，offline「不报错」信号已降权")
        if reported_version:
            parts.append(f"AutoCloseable 回显 {reported_version}")
            if reported_note:
                parts.append(reported_note)
        if is_83 is True:
            parts.append("1.2.83 探针不报错")
        elif is_83 is False:
            parts.append("1.2.83 探针报错")
        if autotype_enabled is True:
            parts.append("AutoType 疑似开启")
        elif autotype_enabled is False:
            parts.append("AutoType 疑似关闭")
        if safemode_enabled is True:
            parts.append("SafeMode 低置信疑似开启")
        elif safemode_enabled is False:
            parts.append("SafeMode 疑似关闭")
        if dns_skip_reason:
            parts.append(dns_skip_reason)
        if dns_hits:
            hit = [k for k, v in dns_hits.items() if v]
            if hit:
                parts.append("DNS 命中 " + ",".join(hit))

        next_actions: list[str] = []
        if version_range == "1.2.83":
            next_actions.append(
                "poc_catalog(family=cve-2026-16723) / poc_run 评估高版本利用面（需授权）"
            )
        elif version_range == "<=1.2.80":
            next_actions.append(
                "poc_catalog(family=1.2.80) → poc_run；AutoType 关时用 expect_bypass"
            )
            if version_detail == "1.2.70-1.2.80":
                next_actions.append(
                    "不出网二分无法区分 1.2.70-72（无链）与 1.2.73-80（Exception 绕过）；"
                    "有回显时看 AutoCloseable 精确版本，或直接试 1.2.80 链"
                )
        elif version_range == "<=1.2.68":
            next_actions.append(
                "poc_catalog(family=1.2.68) → deps_probe 确认 commons-io 等 → poc_run"
            )
        elif version_range == "<=1.2.47":
            next_actions.append(
                "poc_catalog(family=1.2.47) → 评估 JNDI / 缓存绕过（需授权）"
            )
        else:
            next_actions.append("结合报错回显与 DNS 命中人工复核版本区间")
        if version_range == "<=1.2.68" and error_surface is False:
            next_actions.append(
                "无回显时 1.2.68 与 1.2.80 的 AutoCloseable 不出网表现可能相同；"
                "请改用报错回显确认是否实为 <=1.2.80"
            )
        if safemode_enabled is True:
            next_actions.append(
                "SafeMode 低置信：若仍能走 AutoCloseable/expectClass 则忽略；"
                "真 SafeMode 时几乎所有 @type 链失效"
            )
        if autotype_enabled is True and error_surface is False:
            next_actions.append(
                "AutoType 开启且无报错回显时，68/80/83 侧信道易混淆；优先找 AT 关闭或有回显的入口"
            )
        if autotype_enabled is False and safemode_enabled is not True:
            next_actions.append(
                "AutoType 关闭：先看 detect_pipeline.expect；"
                "再用 poc_run(expect_bypass=true) / 1.2.68 AutoCloseable 链"
            )
        if dns_skip_reason:
            next_actions.append(
                "配置项目 .env 的 CEYE_TOKEN/CEYE_DOMAIN 后重跑 "
                "detect_pipeline(include_dns_version=true)"
            )
        elif dns_hits and FastjsonVersionDetector._dns_overfired(dns_hits):
            next_actions.append(
                "DNS le47 与 80/83 探针同时命中（InetSocketAddress 可单独出网），"
                "已忽略低档 DNS 门闩，改以回显 / 不出网二分 / 双 DNS 为准"
            )
        elif not dns_hits or not any(dns_hits.values()):
            next_actions.append("若目标不出网，以 offline 二分与 AutoCloseable 回显为准")
        return "；".join(parts), next_actions
