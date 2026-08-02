"""Fastjson version detector."""

from __future__ import annotations

import re
from typing import Mapping, Optional
from urllib.parse import urlparse

from fastjson_toolkit.dnslog import CeyeClient, CeyeConfig
from fastjson_toolkit.http.client import HttpClient, HttpResponse
from fastjson_toolkit.version.models import VersionEvidence, VersionResult
from fastjson_toolkit.version.probes import (
    AUTOCLOSEABLE_EXACT,
    AUTOTYPE_CLASS,
    AUTOTYPE_RANDOM,
    NEGATIVE_CONTROL,
    OFFLINE_AUTOCLOSEABLE,
    OFFLINE_CLASS_JDBC,
    OFFLINE_EXCEPTION,
    OFFLINE_JDBC,
    PROBE_1_2_83,
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


def _excerpt(text: str, limit: int = 400) -> str:
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _resolve_url(target: str) -> str:
    """Normalize scheme only; do not rewrite empty paths (align with detect)."""
    parsed = urlparse(target)
    if not parsed.scheme:
        return "http://" + target
    return target


def response_errored(resp: HttpResponse) -> bool:
    """Judge whether the target treated the payload as a parse/runtime error."""
    if resp.status_code >= 400:
        return True
    text = resp.text or ""
    lower = text.lower()
    if any(m.lower() in lower for m in _ERROR_MARKERS):
        return True
    if '"error"' in lower and ("exception" in lower or "syntax" in lower):
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
        error_surface = self._probe_negative_control(url, evidence)

        methods.append("autotype")
        autotype_enabled = self._probe_autotype(url, evidence)

        methods.append("autoclosable_exact")
        reported_version, reported_note = self._probe_exact(url, evidence)

        methods.append("probe_1_2_83")
        is_83 = self._probe_1_2_83(url, evidence)

        methods.append("offline")
        offline_flags = self._run_offline(url, evidence)

        version_range, confidence = self._infer_band(
            reported_version=reported_version,
            is_83=is_83,
            offline=offline_flags,
            error_surface=error_surface,
            autotype_enabled=autotype_enabled,
            dns_hits=None,
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
                    version_range, confidence = self._infer_band(
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
            reported_version=reported_version,
            reported_note=reported_note,
            is_83=is_83,
            version_range=version_range,
            confidence=confidence,
            dns_hits=dns_hits,
            error_surface=error_surface,
            dns_skip_reason=dns_skip_reason,
        )

        return VersionResult(
            target=target,
            autotype_enabled=autotype_enabled,
            reported_version=reported_version,
            reported_version_note=reported_note,
            is_1_2_83_hint=is_83,
            version_range=version_range,
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
                "dns_skip_reason": dns_skip_reason,
                "ceye_domain": self.ceye_config.domain if self.ceye_config else None,
                "probe_ids": [p.id for p in all_version_probes(dns_hosts or None)],
            },
        )

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
        errored = response_errored(resp)
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

    def _probe_negative_control(self, url: str, evidence: list[VersionEvidence]) -> Optional[bool]:
        """Return True if the target surfaces parse errors (required for offline OK signals)."""
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
        errored = response_errored(resp)
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
                    "目标会回显/返回解析错误，offline「不报错」可信"
                    if errored
                    else "目标不回显错误，offline「不报错」不可作为版本信号"
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
        class_errored = response_errored(class_resp)
        rand_errored = response_errored(rand_resp)

        enabled: Optional[bool] = None
        interpretation = "无法判定 AutoType 状态"
        # 开启：payload1 报错，payload2 不报错（无回显时仅看状态码）
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
                errored=response_errored(resp),
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

        errored = response_errored(resp)
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
            errored = response_errored(resp)
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

    # Canonical bands the toolkit aims to distinguish.
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
    def _band_from_echo(cls, reported_version: Optional[str]) -> Optional[str]:
        """Note §2: AutoCloseable fastjson-version；1.2.76+ 常写死 1.2.76 → <=1.2.80."""
        if not reported_version:
            return None
        if reported_version == "1.2.83":
            return "1.2.83"
        if reported_version == "1.2.76":
            return "<=1.2.80"
        try:
            parts = [int(x) for x in reported_version.split(".")]
        except ValueError:
            return cls.normalize_band(reported_version)
        if len(parts) >= 3 and parts[0] == 1 and parts[1] == 2:
            patch = parts[2]
            if patch <= 47:
                return "<=1.2.47"
            if patch <= 68:
                return "<=1.2.68"
            if patch <= 80:
                return "<=1.2.80"
            if patch >= 83:
                return "1.2.83"
        return cls.normalize_band(reported_version)

    @classmethod
    def _band_from_offline(
        cls,
        offline: dict[str, Optional[bool]],
        *,
        trust: bool,
    ) -> tuple[Optional[str], float]:
        """Note §5 error/ok binary table → four bands."""
        e = offline.get("exception_ok")
        a = offline.get("autoclosable_ok")
        c = offline.get("class_jdbc_ok")
        j = offline.get("jdbc_ok")
        if None in (e, a, c, j) or not trust:
            return None, 0.0
        pattern = (e, a, c, j)
        table = {
            (True, True, True, True): ("<=1.2.47", 0.8),  # ~1.2.24
            (False, True, True, True): ("<=1.2.47", 0.85),
            (False, True, True, False): ("<=1.2.47", 0.85),
            # ac=ok & cj=err → note §5 「<=1.2.68」；1.2.80 在 raw parse 下也可能同型
            (False, True, False, False): ("<=1.2.68", 0.85),
            # ac=err → note §5 「1.2.70-1.2.83」上限收到 <=1.2.80（再靠双 DNS / 回显分 83）
            (False, False, False, False): ("<=1.2.80", 0.85),
            (True, False, False, False): ("1.2.83", 0.9),
            # 实测 1.2.83 上 AutoCloseable 二分常仍不报错
            (True, True, False, False): ("1.2.83", 0.85),
        }
        return table.get(pattern, (None, 0.0))

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
    ) -> tuple[Optional[str], float]:
        """Four bands via note §2 echo / §3 83 / §4 DNS / §5 offline.

        DNSLog 开启时：双 DNS 优先定 1.2.83；其余在 DNS overfire 时回退出网二分与回显。
        """
        trust_offline = error_surface is not False and autotype_enabled is not True
        echo_band = cls._band_from_echo(reported_version)
        offline_band, offline_conf = cls._band_from_offline(offline, trust=trust_offline)
        dns_band, dns_conf = (None, 0.0)
        if dns_hits is not None:
            dns_band, dns_conf = cls._band_from_dns(
                dns_hits, autotype_enabled=autotype_enabled
            )

        # 1) AutoCloseable 回显（§2）；1.2.76 用双 DNS 排除真 83
        if echo_band == "1.2.83":
            return "1.2.83", 0.95
        if reported_version == "1.2.76" or echo_band == "<=1.2.80":
            if dns_band == "1.2.83" or is_83 is True:
                return "1.2.83", 0.92
            if echo_band:
                return "<=1.2.80", 0.92
        if echo_band in ("<=1.2.47", "<=1.2.68"):
            return echo_band, 0.95

        # 2) DNS 双请求 → 1.2.83（§4，DNSLog 主路径）
        if dns_band == "1.2.83":
            return "1.2.83", dns_conf
        if is_83 is True and autotype_enabled is not True:
            return "1.2.83", 0.88

        # 3) 不出网二分（§5）—— DNS overfire 或未开 DNS 时的主路径
        if trust_offline and offline_band:
            if offline_band == "1.2.83":
                return "1.2.83", offline_conf
            return offline_band, offline_conf

        # 4) 互斥 DNS 档（仅当未 overfire）
        if dns_band:
            return dns_band, dns_conf

        # 5) silent / AT-on：offline 不可信时的弱信号
        if not trust_offline and dns_hits is not None and cls._dns_overfired(dns_hits):
            if bool(dns_hits.get("d80a")) and not bool(dns_hits.get("d80b")):
                return "<=1.2.80", 0.5
        if is_83 is True:
            return "1.2.83", 0.65
        if echo_band:
            return echo_band, 0.7
        return None, 0.0

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
        return cls._infer_band(
            reported_version=reported_version,
            is_83=is_83,
            offline=offline,
            error_surface=error_surface,
            autotype_enabled=autotype_enabled,
            dns_hits=None,
        )

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
    ) -> tuple[str, list[str]]:
        parts: list[str] = []
        if version_range:
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
        if dns_skip_reason:
            parts.append(dns_skip_reason)
        if dns_hits:
            hit = [k for k, v in dns_hits.items() if v]
            if hit:
                parts.append("DNS 命中 " + ",".join(hit))

        next_actions: list[str] = []
        if version_range == "1.2.83":
            next_actions.append("可进入高版本 expectClass / 利用面评估（需授权）")
        elif version_range == "<=1.2.80":
            next_actions.append("区间上限约 1.2.80，可对照该档绕过链做授权评估")
        elif version_range == "<=1.2.68":
            next_actions.append("区间上限约 1.2.68，可对照该档绕过链做授权评估")
        elif version_range == "<=1.2.47":
            next_actions.append("低版本档（≤1.2.47），可优先评估经典 JNDI / 缓存绕过（需授权）")
        else:
            next_actions.append("结合报错回显与 DNS 命中人工复核版本区间")
        if version_range == "<=1.2.68" and error_surface is False:
            next_actions.append(
                "无回显时 1.2.68 与 1.2.80 的 AutoCloseable 不出网表现可能相同；"
                "请改用报错回显（§2：1.2.68 vs 写死的 1.2.76）确认是否实为 <=1.2.80"
            )
        if autotype_enabled is True and error_surface is False:
            next_actions.append(
                "AutoType 开启且无报错回显时，68/80/83 侧信道易混淆；优先找 AT 关闭或有回显的入口"
            )
        if autotype_enabled is False:
            next_actions.append("AutoType 关闭时优先考虑 expectClass / 其他绕过面")
        if dns_skip_reason:
            next_actions.append("在设置页配置 CEYE，或填写自定义 DNSLog 域名后再开 DNS")
        elif dns_hits and FastjsonVersionDetector._dns_overfired(dns_hits):
            next_actions.append(
                "DNS le47 与 80/83 探针同时命中（InetSocketAddress 可单独出网），"
                "已忽略低档 DNS 门闩，改以回显 / 不出网二分 / 双 DNS 为准"
            )
        elif not dns_hits or not any(dns_hits.values()):
            next_actions.append("若目标不出网，以 offline 二分与 AutoCloseable 回显为准")
        return "；".join(parts), next_actions
