"""Probe payloads for Fastjson fingerprinting."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Probe:
    """A single fingerprint probe."""

    id: str
    category: str
    description: str
    payload: str
    # typed person endpoint preferred when True
    prefer_typed: bool = False
    # exclusive / strong signals for Fastjson
    expect_fastjson: tuple[str, ...] = ()
    # signals that point to another library
    expect_other: dict[str, tuple[str, ...]] = field(default_factory=dict)
    weight: float = 1.0
    dns_related: bool = False
    # if True, success body must not be treated as Fastjson-only (shared by many parsers)
    non_exclusive: bool = False


def build_dns_payloads(dnslog_host: str) -> list[Probe]:
    host = dnslog_host.strip()
    return [
        Probe(
            id="dns_inet4",
            category="dns",
            description="Inet4Address DNS / timing probe",
            payload=f'{{"@type":"java.net.Inet4Address","val":"{host}"}}',
            expect_fastjson=("autoType is not support", "com.alibaba.fastjson"),
            dns_related=True,
            weight=1.2,
        ),
        Probe(
            id="dns_inet_socket",
            category="dns",
            description="InetSocketAddress DNS / timing probe",
            payload=f'{{"@type":"java.net.InetSocketAddress"{{"address":,"val":"{host}"}}}}',
            expect_fastjson=("autoType is not support", "com.alibaba.fastjson"),
            dns_related=True,
            weight=1.1,
        ),
        Probe(
            id="dns_url",
            category="dns",
            description="java.net.URL as map key DNS / timing probe",
            payload=f'{{{{"@type":"java.net.URL","val":"http://{host}"}}:"a"}}',
            expect_fastjson=("autoType is not support", "com.alibaba.fastjson"),
            dns_related=True,
            weight=1.1,
        ),
    ]


PROBES: list[Probe] = [
    # 1. error-based (exclusive)
    Probe(
        id="error_broken_json",
        category="error",
        description="Broken JSON to surface parser exception",
        payload='{"age":20,"name":"Bob"',
        expect_fastjson=(
            "com.alibaba.fastjson.JSONException",
            "com.alibaba.fastjson",
        ),
        expect_other={
            "jackson": ("com.fasterxml.jackson", "JsonEOFException", "Unexpected end-of-input"),
            "gson": ("com.google.gson", "MalformedJsonException", "JsonSyntaxException"),
            "org.json": ("org.json.JSONException",),
        },
        weight=1.5,
    ),
    Probe(
        id="error_autotype",
        category="error",
        description="@type probe for Fastjson autoType message",
        payload='{"@type":"whatever"}',
        expect_fastjson=(
            "com.alibaba.fastjson.JSONException",
            "autoType is not support",
            "autoType is not support. whatever",
        ),
        weight=2.0,
    ),
    # 2. parse-behavior (exclusive to Fastjson-like parsers)
    Probe(
        id="parse_features",
        category="parse",
        description="Fastjson feature syntax: new / hex / comment / Set",
        payload="{\"a\":new a(1),\"b\":x'11',/**/\"c\":Set[{}],\"d\":\"\\u0000\\x00\"}",
        expect_fastjson=('{"a":1', '"b":"EQ=="', '"c":[{}]'),
        weight=1.8,
    ),
    Probe(
        id="parse_ref",
        category="parse",
        description="Fastjson $ref resolution",
        payload='{"ext":"blue","name":{"$ref":"$.ext"}}',
        expect_fastjson=(),  # scored manually when $ref is resolved
        weight=1.6,
    ),
    # 4. jackson diffs — only identify jackson; success is NOT Fastjson-exclusive
    Probe(
        id="diff_jackson_extra_field",
        category="diff_jackson",
        description="Extra field: Jackson typed FAIL; many other libs OK",
        payload='{"age":20,"name":"Bob","test":1}',
        prefer_typed=True,
        expect_other={
            "jackson": (
                "UnrecognizedPropertyException",
                "Unrecognized field",
                "not marked as ignorable",
            ),
        },
        weight=1.3,
        non_exclusive=True,
    ),
    Probe(
        id="diff_jackson_single_quote",
        category="diff_jackson",
        description="Single quotes: Jackson FAIL by default; many other libs OK",
        payload="{\"age\":20,'name':'Bob'}",
        expect_other={
            "jackson": (
                "JsonParseException",
                "Unexpected character ('''",
                "was expecting double-quote",
            ),
        },
        weight=1.3,
        non_exclusive=True,
    ),
    Probe(
        id="diff_jackson_comment",
        category="diff_jackson",
        description="Trailing /*# with single quotes — library-dependent",
        payload='{\n    "age":20,\n    "name":\'Bob\'\n}/*#aaaa',
        expect_other={
            "jackson": ("com.fasterxml.jackson", "JsonParseException"),
            "fastjson": ("com.alibaba.fastjson.JSONException",),
        },
        weight=1.0,
        non_exclusive=True,
    ),
    Probe(
        id="diff_jackson_precision",
        category="diff_jackson",
        description="Long float precision: Jackson often shortens",
        payload='{"age":20.111111111111111111111111111,"name":"Bob"}',
        expect_other={
            "jackson": ('"age":20.11111111111111', "20.11111111111111"),
        },
        weight=0.8,
        non_exclusive=True,
    ),
    # 5. gson diffs
    Probe(
        id="diff_gson_precision",
        category="diff_gson",
        description="Gson float precision loss fingerprint",
        payload="{a:1.111111111111111111111111111}",
        expect_other={
            "gson": ("1.1111111111111112",),
        },
        weight=1.0,
        non_exclusive=True,
    ),
    Probe(
        id="diff_gson_hash_comment",
        category="diff_gson",
        description="Gson accepts leading # comment",
        payload="#\r\n{a:1}",
        expect_other={
            "gson": ('"a":1',),
            "fastjson": ("com.alibaba.fastjson.JSONException",),
            "jackson": ("com.fasterxml.jackson",),
        },
        weight=1.1,
        non_exclusive=True,
    ),
    # 6. org.json diffs — real CR inside quotes
    Probe(
        id="diff_orgjson_cr",
        category="diff_orgjson",
        description="org.json fails on real CR inside single-quoted string",
        payload="{a:'\r'}",
        expect_other={
            "org.json": (
                "org.json.JSONException",
                "Unterminated string",
            ),
        },
        weight=1.2,
        non_exclusive=True,
    ),
    # hutool permissiveness: unquoted + trailing junk
    Probe(
        id="diff_hutool_permissive",
        category="diff_hutool",
        description="Hutool accepts unquoted key/value and trailing junk",
        payload="{a:what.ever}/*\r\nxxx",
        expect_other={
            "hutool": ('"a":"what.ever"',),
        },
        weight=1.2,
        non_exclusive=True,
    ),
]


def all_probes(dnslog_host: Optional[str] = None) -> list[Probe]:
    probes = list(PROBES)
    if dnslog_host:
        probes.extend(build_dns_payloads(dnslog_host))
    return probes


def baseline_timing_payload() -> str:
    return '{"age":20,"name":"Bob"}'
