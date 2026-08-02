"""getter 触发包装单测。"""

from __future__ import annotations

import json

import pytest

from fastjson_toolkit.poc.getter import (
    apply_currency_if_needed,
    json_object_key,
    normalize_getter_trigger,
    wrap_with_currency,
)


def test_wrap_currency_shape():
    s = wrap_with_currency('{"a":1}')
    obj = json.loads(s)
    assert obj["x"]["@type"] == "java.util.Currency"
    assert obj["x"]["val"]["currency"]["xx"] == {"a": 1}


def test_wrap_currency_code_field():
    s = wrap_with_currency('{"a":1}', currency_field="currencyCode")
    obj = json.loads(s)
    assert "currencyCode" in obj["x"]["val"]
    assert "currency" not in obj["x"]["val"]


def test_json_object_key_variants():
    with_type = json_object_key('"c":{"u":1}', with_type=True)
    # 默认返回可嵌入的 key:value
    assert with_type.startswith('{"@type":"com.alibaba.fastjson.JSONObject"')
    assert with_type.endswith(":{}")

    wrapped = json_object_key('"c":{"u":1}', with_type=True, wrap_object=True)
    assert wrapped.startswith('{{"@type":"com.alibaba.fastjson.JSONObject"')
    assert wrapped.endswith(":{}}")

    no_type = json_object_key('"c":{"u":1}', with_type=False)
    assert no_type.startswith('{"c":')
    assert "com.alibaba.fastjson.JSONObject" not in no_type

    as_arr = json_object_key('"c":{"u":1}', with_type=False, as_array=True)
    assert as_arr.startswith("[{")
    assert as_arr.endswith(":{}")


def test_apply_currency_modes():
    base = '{"k":1}'
    assert apply_currency_if_needed(base, "ref") == base
    assert apply_currency_if_needed(base, "json_key") == base
    wrapped = apply_currency_if_needed(base, "currency")
    assert "java.util.Currency" in wrapped
    assert apply_currency_if_needed(base, "currency_json_key").count("Currency") == 1


def test_normalize_rejects_unknown():
    with pytest.raises(ValueError):
        normalize_getter_trigger("nope")
