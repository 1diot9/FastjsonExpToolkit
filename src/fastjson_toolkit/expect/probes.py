"""Payload builders for expected-class (期望类) probes.

Notes:
1. ``{"@type":"com.alibaba.fastjson.support.geo.Feature", ...}`` 报错 → 可能存在期望类
   （Feature 自 1.2.68 引入；低于该版本也会因类不存在而报错）
2. 根级 ``{ {}: {}, ... }`` 报错且期望类型不是 Map → 存在期望类
3. 嵌套 ``"test": { { {}: {} }: "" }`` 作为对照，通常不报错
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional, Union

FEATURE_TYPE = "com.alibaba.fastjson.support.geo.Feature"
DEFAULT_BASE_BODY = '{"age":20,"name":"Bob"}'


@dataclass(frozen=True)
class ExpectProbe:
    id: str
    category: str
    description: str
    payload: str


JsonValue = Union[dict[str, Any], list[Any], str, int, float, bool, None]


def parse_base_body(base_body: str) -> JsonValue:
    text = (base_body or "").strip() or DEFAULT_BASE_BODY
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"base_body 不是合法 JSON: {exc}") from exc


def _object_inner(obj: dict[str, Any]) -> str:
    if not obj:
        return ""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))[1:-1]


def _inject_into_object(obj: dict[str, Any], prefix_inner: str) -> str:
    rest = _object_inner(obj)
    if rest:
        return "{" + prefix_inner + "," + rest + "}"
    return "{" + prefix_inner + "}"


def _inject_into_array(arr: list[Any], merge_object) -> str:
    if not arr:
        raise ValueError("数组 base_body 不能为空")
    if not isinstance(arr[0], dict):
        raise ValueError("数组 base_body 的首元素必须是对象，才能注入期望类探针")
    first = merge_object(arr[0])
    if len(arr) == 1:
        return "[" + first + "]"
    rest = json.dumps(arr[1:], ensure_ascii=False, separators=(",", ":"))
    # rest like `[...]` → splice after first element
    return "[" + first + "," + rest[1:]


def build_feature_payload(base: JsonValue) -> str:
    """Merge Feature @type into original object / first array element."""
    prefix = f'"@type":"{FEATURE_TYPE}"'
    if isinstance(base, dict):
        return _inject_into_object(base, prefix)
    if isinstance(base, list):
        return _inject_into_array(base, lambda o: _inject_into_object(o, prefix))
    raise ValueError("base_body 须为 JSON 对象或对象数组")


def build_empty_key_payload(base: JsonValue) -> str:
    """Root-level Fastjson ``{ {}: {}, ... }`` probe."""
    prefix = "{}:{}"
    if isinstance(base, dict):
        return _inject_into_object(base, prefix)
    if isinstance(base, list):
        return _inject_into_array(base, lambda o: _inject_into_object(o, prefix))
    raise ValueError("base_body 须为 JSON 对象或对象数组")


def build_nested_empty_key_payload(base: JsonValue) -> str:
    """Nested control: ``"test": { { {}: {} }: "" }`` should usually not error."""
    nested = '"test":{{{}:{}}:""}'
    if isinstance(base, dict):
        return _inject_into_object(base, nested)
    if isinstance(base, list):
        return _inject_into_array(base, lambda o: _inject_into_object(o, nested))
    raise ValueError("base_body 须为 JSON 对象或对象数组")


def baseline_payload(base: JsonValue) -> str:
    return json.dumps(base, ensure_ascii=False, separators=(",", ":"))


def build_all_payloads(base_body: Optional[str] = None) -> dict[str, str]:
    base = parse_base_body(base_body or DEFAULT_BASE_BODY)
    return {
        "baseline": baseline_payload(base),
        "feature": build_feature_payload(base),
        "empty_key": build_empty_key_payload(base),
        "nested_empty_key": build_nested_empty_key_payload(base),
    }


def all_expect_probes(base_body: Optional[str] = None) -> list[ExpectProbe]:
    payloads = build_all_payloads(base_body)
    return [
        ExpectProbe(
            id="baseline",
            category="control",
            description="原始请求参数基线；若基线即报错，后续信号降权",
            payload=payloads["baseline"],
        ),
        ExpectProbe(
            id="feature_type",
            category="feature",
            description=(
                "注入 @type=com.alibaba.fastjson.support.geo.Feature；"
                "报错提示存在期望类（或版本 <1.2.68 类不存在）"
            ),
            payload=payloads["feature"],
        ),
        ExpectProbe(
            id="empty_key_root",
            category="empty_key",
            description="根级 { {}: {} }；报错且类型非 Map → 存在期望类",
            payload=payloads["empty_key"],
        ),
        ExpectProbe(
            id="empty_key_nested",
            category="control",
            description='嵌套 "test": { { {}: {} }: "" } 对照；通常不报错',
            payload=payloads["nested_empty_key"],
        ),
    ]
