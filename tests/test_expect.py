from fastjson_toolkit.expect.detector import FastjsonExpectClassDetector
from fastjson_toolkit.expect.probes import (
    FEATURE_TYPE,
    build_all_payloads,
    build_empty_key_payload,
    build_feature_payload,
    build_nested_empty_key_payload,
    parse_base_body,
)


def test_feature_payload_object():
    base = parse_base_body('{"username":"admin","password":"123456"}')
    payload = build_feature_payload(base)
    assert payload.startswith("{")
    assert f'"@type":"{FEATURE_TYPE}"' in payload
    assert '"username":"admin"' in payload
    assert '"password":"123456"' in payload


def test_feature_payload_array():
    base = parse_base_body('[{"username":"admin","password":"123456"}]')
    payload = build_feature_payload(base)
    assert payload.startswith("[{")
    assert f'"@type":"{FEATURE_TYPE}"' in payload
    assert payload.endswith("}]")


def test_empty_key_payload():
    base = parse_base_body('{"username":"admin","password":"123456"}')
    payload = build_empty_key_payload(base)
    assert payload.startswith("{{}:{}")
    assert '"username":"admin"' in payload


def test_nested_empty_key_payload():
    base = parse_base_body('{"username":"admin","password":"123456"}')
    payload = build_nested_empty_key_payload(base)
    assert '"test":{{{}:{}}:""}' in payload
    assert '"username":"admin"' in payload


def test_build_all_payloads_keys():
    payloads = build_all_payloads('{"age":20,"name":"Bob"}')
    assert set(payloads) == {"baseline", "feature", "empty_key", "nested_empty_key"}
    assert payloads["baseline"] == '{"age":20,"name":"Bob"}'


def test_infer_has_expect_class():
    has, not_map, lt68, conf, _ = FastjsonExpectClassDetector._infer(
        baseline_err=False,
        feature_err=True,
        empty_err=True,
        nested_err=False,
    )
    assert has is True
    assert not_map is True
    assert lt68 is False
    assert conf >= 0.8


def test_infer_version_lt_68():
    has, not_map, lt68, conf, _ = FastjsonExpectClassDetector._infer(
        baseline_err=False,
        feature_err=True,
        empty_err=False,
        nested_err=False,
    )
    assert has is False
    assert not_map is False
    assert lt68 is True
    assert conf >= 0.7


def test_infer_no_expect_class():
    has, not_map, lt68, conf, _ = FastjsonExpectClassDetector._infer(
        baseline_err=False,
        feature_err=False,
        empty_err=False,
        nested_err=False,
    )
    assert has is False
    assert lt68 is False
    assert conf >= 0.8


def test_infer_baseline_error():
    has, _, _, conf, text = FastjsonExpectClassDetector._infer(
        baseline_err=True,
        feature_err=True,
        empty_err=True,
        nested_err=False,
    )
    assert has is None
    assert conf < 0.5
    assert "基线" in text
