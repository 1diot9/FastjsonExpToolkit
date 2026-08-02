from fastjson_toolkit.http.client import HttpResponse
from fastjson_toolkit.version.detector import FastjsonVersionDetector, response_errored
from fastjson_toolkit.version.models import VersionEvidence
from fastjson_toolkit.version.probes import (
    SAFEMODE_STRING,
    all_version_probes,
    build_dns_version_probes,
    validate_dns_host,
)
import pytest


def test_version_probe_ids_unique():
    probes = all_version_probes(
        {
            "le47": "le47.example.ceye.io",
            "le68": "le68.example.ceye.io",
            "d80a": "d80a.example.ceye.io",
            "d80b": "d80b.example.ceye.io",
        }
    )
    ids = [p.id for p in probes]
    assert len(ids) == len(set(ids))


def test_dns_version_payload_hosts():
    probes = build_dns_version_probes(
        {
            "le47": "aaa.example.ceye.io",
            "le68": "bbb.example.ceye.io",
            "d80a": "ccc.example.ceye.io",
            "d80b": "ddd.example.ceye.io",
        }
    )
    by_id = {p.id: p.payload for p in probes}
    assert "aaa.example.ceye.io" in by_id["dns_le_1_2_47"]
    assert "bbb.example.ceye.io" in by_id["dns_le_1_2_68"]
    assert "ccc.example.ceye.io" in by_id["dns_1_2_80_83"]
    assert "ddd.example.ceye.io" in by_id["dns_1_2_80_83"]
    assert 'InetSocketAddress"{"address":,' in by_id["dns_le_1_2_47"]


def test_response_errored_status_and_markers():
    assert response_errored(HttpResponse(500, "oops", 1.0, {}))
    assert response_errored(
        HttpResponse(200, "autoType is not support. Random.String", 1.0, {})
    )
    assert not response_errored(HttpResponse(200, '{"a":1}', 1.0, {}))
    assert response_errored(HttpResponse(500, '{"ok":false}', 1.0, {}))


def test_offline_bands_autotype_off():
    cases = [
        ({"exception_ok": True, "autoclosable_ok": True, "class_jdbc_ok": True, "jdbc_ok": True}, "<=1.2.47"),
        ({"exception_ok": False, "autoclosable_ok": True, "class_jdbc_ok": True, "jdbc_ok": False}, "<=1.2.47"),
        ({"exception_ok": False, "autoclosable_ok": True, "class_jdbc_ok": True, "jdbc_ok": True}, "<=1.2.47"),
        ({"exception_ok": False, "autoclosable_ok": True, "class_jdbc_ok": False, "jdbc_ok": False}, "<=1.2.68"),
        ({"exception_ok": False, "autoclosable_ok": False, "class_jdbc_ok": False, "jdbc_ok": False}, "<=1.2.80"),
        ({"exception_ok": True, "autoclosable_ok": False, "class_jdbc_ok": False, "jdbc_ok": False}, "1.2.83"),
        ({"exception_ok": True, "autoclosable_ok": True, "class_jdbc_ok": False, "jdbc_ok": False}, "1.2.83"),
    ]
    for offline, expected in cases:
        band, conf = FastjsonVersionDetector._infer_band(
            None, None, offline, True, False, None
        )
        assert band == expected
        assert conf >= 0.8


def test_echo_maps_to_bands():
    assert FastjsonVersionDetector._band_from_echo("1.2.47") == "<=1.2.47"
    assert FastjsonVersionDetector._band_from_echo("1.2.68") == "<=1.2.68"
    assert FastjsonVersionDetector._band_from_echo("1.2.76") == "<=1.2.80"
    assert FastjsonVersionDetector._band_from_echo("1.2.83") == "1.2.83"


def test_dns_exclusive_bands_when_not_overfired():
    assert FastjsonVersionDetector._infer_from_dns(
        {"le47": False, "le68": False, "d80a": True, "d80b": False}
    )[0] == "<=1.2.80"
    assert FastjsonVersionDetector._infer_from_dns(
        {"le47": False, "le68": True, "d80a": False, "d80b": False}
    )[0] == "<=1.2.68"
    assert FastjsonVersionDetector._infer_from_dns(
        {"le47": True, "le68": False, "d80a": False, "d80b": False}
    )[0] == "<=1.2.47"
    assert FastjsonVersionDetector._infer_from_dns(
        {"le47": False, "le68": False, "d80a": True, "d80b": True}
    )[0] == "1.2.83"


def test_dns_overfire_defers_to_offline():
    # le47+d80a together → DNS alone returns None; offline decides.
    assert FastjsonVersionDetector._infer_from_dns(
        {"le47": True, "le68": True, "d80a": True, "d80b": False}
    )[0] is None
    band, conf = FastjsonVersionDetector._infer_band(
        None,
        False,
        {
            "exception_ok": False,
            "autoclosable_ok": True,
            "class_jdbc_ok": False,
            "jdbc_ok": False,
        },
        True,
        False,
        {"le47": True, "le68": True, "d80a": True, "d80b": False},
    )
    assert band == "<=1.2.68"
    assert conf >= 0.8


def test_dual_dns_wins_for_83():
    band, conf = FastjsonVersionDetector._infer_band(
        None,
        True,
        {
            "exception_ok": True,
            "autoclosable_ok": True,
            "class_jdbc_ok": False,
            "jdbc_ok": False,
        },
        True,
        False,
        {"le47": True, "le68": True, "d80a": True, "d80b": True},
    )
    assert band == "1.2.83"
    assert conf >= 0.85


def test_echo_176_maps_to_le80_band():
    band, conf = FastjsonVersionDetector._infer_band(
        "1.2.76",
        False,
        {
            "exception_ok": False,
            "autoclosable_ok": True,
            "class_jdbc_ok": False,
            "jdbc_ok": False,
        },
        True,
        False,
        {"le47": True, "le68": True, "d80a": True, "d80b": False},
    )
    assert band == "<=1.2.80"
    assert conf >= 0.9


def test_validate_dns_host_rejects_quotes():
    with pytest.raises(ValueError):
        validate_dns_host('evil".ceye.io')


def test_safemode_probe_payload():
    assert SAFEMODE_STRING.payload == '{"zero":{"@type":"java.lang.String"""}}}'
    assert SAFEMODE_STRING.id == "safemode_string"


def test_probe_safemode_errored_means_on(monkeypatch):
    det = FastjsonVersionDetector.__new__(FastjsonVersionDetector)
    evidence: list[VersionEvidence] = []

    monkeypatch.setattr(
        det,
        "_send",
        lambda url, probe: HttpResponse(400, "com.alibaba.fastjson.JSONException", 1.0, {}),
    )
    assert det._probe_safemode("http://example/", evidence) is True
    assert evidence[-1].errored is True

    evidence.clear()
    monkeypatch.setattr(
        det,
        "_send",
        lambda url, probe: HttpResponse(200, '{"ok":true}', 1.0, {}),
    )
    assert det._probe_safemode("http://example/", evidence) is False
    assert evidence[-1].errored is False
