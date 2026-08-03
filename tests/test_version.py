from fastjson_toolkit.http.client import HttpResponse
from fastjson_toolkit.version.detector import (
    FastjsonVersionDetector,
    ResponseSig,
    response_errored,
)
from fastjson_toolkit.version.models import VersionEvidence
from fastjson_toolkit.version.probes import (
    SAFEMODE_STRING,
    all_version_probes,
    build_dns_version_probes,
    inject_probe_into_object,
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
    assert "baseline_ok" in ids


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
    assert response_errored(HttpResponse(200, "error", 1.0, {}))
    assert response_errored(HttpResponse(200, '{"ok":false}', 1.0, {}))
    assert response_errored(HttpResponse(200, '{"error":"bad"}', 1.0, {}))


def test_response_errored_matches_error_fingerprint():
    err = ResponseSig(200, "error")
    assert response_errored(HttpResponse(200, "error", 1.0, {}), error_sig=err)
    assert not response_errored(HttpResponse(200, '{"x":1}', 1.0, {}), error_sig=err)


def test_inject_probe_into_object_keeps_dual_atype():
    out = inject_probe_into_object(
        '{"page":{"pageNumber":1,"pageSize":1}}',
        '{"zero":{"@type":"java.lang.Exception","@type":"org.XxException"}}',
    )
    assert out.startswith('{"page":')
    assert '"@type":"java.lang.Exception","@type":"org.XxException"' in out


def test_offline_bands_autotype_off():
    cases = [
        (
            {"exception_ok": True, "autoclosable_ok": True, "class_jdbc_ok": True, "jdbc_ok": True},
            "<=1.2.47",
            "≈1.2.24",
        ),
        (
            {"exception_ok": False, "autoclosable_ok": True, "class_jdbc_ok": True, "jdbc_ok": False},
            "<=1.2.47",
            "1.2.25-1.2.47",
        ),
        (
            {"exception_ok": False, "autoclosable_ok": True, "class_jdbc_ok": True, "jdbc_ok": True},
            "<=1.2.47",
            "1.2.25-1.2.47",
        ),
        (
            {"exception_ok": False, "autoclosable_ok": True, "class_jdbc_ok": False, "jdbc_ok": False},
            "<=1.2.68",
            "1.2.48-1.2.68",
        ),
        (
            {"exception_ok": False, "autoclosable_ok": False, "class_jdbc_ok": False, "jdbc_ok": False},
            "<=1.2.80",
            "1.2.70-1.2.80",
        ),
        (
            {"exception_ok": True, "autoclosable_ok": False, "class_jdbc_ok": False, "jdbc_ok": False},
            "1.2.83",
            "1.2.83",
        ),
        (
            {"exception_ok": True, "autoclosable_ok": True, "class_jdbc_ok": False, "jdbc_ok": False},
            "1.2.83",
            "1.2.83",
        ),
    ]
    for offline, expected_band, expected_detail in cases:
        band, detail, conf = FastjsonVersionDetector._infer_band(
            None, None, offline, True, False, None
        )
        assert band == expected_band
        assert detail == expected_detail
        assert conf >= 0.75


def test_echo_maps_to_bands():
    assert FastjsonVersionDetector._band_from_echo("1.2.47") == ("<=1.2.47", "1.2.25-1.2.47")
    assert FastjsonVersionDetector._band_from_echo("1.2.68") == ("<=1.2.68", "1.2.48-1.2.68")
    assert FastjsonVersionDetector._band_from_echo("1.2.76") == ("<=1.2.80", "1.2.76-1.2.80")
    assert FastjsonVersionDetector._band_from_echo("1.2.83") == ("1.2.83", "1.2.83")
    assert FastjsonVersionDetector._band_from_echo("1.2.71") == ("<=1.2.80", "1.2.70-1.2.72")
    assert FastjsonVersionDetector._band_from_echo("1.2.80") == ("<=1.2.80", "1.2.73-1.2.80")


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
    band, detail, conf = FastjsonVersionDetector._infer_band(
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
    assert detail == "1.2.48-1.2.68"
    assert conf >= 0.8


def test_dual_dns_wins_for_83():
    band, detail, conf = FastjsonVersionDetector._infer_band(
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
    assert detail == "1.2.83"
    assert conf >= 0.85


def test_echo_176_maps_to_le80_band():
    band, detail, conf = FastjsonVersionDetector._infer_band(
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
    assert detail == "1.2.76-1.2.80"
    assert conf >= 0.9


def test_validate_dns_host_rejects_quotes():
    with pytest.raises(ValueError):
        validate_dns_host('evil".ceye.io')


def test_safemode_probe_payload():
    assert SAFEMODE_STRING.payload == '{"zero":{"@type":"java.lang.String"""}}}'
    assert SAFEMODE_STRING.id == "safemode_string"


def test_probe_safemode_skips_without_error_surface():
    det = FastjsonVersionDetector.__new__(FastjsonVersionDetector)
    det._error_sig = None
    evidence: list[VersionEvidence] = []
    assert det._probe_safemode("http://example/", evidence, error_surface=False) is None
    assert evidence[-1].matched == ["skipped_no_error_surface"]


def test_probe_safemode_errored_means_pending(monkeypatch):
    det = FastjsonVersionDetector.__new__(FastjsonVersionDetector)
    det._error_sig = None
    evidence: list[VersionEvidence] = []

    monkeypatch.setattr(
        det,
        "_send",
        lambda url, probe: HttpResponse(
            400, "com.alibaba.fastjson.JSONException: not close json text", 1.0, {}
        ),
    )
    assert det._probe_safemode("http://example/", evidence, error_surface=True) is True
    assert "errored_pending_crosscheck" in evidence[-1].matched

    evidence.clear()
    monkeypatch.setattr(
        det,
        "_send",
        lambda url, probe: HttpResponse(200, '{"ok":true}', 1.0, {}),
    )
    assert det._probe_safemode("http://example/", evidence, error_surface=True) is False
    assert evidence[-1].errored is False


def test_probe_safemode_marker_means_on(monkeypatch):
    det = FastjsonVersionDetector.__new__(FastjsonVersionDetector)
    det._error_sig = None
    evidence: list[VersionEvidence] = []
    monkeypatch.setattr(
        det,
        "_send",
        lambda url, probe: HttpResponse(
            400, "safeMode not support autoType : java.lang.String", 1.0, {}
        ),
    )
    assert det._probe_safemode("http://example/", evidence, error_surface=True) is True
    assert "safemode_marker" in evidence[-1].matched


def test_safemode_crosscheck_downgrades_when_autotype_off():
    det = FastjsonVersionDetector.__new__(FastjsonVersionDetector)
    evidence: list[VersionEvidence] = [
        VersionEvidence(
            probe_id="safemode_string",
            category="safemode",
            description="x",
            matched=["errored_pending_crosscheck"],
            response_excerpt="not close json text, token : }",
        )
    ]
    out = det._crosscheck_safemode(
        True,
        offline_flags={"autoclosable_ok": False},
        reported_version=None,
        autotype_enabled=False,
        error_surface=True,
        version_range="<=1.2.80",
        evidence=evidence,
    )
    assert out is False
    assert "AutoType 关闭形态（java.lang.Class @type 仍可用）" in evidence[-1].matched


def test_safemode_crosscheck_downgrades_for_pre_safemode_band():
    det = FastjsonVersionDetector.__new__(FastjsonVersionDetector)
    evidence: list[VersionEvidence] = []
    out = det._crosscheck_safemode(
        True,
        offline_flags={"autoclosable_ok": False},
        reported_version=None,
        autotype_enabled=None,
        error_surface=True,
        version_range="<=1.2.47",
        evidence=evidence,
    )
    assert out is False
    assert "version_range<=1.2.47" in evidence[-1].matched


def test_safemode_crosscheck_downgrades_when_autoclosable_ok():
    det = FastjsonVersionDetector.__new__(FastjsonVersionDetector)
    evidence: list[VersionEvidence] = []
    out = det._crosscheck_safemode(
        True,
        offline_flags={"autoclosable_ok": True},
        reported_version=None,
        autotype_enabled=None,
        error_surface=True,
        version_range="<=1.2.80",
        evidence=evidence,
    )
    assert out is False
    assert evidence[-1].probe_id == "safemode_crosscheck"


def test_safemode_crosscheck_syntax_only_without_counter_is_unknown():
    det = FastjsonVersionDetector.__new__(FastjsonVersionDetector)
    evidence: list[VersionEvidence] = [
        VersionEvidence(
            probe_id="safemode_string",
            category="safemode",
            description="x",
            matched=["errored_pending_crosscheck"],
            response_excerpt="JSONException: not close json text, token : }",
        )
    ]
    out = det._crosscheck_safemode(
        True,
        offline_flags={"autoclosable_ok": False},
        reported_version=None,
        autotype_enabled=None,
        error_surface=True,
        version_range="<=1.2.80",
        evidence=evidence,
    )
    assert out is None
    assert "syntax_only_not_close_json" in evidence[-1].matched


def test_safemode_crosscheck_no_error_surface_is_unknown():
    det = FastjsonVersionDetector.__new__(FastjsonVersionDetector)
    evidence: list[VersionEvidence] = []
    assert (
        det._crosscheck_safemode(
            True,
            offline_flags={},
            reported_version=None,
            autotype_enabled=None,
            error_surface=False,
            version_range=None,
            evidence=evidence,
        )
        is None
    )


def test_build_summary_mentions_70_73_gap():
    _summary, actions = FastjsonVersionDetector._build_summary(
        autotype_enabled=False,
        reported_version=None,
        reported_note=None,
        is_83=False,
        version_range="<=1.2.80",
        version_detail="1.2.70-1.2.80",
        confidence=0.85,
        dns_hits={},
        error_surface=True,
    )
    assert any("1.2.70-72" in a for a in actions)
