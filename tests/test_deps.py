from fastjson_toolkit.deps.catalog import DepEntry, default_catalog, parse_jar_list_text
from fastjson_toolkit.deps.probes import (
    character_payload,
    dns_locale_payload,
    response_indicates_class_absent,
    response_indicates_class_present,
)


def test_catalog_unique_classes():
    catalog = default_catalog()
    classes = [e.clazz for e in catalog]
    assert len(classes) == len(set(classes))
    assert len(catalog) >= 20


def test_parse_jar_list_text():
    text = """
# comment
org.springframework.web.bind.annotation.RequestMapping //SpringBoot
groovy.lang.GroovyShell //Groovy

invalid line without marker
"""
    entries = parse_jar_list_text(text)
    assert len(entries) == 2
    assert entries[0].description == "SpringBoot"
    assert entries[1].clazz == "groovy.lang.GroovyShell"


def test_character_payload_template():
    payload = character_payload("java.net.http.HttpClient")
    assert '"@type":"java.lang.Character"' in payload
    assert '"val":"java.net.http.HttpClient"' in payload
    assert "${clazz}" not in payload


def test_dns_locale_payload_template():
    payload = dns_locale_payload("groovy.lang.GroovyShell", "abc.ceye.io")
    assert "groovy.lang.GroovyShell" in payload
    assert "abc.ceye.io" in payload
    assert "${clazz}" not in payload
    assert "${dns_host}" not in payload


def test_cast_marker_detection():
    assert response_indicates_class_present(
        "com.alibaba.fastjson.JSONException: can not cast to char, value : ..."
    )
    assert not response_indicates_class_present("No message available")
    assert not response_indicates_class_present("")
    assert response_indicates_class_absent("No message available")
    assert response_indicates_class_absent("autoType is not support")
    assert not response_indicates_class_absent("ok")


def test_explicit_classes_bypass_category_filter():
    catalog = default_catalog()
    categories = ["spring"]
    classes = ["groovy.lang.GroovyShell"]
    cats = {c.strip().lower() for c in categories}
    filtered = [e for e in catalog if e.category.lower() in cats]
    wanted = set(classes)
    known = {e.clazz: e for e in catalog if e.clazz in wanted}
    selected = [
        known[c] if c in known else DepEntry(clazz=c, description=c) for c in wanted
    ]
    assert any(e.clazz == "groovy.lang.GroovyShell" for e in selected)
    assert not any(e.clazz == "groovy.lang.GroovyShell" for e in filtered)
