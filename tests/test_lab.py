"""Docker lab catalog / port helpers (no docker required)."""

from fastjson_toolkit.config import project_root
from fastjson_toolkit.lab.catalog import all_default_ports, all_labs, get_lab
from fastjson_toolkit.lab.docker_env import DockerEnvironment, check_ports
from fastjson_toolkit.lab.service import describe_lab, list_lab_status


def test_lab_catalog_ids_unique():
    labs = all_labs()
    ids = [lab.id for lab in labs]
    assert len(ids) == len(set(ids))
    assert get_lab("json-fingerprint") is not None
    assert get_lab("cve-2026-16723") is not None
    assert get_lab("nope") is None


def test_default_ports_unique():
    ports = all_default_ports()
    assert len(ports) == len(set(ports))
    assert 18247 in ports
    assert 18268 in ports
    assert 18280 in ports
    assert 18505 in ports
    assert 18047 in ports  # version matrix stays distinct from gadget


def test_resolve_port_override():
    lab = get_lab("json-fingerprint")
    assert lab is not None
    m = lab.resolve_ports({"http": 19080})
    assert m["http"] == 19080
    assert lab.compose_env(m)["LAB_PORT_JSON_FINGERPRINT"] == "19080"
    assert "19080" in lab.endpoints_for(m)[0]


def test_lab_compose_files_exist():
    for lab in all_labs():
        compose = project_root().joinpath(*lab.compose_rel.split("/")) / "docker-compose.yml"
        assert compose.is_file(), f"missing {compose}"
        text = compose.read_text(encoding="utf-8")
        for spec in lab.port_specs:
            assert spec.env in text
            assert str(spec.default) in text


def test_check_ports_shape():
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(1)
    try:
        checks = check_ports([port], owned_ports=set())
        assert checks[0].occupied is True
        assert checks[0].owned_by_lab is False
        owned = check_ports([port], owned_ports={port})
        assert owned[0].owned_by_lab is True
    finally:
        sock.close()

    # free high port unlikely reserved
    free = check_ports([60123], owned_ports=set())
    # may still be occupied on some hosts; only assert shape
    assert free[0].port == 60123
    assert isinstance(free[0].occupied, bool)


def test_describe_lab_without_docker_daemon():
    env = DockerEnvironment(
        docker_installed=False,
        docker_running=False,
        compose_available=False,
        compose_backend=None,
        errors=["未找到 docker"],
    )
    lab = get_lab("json-fingerprint")
    assert lab is not None
    status = describe_lab(lab, env=env)
    assert status.can_start is False
    assert status.state == "unknown"
    assert any("docker" in b.lower() or "Docker" in b for b in status.blockers)

    listed = list_lab_status(env=env)
    assert len(listed) == len(all_labs())
