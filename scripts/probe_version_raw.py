"""Dump raw responses for key version probes against matrix labs."""

from __future__ import annotations

import json

from fastjson_toolkit.http.client import HttpClient
from fastjson_toolkit.version.detector import response_errored
from fastjson_toolkit.version.probes import (
    AUTOCLOSEABLE_EXACT,
    AUTOTYPE_CLASS,
    AUTOTYPE_RANDOM,
    OFFLINE_AUTOCLOSEABLE,
    OFFLINE_CLASS_JDBC,
    OFFLINE_EXCEPTION,
    OFFLINE_JDBC,
    PROBE_1_2_83,
    SAFEMODE_STRING,
)

PROBES = [
    AUTOTYPE_CLASS,
    AUTOTYPE_RANDOM,
    SAFEMODE_STRING,
    AUTOCLOSEABLE_EXACT,
    PROBE_1_2_83,
    OFFLINE_EXCEPTION,
    OFFLINE_AUTOCLOSEABLE,
    OFFLINE_CLASS_JDBC,
    OFFLINE_JDBC,
]

TARGETS = [
    ("1.2.30", "http://127.0.0.1:18030/api/fastjson"),
    ("1.2.47", "http://127.0.0.1:18047/api/fastjson"),
    ("1.2.68", "http://127.0.0.1:18068/api/fastjson"),
    ("1.2.80", "http://127.0.0.1:18082/api/fastjson"),
    ("1.2.83", "http://127.0.0.1:18080/api/fastjson"),
]


def main() -> None:
    client = HttpClient(timeout=8.0)
    try:
        for name, url in TARGETS:
            print(f"\n===== {name} {url} =====")
            for probe in PROBES:
                resp = client.post_raw(url, probe.payload)
                err = response_errored(resp)
                excerpt = resp.text.replace("\n", " ")[:160]
                print(
                    f"{probe.id:22} status={resp.status_code} errored={err} "
                    f"body={excerpt}"
                )
    finally:
        client.close()


if __name__ == "__main__":
    main()
