"""Run version detector against local Fastjson version matrix labs."""

from __future__ import annotations

import json
import sys

from fastjson_toolkit.version import FastjsonVersionDetector

TARGETS = [
    ("1.2.30", "http://127.0.0.1:18030/api/fastjson"),
    ("1.2.30-at", "http://127.0.0.1:18030/api/fastjson/autotype"),
    ("1.2.47", "http://127.0.0.1:18047/api/fastjson"),
    ("1.2.47-at", "http://127.0.0.1:18047/api/fastjson/autotype"),
    ("1.2.68", "http://127.0.0.1:18068/api/fastjson"),
    ("1.2.68-at", "http://127.0.0.1:18068/api/fastjson/autotype"),
    ("1.2.80", "http://127.0.0.1:18082/api/fastjson"),
    ("1.2.80-at", "http://127.0.0.1:18082/api/fastjson/autotype"),
    ("1.2.83", "http://127.0.0.1:18080/api/fastjson"),
]


def main() -> int:
    rows = []
    for name, url in TARGETS:
        detector = FastjsonVersionDetector(timeout=8.0)
        try:
            result = detector.detect(url, include_dns=False)
        finally:
            detector.close()
        row = {
            "target": name,
            "version_range": result.version_range,
            "confidence": result.confidence,
            "echo": result.reported_version,
            "autotype": result.autotype_enabled,
            "safemode": result.safemode_enabled,
            "p83": result.is_1_2_83_hint,
            "offline": result.raw.get("offline_flags"),
            "error_surface": result.raw.get("error_surface"),
            "summary": result.summary,
        }
        rows.append(row)
        print(
            f"{name:10} range={result.version_range!r:45} "
            f"conf={result.confidence:.2f} echo={result.reported_version!r:8} "
            f"at={result.autotype_enabled} sm={result.safemode_enabled} "
            f"p83={result.is_1_2_83_hint} "
            f"offline={result.raw.get('offline_flags')}"
        )
    print("---JSON---")
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
