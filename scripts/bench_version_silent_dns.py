"""Benchmark 4-band version detection (note §2/§4/§5).

PRIMARY (gate):
  - silent + DNS for <=47 / 1.2.83
  - echo + DNS for <=68 / <=80  (1.2.68 vs hardcoded 1.2.76)
SECONDARY: all-silent + DNS (best-effort; 68 vs 80 may collapse)
"""

from __future__ import annotations

import json
import sys

from fastjson_toolkit.config import load_dotenv
from fastjson_toolkit.dnslog import CeyeConfig
from fastjson_toolkit.version import FastjsonVersionDetector

EXPECT = {
    "1.2.30": "<=1.2.47",
    "1.2.47": "<=1.2.47",
    "1.2.68": "<=1.2.68",
    "1.2.80": "<=1.2.80",
    "1.2.83": "1.2.83",
}

# Stable four-band path used in practice.
TARGETS_PRIMARY = [
    ("1.2.30-silent", "1.2.30", "http://127.0.0.1:18030/api/fastjson/silent"),
    ("1.2.47-silent", "1.2.47", "http://127.0.0.1:18047/api/fastjson/silent"),
    ("1.2.68-echo", "1.2.68", "http://127.0.0.1:18068/api/fastjson"),
    ("1.2.80-echo", "1.2.80", "http://127.0.0.1:18082/api/fastjson"),
    ("1.2.83-silent", "1.2.83", "http://127.0.0.1:18080/api/fastjson/silent"),
]

# All silent — documents §5 AutoCloseable gap on 1.2.80 raw parse.
TARGETS_SILENT = [
    ("1.2.30-silent", "1.2.30", "http://127.0.0.1:18030/api/fastjson/silent"),
    ("1.2.47-silent", "1.2.47", "http://127.0.0.1:18047/api/fastjson/silent"),
    ("1.2.68-silent", "1.2.68", "http://127.0.0.1:18068/api/fastjson/silent"),
    ("1.2.80-silent", "1.2.80", "http://127.0.0.1:18082/api/fastjson/silent"),
    ("1.2.83-silent", "1.2.83", "http://127.0.0.1:18080/api/fastjson/silent"),
]


def run_suite(targets, ceye, include_dns: bool) -> list[dict]:
    rows = []
    for name, actual, url in targets:
        detector = FastjsonVersionDetector(
            timeout=10.0,
            ceye=ceye if include_dns else None,
            ceye_wait=12.0,
        )
        try:
            result = detector.detect(url, include_dns=include_dns)
        finally:
            detector.close()
        expected = EXPECT[actual]
        got = FastjsonVersionDetector.normalize_band(result.version_range) or result.version_range
        verdict = "PASS" if got == expected else "FAIL"
        row = {
            "target": name,
            "actual": actual,
            "expected": expected,
            "got": got,
            "raw_range": result.version_range,
            "verdict": verdict,
            "confidence": result.confidence,
            "autotype": result.autotype_enabled,
            "echo": result.reported_version,
            "offline": result.raw.get("offline_flags"),
            "dns_hits": result.dns_hits,
            "dns_records": len(result.dns_records),
        }
        rows.append(row)
        print(
            f"{verdict:4} {name:22} expect={expected:8} got={got!r:10} "
            f"conf={result.confidence:.2f} echo={result.reported_version!r} "
            f"dns={result.dns_hits}"
        )
    return rows


def main() -> int:
    load_dotenv()
    ceye = CeyeConfig.from_env()
    if ceye is None:
        print("CEYE not configured; abort", file=sys.stderr)
        return 2

    print("=== PRIMARY: DNS + (silent|echo) four-band gate ===")
    primary = run_suite(TARGETS_PRIMARY, ceye, include_dns=True)
    p_pass = sum(1 for r in primary if r["verdict"] == "PASS")
    print(f"PRIMARY SCORE {p_pass}/{len(primary)}\n")

    print("=== SECONDARY: all-silent + DNS (best-effort) ===")
    secondary = run_suite(TARGETS_SILENT, ceye, include_dns=True)
    s_pass = sum(1 for r in secondary if r["verdict"] == "PASS")
    print(f"SECONDARY SCORE {s_pass}/{len(secondary)}")

    out = {"primary": primary, "secondary": secondary}
    print("---JSON---")
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if p_pass == len(primary) else 1


if __name__ == "__main__":
    sys.exit(main())
