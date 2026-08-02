"""Fastjson ≤1.2.68（AutoCloseable expectClass）证明 PoC。"""

from fastjson_toolkit.poc.v1_2_68.catalog import GADGETS, get_gadget, list_gadgets
from fastjson_toolkit.poc.v1_2_68.models import (
    Poc1268GenerateOptions,
    Poc1268GenerateResult,
    Poc1268SendOptions,
    Poc1268SendResult,
)
from fastjson_toolkit.poc.v1_2_68.payloads import build_payload
from fastjson_toolkit.poc.v1_2_68.service import generate_poc_1268, run_poc_1268

__all__ = [
    "GADGETS",
    "Poc1268GenerateOptions",
    "Poc1268GenerateResult",
    "Poc1268SendOptions",
    "Poc1268SendResult",
    "build_payload",
    "generate_poc_1268",
    "get_gadget",
    "list_gadgets",
    "run_poc_1268",
]
