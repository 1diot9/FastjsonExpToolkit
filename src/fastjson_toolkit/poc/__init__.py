"""各版本 Fastjson PoC。"""

from fastjson_toolkit.poc.getter import (
    GETTER_TRIGGER_CHOICES,
    GetterTrigger,
    apply_currency_if_needed,
    wrap_with_currency,
)
from fastjson_toolkit.poc.cve_2026_16723 import (
    Poc16723Options,
    Poc16723Result,
    run_cve_2026_16723,
)
from fastjson_toolkit.poc.v1_2_47 import (
    Poc1247GenerateOptions,
    Poc1247GenerateResult,
    Poc1247SendOptions,
    Poc1247SendResult,
    generate_poc_1247,
    list_gadgets as list_poc_1247_gadgets,
    run_poc_1247,
)
from fastjson_toolkit.poc.v1_2_68 import (
    Poc1268GenerateOptions,
    Poc1268GenerateResult,
    Poc1268SendOptions,
    Poc1268SendResult,
    generate_poc_1268,
    list_gadgets as list_poc_1268_gadgets,
    run_poc_1268,
)
from fastjson_toolkit.poc.v1_2_80 import (
    Poc1280GenerateOptions,
    Poc1280GenerateResult,
    Poc1280SendOptions,
    Poc1280SendResult,
    generate_poc_1280,
    list_gadgets as list_poc_1280_gadgets,
    run_poc_1280,
)

__all__ = [
    "GETTER_TRIGGER_CHOICES",
    "GetterTrigger",
    "Poc1247GenerateOptions",
    "Poc1247GenerateResult",
    "Poc1247SendOptions",
    "Poc1247SendResult",
    "Poc1268GenerateOptions",
    "Poc1268GenerateResult",
    "Poc1268SendOptions",
    "Poc1268SendResult",
    "Poc1280GenerateOptions",
    "Poc1280GenerateResult",
    "Poc1280SendOptions",
    "Poc1280SendResult",
    "Poc16723Options",
    "Poc16723Result",
    "apply_currency_if_needed",
    "generate_poc_1247",
    "generate_poc_1268",
    "generate_poc_1280",
    "list_poc_1247_gadgets",
    "list_poc_1268_gadgets",
    "list_poc_1280_gadgets",
    "run_cve_2026_16723",
    "run_poc_1247",
    "run_poc_1268",
    "run_poc_1280",
    "wrap_with_currency",
]
