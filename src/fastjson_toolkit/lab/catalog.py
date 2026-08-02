"""Docker lab catalog — local reproduce environments only."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LabSpec:
    id: str
    name: str
    description: str
    category: str
    compose_rel: str
    services: tuple[str, ...]
    ports: tuple[int, ...]
    container_names: tuple[str, ...]
    endpoints: tuple[str, ...] = field(default_factory=tuple)
    notes: str = ""


# Ports / compose layout mirror lab/README.md
LABS: tuple[LabSpec, ...] = (
    LabSpec(
        id="json-fingerprint",
        name="指纹对照",
        description="多 JSON 库对照，验证识别引擎",
        category="fingerprint",
        compose_rel="lab",
        services=("json-fingerprint-lab",),
        ports=(18080,),
        container_names=("json-fingerprint-lab",),
        endpoints=("http://127.0.0.1:18080/api/fastjson",),
        notes="对应 /detect、/expect、/deps",
    ),
    LabSpec(
        id="fj-1-2-30",
        name="版本矩阵 1.2.30",
        description="固定 Fastjson 1.2.30，验证版本探测",
        category="version",
        compose_rel="lab",
        services=("fj-1-2-30",),
        ports=(18030,),
        container_names=("fj-1-2-30",),
        endpoints=("http://127.0.0.1:18030/api/fastjson",),
    ),
    LabSpec(
        id="fj-1-2-47",
        name="版本矩阵 1.2.47",
        description="固定 Fastjson 1.2.47（无 gadget 依赖）",
        category="version",
        compose_rel="lab",
        services=("fj-1-2-47",),
        ports=(18047,),
        container_names=("fj-1-2-47",),
        endpoints=("http://127.0.0.1:18047/api/fastjson",),
        notes="gadget 请用 ≤1.2.47 专用靶场 :18147",
    ),
    LabSpec(
        id="fj-1-2-68",
        name="版本矩阵 1.2.68",
        description="固定 Fastjson 1.2.68（无 gadget 依赖）",
        category="version",
        compose_rel="lab",
        services=("fj-1-2-68",),
        ports=(18068,),
        container_names=("fj-1-2-68",),
        endpoints=("http://127.0.0.1:18068/api/fastjson",),
    ),
    LabSpec(
        id="fj-1-2-80",
        name="版本矩阵 1.2.80",
        description="固定 Fastjson 1.2.80（无 gadget 依赖）",
        category="version",
        compose_rel="lab",
        services=("fj-1-2-80",),
        ports=(18082,),
        container_names=("fj-1-2-80",),
        endpoints=("http://127.0.0.1:18082/api/fastjson",),
    ),
    LabSpec(
        id="fastjson-1247",
        name="≤1.2.47 gadget",
        description="Class 缓存绕过 + 依赖链落盘证明",
        category="gadget",
        compose_rel="lab/fastjson-1247-lab",
        services=("fastjson-1247-lab",),
        ports=(18147,),
        container_names=("fastjson-1247-lab",),
        endpoints=("http://127.0.0.1:18147/api/fastjson",),
        notes="对应 /poc → ≤1.2.47",
    ),
    LabSpec(
        id="fastjson-1268",
        name="≤1.2.68 gadget",
        description="AutoCloseable expectClass 落盘证明",
        category="gadget",
        compose_rel="lab/fastjson-1268-lab",
        services=("fastjson-1268-lab",),
        ports=(18168,),
        container_names=("fastjson-1268-lab",),
        endpoints=("http://127.0.0.1:18168/api/fastjson",),
        notes="对应 /poc → ≤1.2.68",
    ),
    LabSpec(
        id="fastjson-1280",
        name="≤1.2.80 gadget",
        description="Exception 缓存绕过落盘证明",
        category="gadget",
        compose_rel="lab/fastjson-1280-lab",
        services=("fastjson-1280-lab",),
        ports=(18180,),
        container_names=("fastjson-1280-lab",),
        endpoints=("http://127.0.0.1:18180/api/fastjson",),
        notes="对应 /poc → ≤1.2.80",
    ),
    LabSpec(
        id="cve-2026-16723",
        name="CVE-2026-16723",
        description="1.2.83 jar:http / fd-cache 证明（Undertow）",
        category="cve",
        compose_rel="lab/cve-2026-16723",
        services=("fastjson-undertow",),
        ports=(18083, 15005),
        container_names=("cve-2026-16723-undertow",),
        endpoints=("http://127.0.0.1:18083/json",),
        notes="HTTP :18083，JDWP :15005；对应 /poc → CVE",
    ),
)

_LAB_BY_ID = {lab.id: lab for lab in LABS}


def get_lab(lab_id: str) -> LabSpec | None:
    return _LAB_BY_ID.get(lab_id)


def all_labs() -> list[LabSpec]:
    return list(LABS)
