"""Docker lab catalog — local reproduce environments only."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LabPortSpec:
    """One published host port (compose host side)."""

    key: str
    label: str
    env: str
    default: int
    container_port: int


@dataclass(frozen=True)
class LabSpec:
    id: str
    name: str
    description: str
    category: str
    compose_rel: str
    services: tuple[str, ...]
    port_specs: tuple[LabPortSpec, ...]
    container_names: tuple[str, ...]
    # Use {key} placeholders, e.g. http://127.0.0.1:{http}/api/fastjson
    endpoint_templates: tuple[str, ...] = ()
    notes: str = ""

    @property
    def default_ports(self) -> tuple[int, ...]:
        return tuple(p.default for p in self.port_specs)

    @property
    def ports(self) -> tuple[int, ...]:
        """Alias for default host ports (backward compatible)."""
        return self.default_ports

    def resolve_ports(self, overrides: dict[str, int] | None = None) -> dict[str, int]:
        values = {p.key: p.default for p in self.port_specs}
        if overrides:
            for key, port in overrides.items():
                if key not in values:
                    raise ValueError(f"未知端口 key: {key}")
                values[key] = int(port)
        return values

    def ports_list(self, port_map: dict[str, int] | None = None) -> list[int]:
        m = port_map or self.resolve_ports()
        return [m[p.key] for p in self.port_specs]

    def compose_env(self, port_map: dict[str, int] | None = None) -> dict[str, str]:
        m = port_map or self.resolve_ports()
        return {p.env: str(m[p.key]) for p in self.port_specs}

    def endpoints_for(self, port_map: dict[str, int] | None = None) -> list[str]:
        m = port_map or self.resolve_ports()
        return [tpl.format(**m) for tpl in self.endpoint_templates]


# Defaults are all distinct across labs (version matrix vs gadget use different ranges).
LABS: tuple[LabSpec, ...] = (
    LabSpec(
        id="json-fingerprint",
        name="指纹对照",
        description="多 JSON 库对照，验证识别引擎",
        category="fingerprint",
        compose_rel="lab",
        services=("json-fingerprint-lab",),
        port_specs=(
            LabPortSpec(
                key="http",
                label="HTTP",
                env="LAB_PORT_JSON_FINGERPRINT",
                default=18080,
                container_port=18080,
            ),
        ),
        container_names=("json-fingerprint-lab",),
        endpoint_templates=("http://127.0.0.1:{http}/api/fastjson",),
        notes="对应 /detect、/expect、/deps",
    ),
    LabSpec(
        id="fj-1-2-30",
        name="版本矩阵 1.2.30",
        description="固定 Fastjson 1.2.30，验证版本探测",
        category="version",
        compose_rel="lab",
        services=("fj-1-2-30",),
        port_specs=(
            LabPortSpec(
                key="http",
                label="HTTP",
                env="LAB_PORT_FJ_1_2_30",
                default=18030,
                container_port=18080,
            ),
        ),
        container_names=("fj-1-2-30",),
        endpoint_templates=("http://127.0.0.1:{http}/api/fastjson",),
    ),
    LabSpec(
        id="fj-1-2-47",
        name="版本矩阵 1.2.47",
        description="固定 Fastjson 1.2.47（无 gadget 依赖）",
        category="version",
        compose_rel="lab",
        services=("fj-1-2-47",),
        port_specs=(
            LabPortSpec(
                key="http",
                label="HTTP",
                env="LAB_PORT_FJ_1_2_47",
                default=18047,
                container_port=18080,
            ),
        ),
        container_names=("fj-1-2-47",),
        endpoint_templates=("http://127.0.0.1:{http}/api/fastjson",),
        notes="gadget 请用 ≤1.2.47 专用靶场默认 :18247",
    ),
    LabSpec(
        id="fj-1-2-68",
        name="版本矩阵 1.2.68",
        description="固定 Fastjson 1.2.68（无 gadget 依赖）",
        category="version",
        compose_rel="lab",
        services=("fj-1-2-68",),
        port_specs=(
            LabPortSpec(
                key="http",
                label="HTTP",
                env="LAB_PORT_FJ_1_2_68",
                default=18068,
                container_port=18080,
            ),
        ),
        container_names=("fj-1-2-68",),
        endpoint_templates=("http://127.0.0.1:{http}/api/fastjson",),
    ),
    LabSpec(
        id="fj-1-2-80",
        name="版本矩阵 1.2.80",
        description="固定 Fastjson 1.2.80（无 gadget 依赖）",
        category="version",
        compose_rel="lab",
        services=("fj-1-2-80",),
        port_specs=(
            LabPortSpec(
                key="http",
                label="HTTP",
                env="LAB_PORT_FJ_1_2_80",
                default=18082,
                container_port=18080,
            ),
        ),
        container_names=("fj-1-2-80",),
        endpoint_templates=("http://127.0.0.1:{http}/api/fastjson",),
    ),
    LabSpec(
        id="fastjson-1247",
        name="≤1.2.47 gadget",
        description="Class 缓存绕过 + 依赖链落盘证明",
        category="gadget",
        compose_rel="lab/fastjson-1247-lab",
        services=("fastjson-1247-lab",),
        port_specs=(
            LabPortSpec(
                key="http",
                label="HTTP",
                env="LAB_PORT_FJ_1247",
                default=18247,
                container_port=18080,
            ),
        ),
        container_names=("fastjson-1247-lab",),
        endpoint_templates=("http://127.0.0.1:{http}/api/fastjson",),
        notes="对应 /poc → ≤1.2.47；与版本矩阵 :18047 区分",
    ),
    LabSpec(
        id="fastjson-1268",
        name="≤1.2.68 gadget",
        description="AutoCloseable expectClass 落盘证明",
        category="gadget",
        compose_rel="lab/fastjson-1268-lab",
        services=("fastjson-1268-lab",),
        port_specs=(
            LabPortSpec(
                key="http",
                label="HTTP",
                env="LAB_PORT_FJ_1268",
                default=18268,
                container_port=18080,
            ),
        ),
        container_names=("fastjson-1268-lab",),
        endpoint_templates=("http://127.0.0.1:{http}/api/fastjson",),
        notes="对应 /poc → ≤1.2.68；与版本矩阵 :18068 区分",
    ),
    LabSpec(
        id="fastjson-1280",
        name="≤1.2.80 gadget",
        description="Exception 缓存绕过落盘证明",
        category="gadget",
        compose_rel="lab/fastjson-1280-lab",
        services=("fastjson-1280-lab",),
        port_specs=(
            LabPortSpec(
                key="http",
                label="HTTP",
                env="LAB_PORT_FJ_1280",
                default=18280,
                container_port=18080,
            ),
        ),
        container_names=("fastjson-1280-lab",),
        endpoint_templates=("http://127.0.0.1:{http}/api/fastjson",),
        notes="对应 /poc → ≤1.2.80；与版本矩阵 :18082 区分",
    ),
    LabSpec(
        id="cve-2026-16723",
        name="CVE-2026-16723",
        description="1.2.83 jar:http / fd-cache 证明（Undertow）",
        category="cve",
        compose_rel="lab/cve-2026-16723",
        services=("fastjson-undertow",),
        port_specs=(
            LabPortSpec(
                key="http",
                label="HTTP",
                env="LAB_PORT_CVE_16723_HTTP",
                default=18083,
                container_port=8080,
            ),
            LabPortSpec(
                key="jdwp",
                label="JDWP",
                env="LAB_PORT_CVE_16723_JDWP",
                default=18505,
                container_port=5005,
            ),
        ),
        container_names=("cve-2026-16723-undertow",),
        endpoint_templates=("http://127.0.0.1:{http}/json",),
        notes="HTTP / JDWP 可分别改端口；对应 /poc → CVE",
    ),
)

_LAB_BY_ID = {lab.id: lab for lab in LABS}


def get_lab(lab_id: str) -> LabSpec | None:
    return _LAB_BY_ID.get(lab_id)


def all_labs() -> list[LabSpec]:
    return list(LABS)


def all_default_ports() -> list[int]:
    ports: list[int] = []
    for lab in LABS:
        ports.extend(lab.default_ports)
    return ports
