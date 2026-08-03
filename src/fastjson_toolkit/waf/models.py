"""WAF 绕过请求 / 响应模型。"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class WafTechniqueInfo(BaseModel):
    id: str
    title: str
    description: str
    notes: list[str] = Field(default_factory=list)


class WafOptions(BaseModel):
    """各变换的可调参数。"""

    encode_keys: bool = Field(True, description="是否编码 JSON key")
    encode_values: bool = Field(True, description="是否编码 JSON 字符串 value")
    encode_targets: list[str] = Field(
        default_factory=list,
        description="仅编码这些 key 的键名/对应字符串值；空=全部",
    )
    key_targets: list[str] = Field(
        default_factory=list,
        description="key 插入 _/- 时仅处理这些原始 key；空=除 @type 外全部",
    )
    include_type_key: bool = Field(
        False,
        description="key 插入 _/- 时是否也处理 @type",
    )
    use_single_quote: bool = Field(
        True,
        description="key 插入 _/- 后是否改用单引号包裹 key",
    )
    comma_count: int = Field(5, ge=1, le=50, description="多逗号变换插入数量")
    pad_size: int = Field(20000, ge=0, le=500_000, description="填充字符数")
    pad_char: str = Field("a", min_length=1, max_length=1, description="填充字符")
    pad_key: str = Field("f", min_length=1, description="填充字段名")
    hex_ghost_filler: str = Field(
        "_",
        min_length=1,
        max_length=1,
        description=r"hex_ghost 零半字节填充符（须非 0-9A-Fa-f 且码点 <103，如 _ / J）",
    )
    unicode_digit_script: str = Field(
        "fullwidth",
        description="unicode_digit 数字字形：fullwidth | thai | gurmukhi",
    )
    ghost_k: int = Field(
        1,
        ge=1,
        le=255,
        description="ghost_bits 高字节 k（chr((k<<8)|b)；避开代理区 0xD8–0xDF）",
    )


class WafVariant(BaseModel):
    technique: str
    title: str
    payload: str
    description: str = ""


class WafResult(BaseModel):
    original: str
    payload: str
    techniques: list[str]
    variants: list[WafVariant] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    summary: str = ""


class WafRequest(BaseModel):
    payload: str = Field(..., description="原始 Fastjson JSON payload")
    techniques: list[str] = Field(
        default_factory=list,
        description="按顺序叠加的变换 id；空则生成全部单项变体",
    )
    mode: str = Field(
        "stack",
        description="stack=按 techniques 顺序叠加；variants=每项单独生成一份",
    )
    options: Optional[WafOptions] = None
