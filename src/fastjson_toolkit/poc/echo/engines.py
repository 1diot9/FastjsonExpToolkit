"""回显引擎目录（参考 pen4uin/java-echo-generator，含 JDK12+ Unsafe 反射兼容）。"""

from __future__ import annotations

from typing import Literal

EchoEngine = Literal[
    "auto",
    "spring",
    "undertow",
    "tomcat",
    "jetty",
    "weblogic",
    "websphere",
    "resin",
    "struts2",
    "httpserver",
    "dfs",
]

ECHO_ENGINES: tuple[EchoEngine, ...] = (
    "auto",
    "spring",
    "undertow",
    "tomcat",
    "jetty",
    "weblogic",
    "websphere",
    "resin",
    "struts2",
    "httpserver",
    "dfs",
)

# 字节码投递链（BCEL / H2 / CVE-16723 / groovy jar）可直接嵌回显类
BYTECODE_ECHO_GADGETS_1247: frozenset[str] = frozenset(
    {
        "bcel_tomcat_dbcp",
        "bcel_tomcat_dbcp2",
        "bcel_commons_dbcp",
        "bcel_commons_dbcp2",
        "mybatis_bcel",
        "h2_jdbc",
    }
)

# Spring XML / 远程 jar 间接 RCE
SPRING_XML_ECHO_GADGETS_1280: frozenset[str] = frozenset({"postgresql", "jython"})
GROOVY_ECHO_GADGETS_1280: frozenset[str] = frozenset({"groovy"})
SPRING_XML_ECHO_GADGETS_1268: frozenset[str] = frozenset({"postgresql_ssrf"})

ENGINE_META: dict[str, dict[str, str]] = {
    "auto": {
        "title": "auto（按序探测）",
        "description": (
            "依次尝试 spring→undertow→tomcat→jetty→weblogic→websphere→resin→struts2"
            "→httpserver→dfs"
        ),
    },
    "spring": {
        "title": "SpringMVC",
        "description": "RequestContextHolder.getRequestAttributes()",
    },
    "undertow": {
        "title": "Undertow",
        "description": "ServletRequestContext.current() / ThreadLocal 表遍历",
    },
    "tomcat": {
        "title": "Tomcat",
        "description": "RequestGroupInfo processors + WRAP_SAME_OBJECT 兜底（JDK12+ Unsafe）",
    },
    "jetty": {
        "title": "Jetty",
        "description": "ThreadLocal → HttpConnection → HttpChannel",
    },
    "weblogic": {
        "title": "WebLogic",
        "description": "Thread.getCurrentWork() / connectionHandler",
    },
    "websphere": {
        "title": "WebSphere",
        "description": "Thread.wsThreadLocals → WebContainerRequestState",
    },
    "resin": {
        "title": "Resin",
        "description": "ServletInvocation.getContextRequest()",
    },
    "struts2": {
        "title": "Struts2",
        "description": "ActionContext ThreadLocal → HttpServletRequest/Response",
    },
    "httpserver": {
        "title": "JDK HttpServer",
        "description": (
            "DFS 挖 com.sun.net.httpserver.HttpExchange，写响应头 X-Echo"
            "（适配本仓库 gadget 靶场）"
        ),
    },
    "dfs": {
        "title": "DFS / Unknown",
        "description": "从当前线程 DFS 挖 javax/jakarta HttpServletRequest（通用兜底）",
    },
}


def normalize_engine(value: str | None) -> EchoEngine:
    eng = (value or "auto").strip().lower()
    if eng not in ECHO_ENGINES:
        raise ValueError(
            f"engine 仅支持 {', '.join(ECHO_ENGINES)}，收到: {value!r}"
        )
    return eng  # type: ignore[return-value]


def list_engines() -> list[dict[str, str]]:
    return [
        {"id": eid, "title": ENGINE_META[eid]["title"], "description": ENGINE_META[eid]["description"]}
        for eid in ECHO_ENGINES
    ]


def supports_bytecode_echo(gadget: str) -> bool:
    return gadget in BYTECODE_ECHO_GADGETS_1247


def supports_1280_echo(gadget: str) -> bool:
    return gadget in SPRING_XML_ECHO_GADGETS_1280 or gadget in GROOVY_ECHO_GADGETS_1280


def supports_1268_echo(gadget: str) -> bool:
    return gadget in SPRING_XML_ECHO_GADGETS_1268
