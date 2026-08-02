package com.fastjsonlab;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.DefaultJSONParser;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.Executors;

/**
 * Fastjson 1.2.47 gadget 依赖靶场。
 *
 * <pre>
 * GET  /api/health
 * GET  /api/markers          — 列出 /tmp/fj1247_* 证明文件
 * DELETE /api/markers        — 清理证明文件
 * POST /api/fastjson         — AutoType off
 * POST /json                 — 同 /api/fastjson
 * </pre>
 */
public class GadgetLabServer {

    private static final String VERSION = "1.2.47";

    /** 供回显 payload 取当前请求（JDK HttpServer 无 Servlet Request）。 */
    public static final ThreadLocal<HttpExchange> CURRENT_EXCHANGE = new ThreadLocal<>();

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("SERVER_PORT", "18080"));
        trySetAutoType(ParserConfig.getGlobalInstance(), false);

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/api/health", GadgetLabServer::health);
        server.createContext("/api/markers", GadgetLabServer::markers);
        server.createContext("/api/fastjson", GadgetLabServer::fastjson);
        server.createContext("/json", GadgetLabServer::fastjson);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("fastjson-1247-lab " + VERSION + " listening on " + port);
        System.out.println("java.version=" + System.getProperty("java.version"));
    }

    private static void health(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            write(ex, 405, "{\"error\":\"method not allowed\"}");
            return;
        }
        boolean bcelCl;
        try {
            Class.forName("com.sun.org.apache.bcel.internal.util.ClassLoader");
            bcelCl = true;
        } catch (Throwable t) {
            bcelCl = false;
        }
        String body = "{"
                + "\"status\":\"ok\","
                + "\"fastjson_version\":\"" + VERSION + "\","
                + "\"java_version\":\"" + escape(System.getProperty("java.version")) + "\","
                + "\"bcel_classloader\":" + bcelCl + ","
                + "\"endpoints\":[\"/api/fastjson\",\"/json\",\"/api/markers\"]"
                + "}";
        write(ex, 200, body);
    }

    private static void markers(HttpExchange ex) throws IOException {
        String method = ex.getRequestMethod();
        if ("DELETE".equalsIgnoreCase(method)) {
            String[] paths = {
                    "/tmp/fj1247_bcel",
                    "/tmp/fj1247_c3p0",
                    "/tmp/fj1247_h2",
                    "/tmp/fj1247_mybatis"
            };
            int removed = 0;
            for (String p : paths) {
                try {
                    if (Files.deleteIfExists(Paths.get(p))) {
                        removed++;
                    }
                } catch (Throwable ignored) {
                }
            }
            write(ex, 200, "{\"ok\":true,\"removed\":" + removed + "}");
            return;
        }
        if (!"GET".equalsIgnoreCase(method)) {
            write(ex, 405, "{\"error\":\"method not allowed\"}");
            return;
        }
        String[] paths = {
                "/tmp/fj1247_bcel",
                "/tmp/fj1247_c3p0",
                "/tmp/fj1247_h2",
                "/tmp/fj1247_mybatis"
        };
        StringBuilder sb = new StringBuilder("{\"markers\":{");
        boolean first = true;
        for (String p : paths) {
            boolean exists = Files.isRegularFile(Paths.get(p));
            String content = "";
            if (exists) {
                try {
                    content = new String(Files.readAllBytes(Paths.get(p)), StandardCharsets.UTF_8).trim();
                } catch (Throwable ignored) {
                }
            }
            if (!first) {
                sb.append(',');
            }
            first = false;
            String key = p.substring(p.lastIndexOf('/') + 1);
            sb.append('"').append(key).append("\":{")
                    .append("\"path\":\"").append(escape(p)).append("\",")
                    .append("\"exists\":").append(exists).append(',')
                    .append("\"content\":\"").append(escape(content)).append("\"}");
        }
        sb.append("}}");
        write(ex, 200, sb.toString());
    }

    private static void fastjson(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            write(ex, 405, "{\"error\":\"method not allowed\"}");
            return;
        }
        String body = readBody(ex);
        CURRENT_EXCHANGE.set(ex);
        try {
            ParserConfig cfg = new ParserConfig();
            trySetAutoType(cfg, false);
            Object obj = parseWith(cfg, body);
            writeParsed(ex, obj);
        } catch (Throwable t) {
            writeError(ex, t);
        } finally {
            CURRENT_EXCHANGE.remove();
        }
    }

    private static Object parseWith(ParserConfig cfg, String body) {
        DefaultJSONParser parser = new DefaultJSONParser(body, cfg);
        try {
            return parser.parse();
        } finally {
            parser.close();
        }
    }

    private static void writeParsed(HttpExchange ex, Object obj) throws IOException {
        try {
            write(ex, 200, JSON.toJSONString(obj));
        } catch (Throwable serializeError) {
            write(
                    ex,
                    200,
                    "{\"ok\":true,\"parse\":\"success\",\"serialize_error\":\""
                            + escape(String.valueOf(serializeError.getMessage()))
                            + "\"}"
            );
        }
    }

    private static void writeError(HttpExchange ex, Throwable t) throws IOException {
        String msg = t.getMessage() == null ? t.toString() : t.getMessage();
        String body = "{"
                + "\"error\":\"" + escape(t.getClass().getName()) + "\","
                + "\"message\":\"" + escape(msg) + "\","
                + "\"detail\":\"" + escape(String.valueOf(t)) + "\""
                + "}";
        write(ex, 400, body);
    }

    private static void write(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        Headers headers = ex.getResponseHeaders();
        headers.set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) >= 0) {
                out.write(buf, 0, n);
            }
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private static void trySetAutoType(ParserConfig cfg, boolean enabled) {
        try {
            Method m = cfg.getClass().getMethod("setAutoTypeSupport", boolean.class);
            m.invoke(cfg, enabled);
        } catch (Throwable ignored) {
        }
    }

    private static String escape(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
}
