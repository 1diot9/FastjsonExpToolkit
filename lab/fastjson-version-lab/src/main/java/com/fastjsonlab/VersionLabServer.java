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
import java.util.concurrent.Executors;

/**
 * Minimal Fastjson version matrix target.
 *
 * Endpoints:
 *   GET  /api/health
 *   POST /api/fastjson                  — AutoType off, error details echoed
 *   POST /api/fastjson/autotype         — AutoType on, error details echoed
 *   POST /api/fastjson/silent           — AutoType off, opaque 500 (no stack/message)
 *   POST /api/fastjson/silent/autotype  — AutoType on, opaque 500
 */
public class VersionLabServer {

    private static final String VERSION = System.getProperty(
            "fastjson.lab.version",
            detectFastjsonVersion()
    );

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("SERVER_PORT", "18080"));

        // Baseline matches typical apps: AutoType off, SafeMode untouched.
        trySetAutoType(ParserConfig.getGlobalInstance(), false);

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        // Register longer prefixes first (HttpServer longest-match).
        server.createContext("/api/health", VersionLabServer::health);
        server.createContext("/api/fastjson/silent/autotype", VersionLabServer::fastjsonSilentAutoType);
        server.createContext("/api/fastjson/silent", VersionLabServer::fastjsonSilent);
        server.createContext("/api/fastjson/autotype", VersionLabServer::fastjsonAutoType);
        server.createContext("/api/fastjson", VersionLabServer::fastjsonSafe);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("fastjson-version-lab " + VERSION + " listening on " + port);
    }

    private static void health(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            write(ex, 405, "{\"error\":\"method not allowed\"}");
            return;
        }
        String body = "{"
                + "\"status\":\"ok\","
                + "\"fastjson_version\":\"" + escape(VERSION) + "\","
                + "\"endpoints\":["
                + "\"/api/fastjson\","
                + "\"/api/fastjson/autotype\","
                + "\"/api/fastjson/silent\","
                + "\"/api/fastjson/silent/autotype\""
                + "]"
                + "}";
        write(ex, 200, body);
    }

    private static void fastjsonSafe(HttpExchange ex) throws IOException {
        handleParse(ex, false, false);
    }

    private static void fastjsonAutoType(HttpExchange ex) throws IOException {
        handleParse(ex, true, false);
    }

    private static void fastjsonSilent(HttpExchange ex) throws IOException {
        handleParse(ex, false, true);
    }

    private static void fastjsonSilentAutoType(HttpExchange ex) throws IOException {
        handleParse(ex, true, true);
    }

    private static void handleParse(HttpExchange ex, boolean autoType, boolean silent) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            write(ex, 405, "{\"error\":\"method not allowed\"}");
            return;
        }
        String body = readBody(ex);
        try {
            ParserConfig cfg = new ParserConfig();
            if (autoType) {
                trySetSafeMode(cfg, false);
                trySetAutoType(cfg, true);
            } else {
                trySetAutoType(cfg, false);
            }
            writeParsed(ex, parseWith(cfg, body), silent);
        } catch (Throwable t) {
            if (silent) {
                writeSilentError(ex);
            } else {
                writeError(ex, t);
            }
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

    /**
     * Version probes judge parse success/failure. Serialize failures (e.g. JdbcRowSetImpl)
     * must not be reported as parse errors.
     */
    private static void writeParsed(HttpExchange ex, Object obj, boolean silent) throws IOException {
        try {
            write(ex, 200, JSON.toJSONString(obj));
        } catch (Throwable serializeError) {
            if (silent) {
                write(ex, 200, "{\"ok\":true}");
            } else {
                write(
                        ex,
                        200,
                        "{\"ok\":true,\"parse\":\"success\",\"serialize_error\":\""
                                + escape(String.valueOf(serializeError.getMessage()))
                                + "\"}"
                );
            }
        }
    }

    private static void writeSilentError(HttpExchange ex) throws IOException {
        // Opaque failure: status distinguishes error, body has no Fastjson fingerprints.
        write(ex, 500, "{\"ok\":false}");
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
            // older jars may not expose the API the same way
        }
    }

    private static void trySetSafeMode(ParserConfig cfg, boolean enabled) {
        try {
            Method m = cfg.getClass().getMethod("setSafeMode", boolean.class);
            m.invoke(cfg, enabled);
        } catch (Throwable ignored) {
            // safeMode exists only on newer Fastjson
        }
    }

    private static String detectFastjsonVersion() {
        try {
            Package p = JSON.class.getPackage();
            if (p != null && p.getImplementationVersion() != null) {
                return p.getImplementationVersion();
            }
        } catch (Throwable ignored) {
        }
        return "unknown";
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
                    sb.append(c);
            }
        }
        return sb.toString();
    }
}
