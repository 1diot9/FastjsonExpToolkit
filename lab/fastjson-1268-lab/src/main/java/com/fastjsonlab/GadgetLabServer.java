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
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;

/**
 * Fastjson 1.2.68 AutoCloseable expectClass 依赖靶场。
 *
 * <pre>
 * GET  /api/health
 * GET  /api/markers          — 列出 /tmp/fj1268_* 证明文件
 * DELETE /api/markers        — 清理证明文件
 * POST /api/fastjson         — AutoType off（expectClass 绕过）
 * POST /json                 — 同 /api/fastjson
 * </pre>
 */
public class GadgetLabServer {

    private static final String VERSION = "1.2.68";
    private static final Path MARKER_DIR = Paths.get("/tmp");
    private static final String MARKER_PREFIX = "fj1268_";

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("SERVER_PORT", "18080"));
        trySetAutoType(ParserConfig.getGlobalInstance(), false);

        // 预置文件复制源
        Path src = Paths.get("/tmp/fj1268_copy_src");
        Files.write(src, "FJ1268_COPY_SRC\n".getBytes(StandardCharsets.UTF_8));

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/api/health", GadgetLabServer::health);
        server.createContext("/api/markers", GadgetLabServer::markers);
        server.createContext("/api/fastjson", GadgetLabServer::fastjson);
        server.createContext("/json", GadgetLabServer::fastjson);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("fastjson-1268-lab " + VERSION + " listening on " + port);
        System.out.println("java.version=" + System.getProperty("java.version"));
    }

    private static void health(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            write(ex, 405, "{\"error\":\"method not allowed\"}");
            return;
        }
        String body = "{"
                + "\"status\":\"ok\","
                + "\"fastjson_version\":\"" + VERSION + "\","
                + "\"java_version\":\"" + escape(System.getProperty("java.version")) + "\","
                + "\"autotype\":false,"
                + "\"deps\":{"
                + "\"commons_io\":" + classPresent("org.apache.commons.io.input.BOMInputStream") + ","
                + "\"commons_codec\":" + classPresent("org.apache.commons.codec.binary.Base64InputStream") + ","
                + "\"aspectjtools\":" + classPresent("org.eclipse.core.internal.localstore.SafeFileOutputStream") + ","
                + "\"ant\":" + classPresent("org.apache.tools.ant.util.LazyFileOutputStream") + ","
                + "\"mysql51\":" + classPresent("com.mysql.jdbc.JDBC4Connection") + ","
                + "\"postgresql\":" + classPresent("org.postgresql.jdbc.PgConnection") + ","
                + "\"spring_context\":" + classPresent("org.springframework.context.support.ClassPathXmlApplicationContext") + ","
                + "\"nashorn_urlreader\":" + classPresent("jdk.nashorn.api.scripting.URLReader")
                + "},"
                + "\"endpoints\":[\"/api/fastjson\",\"/json\",\"/api/markers\"]"
                + "}";
        write(ex, 200, body);
    }

    private static void markers(HttpExchange ex) throws IOException {
        String method = ex.getRequestMethod();
        if ("DELETE".equalsIgnoreCase(method)) {
            int removed = 0;
            for (Path p : listMarkers()) {
                try {
                    if (Files.deleteIfExists(p)) {
                        removed++;
                    }
                } catch (Throwable ignored) {
                }
            }
            // 保留 copy 源
            try {
                Path src = Paths.get("/tmp/fj1268_copy_src");
                if (!Files.isRegularFile(src)) {
                    Files.write(src, "FJ1268_COPY_SRC\n".getBytes(StandardCharsets.UTF_8));
                }
            } catch (Throwable ignored) {
            }
            write(ex, 200, "{\"ok\":true,\"removed\":" + removed + "}");
            return;
        }
        if (!"GET".equalsIgnoreCase(method)) {
            write(ex, 405, "{\"error\":\"method not allowed\"}");
            return;
        }
        StringBuilder sb = new StringBuilder("{\"markers\":{");
        boolean first = true;
        for (Path p : listMarkers()) {
            boolean exists = Files.isRegularFile(p);
            String content = "";
            long size = 0;
            if (exists) {
                try {
                    byte[] raw = Files.readAllBytes(p);
                    size = raw.length;
                    content = new String(raw, StandardCharsets.UTF_8);
                    if (content.length() > 200) {
                        content = content.substring(0, 200);
                    }
                    content = content.trim();
                } catch (Throwable ignored) {
                }
            }
            if (!first) {
                sb.append(',');
            }
            first = false;
            String key = p.getFileName().toString();
            sb.append('"').append(escape(key)).append("\":{")
                    .append("\"path\":\"").append(escape(p.toString())).append("\",")
                    .append("\"exists\":").append(exists).append(',')
                    .append("\"size\":").append(size).append(',')
                    .append("\"content\":\"").append(escape(content)).append("\"}");
        }
        sb.append("}}");
        write(ex, 200, sb.toString());
    }

    private static List<Path> listMarkers() throws IOException {
        List<Path> out = new ArrayList<>();
        if (!Files.isDirectory(MARKER_DIR)) {
            return out;
        }
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(MARKER_DIR, MARKER_PREFIX + "*")) {
            for (Path p : ds) {
                if (Files.isRegularFile(p) || Files.isDirectory(p)) {
                    out.add(p);
                }
            }
        }
        out.sort(Path::compareTo);
        return out;
    }

    private static void fastjson(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            write(ex, 405, "{\"error\":\"method not allowed\"}");
            return;
        }
        String body = readBody(ex);
        try {
            ParserConfig cfg = new ParserConfig();
            trySetAutoType(cfg, false);
            Object obj = parseWith(cfg, body);
            writeParsed(ex, obj);
        } catch (Throwable t) {
            writeError(ex, t);
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

    private static boolean classPresent(String name) {
        try {
            Class.forName(name);
            return true;
        } catch (Throwable t) {
            return false;
        }
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
