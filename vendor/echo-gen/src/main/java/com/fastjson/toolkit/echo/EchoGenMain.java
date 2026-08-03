package com.fastjson.toolkit.echo;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import jeg.common.config.Constants;
import jeg.core.config.jEGConfig;
import jeg.core.config.jEGConstants;
import jeg.core.jEGenerator;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One-shot java-echo-generator wrapper: stdin/stdout JSON.
 *
 * <pre>
 *   java -jar echo-gen.jar config
 *   java -jar echo-gen.jar generate &lt; request.json
 * </pre>
 */
public final class EchoGenMain {
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    private static final Map<String, String> ENGINE_MAP = new LinkedHashMap<String, String>();

    static {
        ENGINE_MAP.put("auto", Constants.SERVER_TOMCAT);
        ENGINE_MAP.put("spring", Constants.SERVER_SPRING_MVC);
        ENGINE_MAP.put("springmvc", Constants.SERVER_SPRING_MVC);
        ENGINE_MAP.put("undertow", Constants.SERVER_UNDERTOW);
        ENGINE_MAP.put("tomcat", Constants.SERVER_TOMCAT);
        ENGINE_MAP.put("jetty", Constants.SERVER_JETTY);
        ENGINE_MAP.put("weblogic", Constants.SERVER_WEBLOGIC);
        ENGINE_MAP.put("websphere", Constants.SERVER_WEBSPHERE);
        ENGINE_MAP.put("resin", Constants.SERVER_RESIN);
        ENGINE_MAP.put("struts2", Constants.SERVER_STRUTS2);
        ENGINE_MAP.put("httpserver", Constants.SERVER_UNKNOWN);
        ENGINE_MAP.put("dfs", Constants.SERVER_UNKNOWN);
        ENGINE_MAP.put("unknown", Constants.SERVER_UNKNOWN);
        ENGINE_MAP.put("bes", Constants.SERVER_BES);
        ENGINE_MAP.put("inforsuite", Constants.SERVER_INFORSUITE);
        ENGINE_MAP.put("tongweb", Constants.SERVER_TONGWEB);
    }

    private EchoGenMain() {
    }

    public static void main(String[] args) {
        String action = args.length > 0 ? args[0].trim().toLowerCase() : "generate";
        try {
            if ("config".equals(action) || "--config".equals(action)) {
                System.out.println(GSON.toJson(buildConfig()));
                return;
            }
            if ("generate".equals(action) || "--generate".equals(action) || action.isEmpty()) {
                String raw = readStdin();
                if (raw == null || raw.trim().isEmpty()) {
                    fail("stdin JSON is empty; usage: java -jar echo-gen.jar generate < req.json");
                    return;
                }
                System.out.println(GSON.toJson(generate(raw)));
                return;
            }
            fail("unknown action: " + action + " (use config|generate)");
        } catch (Throwable t) {
            JsonObject err = new JsonObject();
            err.addProperty("error", String.valueOf(t.getMessage() == null ? t : t.getMessage()));
            System.out.println(GSON.toJson(err));
            System.exit(1);
        }
    }

    private static void fail(String msg) {
        JsonObject err = new JsonObject();
        err.addProperty("error", msg);
        System.out.println(GSON.toJson(err));
        System.exit(1);
    }

    private static String readStdin() throws Exception {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }

    private static Map<String, Object> buildConfig() {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("engines", ENGINE_MAP.keySet().toArray(new String[0]));
        out.put("servers", new String[]{
                Constants.SERVER_TOMCAT,
                Constants.SERVER_SPRING_MVC,
                Constants.SERVER_UNDERTOW,
                Constants.SERVER_JETTY,
                Constants.SERVER_WEBLOGIC,
                Constants.SERVER_WEBSPHERE,
                Constants.SERVER_RESIN,
                Constants.SERVER_STRUTS2,
                Constants.SERVER_UNKNOWN,
                Constants.SERVER_BES,
                Constants.SERVER_INFORSUITE,
                Constants.SERVER_TONGWEB,
        });
        out.put("models", new String[]{jEGConstants.MODEL_CMD, jEGConstants.MODEL_CODE});
        return out;
    }

    private static Map<String, Object> generate(String raw) throws Throwable {
        JsonObject root = JsonParser.parseString(raw).getAsJsonObject();
        String engine = text(root, "engine", "tomcat");
        String className = text(root, "className", "EchoPayload");
        String cmdHeader = text(root, "cmdHeader", "X-Cmd");
        String model = text(root, "model", jEGConstants.MODEL_CMD);
        String server = mapEngine(engine);

        java.nio.file.Path tmp = Files.createTempDirectory("echo-gen-");
        try {
            final String serverF = server;
            final String modelF = model;
            final String classNameF = className;
            final String cmdHeaderF = cmdHeader;
            final String outDir = tmp.toAbsolutePath().toString();
            jEGConfig config = new jEGConfig() {{
                setServerType(serverF);
                setModelType(modelF);
                setFormatType(jEGConstants.FORMAT_CLASS);
                setClassName(classNameF);
                setReqHeaderName(cmdHeaderF);
                setOutputDir(outDir);
                build();
            }};
            // 固定用户指定的 header / className（build 可能已随机填充）
            config.setReqHeaderName(cmdHeader);
            config.setClassName(className);

            jEGenerator generator = new jEGenerator(config);
            String path = generator.getPayload();
            byte[] classBytes = Files.readAllBytes(java.nio.file.Paths.get(path));
            if (classBytes.length < 4
                    || (classBytes[0] & 0xff) != 0xca
                    || (classBytes[1] & 0xff) != 0xfe
                    || (classBytes[2] & 0xff) != 0xba
                    || (classBytes[3] & 0xff) != 0xbe) {
                throw new IllegalStateException("echo-gen output is not a valid .class");
            }

            Map<String, Object> art = new LinkedHashMap<String, Object>();
            art.put("className", config.getClassName());
            art.put("classSize", classBytes.length);
            art.put("classBytesBase64", Base64.getEncoder().encodeToString(classBytes));
            art.put("cmdHeader", config.getReqHeaderName());
            art.put("engine", engine);
            art.put("serverType", config.getServerType());
            art.put("modelType", config.getModelType());

            Map<String, Object> out = new LinkedHashMap<String, Object>();
            out.put("echoResult", art);
            return out;
        } finally {
            try {
                Files.walk(tmp)
                        .sorted(java.util.Comparator.reverseOrder())
                        .forEach(p -> {
                            try {
                                Files.deleteIfExists(p);
                            } catch (Exception ignore) {
                            }
                        });
            } catch (Exception ignore) {
            }
        }
    }

    private static String mapEngine(String engine) {
        if (engine == null || engine.trim().isEmpty()) {
            return Constants.SERVER_TOMCAT;
        }
        String key = engine.trim().toLowerCase();
        // 直接传 jEG 正式名
        for (String v : ENGINE_MAP.values()) {
            if (v.equalsIgnoreCase(engine.trim())) {
                return v;
            }
        }
        String mapped = ENGINE_MAP.get(key);
        if (mapped == null) {
            throw new IllegalArgumentException("unknown engine: " + engine);
        }
        return mapped;
    }

    private static String text(JsonObject root, String key, String def) {
        if (!root.has(key) || root.get(key).isJsonNull()) {
            return def;
        }
        String v = root.get(key).getAsString();
        return v == null || v.trim().isEmpty() ? def : v.trim();
    }
}
