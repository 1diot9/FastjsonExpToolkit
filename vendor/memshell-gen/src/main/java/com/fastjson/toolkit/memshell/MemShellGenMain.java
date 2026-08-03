package com.fastjson.toolkit.memshell;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ServerFactory;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.AntSwordConfig;
import com.reajason.javaweb.memshell.config.BehinderConfig;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.CustomConfig;
import com.reajason.javaweb.memshell.config.GodzillaConfig;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.NeoreGeorgConfig;
import com.reajason.javaweb.memshell.config.ProxyConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.config.Suo5Config;
import com.reajason.javaweb.memshell.server.AbstractServer;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * One-shot MemShellParty wrapper: no Spring Boot, stdin/stdout JSON.
 *
 * <pre>
 *   java -jar memshell-gen.jar config
 *   java -jar memshell-gen.jar generate &lt; request.json
 * </pre>
 */
public final class MemShellGenMain {
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    private MemShellGenMain() {
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
                    fail("stdin JSON is empty; usage: java -jar memshell-gen.jar generate < req.json");
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
        Map<String, Object> core = new LinkedHashMap<String, Object>();
        List<String> servers = ServerFactory.getSupportedServers();
        for (String name : servers) {
            AbstractServer server = ServerFactory.getServer(name);
            if (server == null) {
                continue;
            }
            Map<String, Set<String>> tools = new LinkedHashMap<String, Set<String>>();
            for (String tool : server.getSupportedShellTools()) {
                Set<String> types = server.getSupportedShellTypes(tool);
                if (types == null || types.isEmpty()) {
                    continue;
                }
                tools.put(tool, new LinkedHashSet<String>(types));
            }
            if (!tools.isEmpty()) {
                core.put(name, tools);
            }
        }
        return core;
    }

    private static Map<String, Object> generate(String raw) {
        JsonObject root = JsonParser.parseString(raw).getAsJsonObject();
        JsonObject shellJson = requiredObject(root, "shellConfig");
        JsonObject toolJson = root.has("shellToolConfig") && root.get("shellToolConfig").isJsonObject()
                ? root.getAsJsonObject("shellToolConfig")
                : new JsonObject();
        JsonObject injJson = root.has("injectorConfig") && root.get("injectorConfig").isJsonObject()
                ? root.getAsJsonObject("injectorConfig")
                : new JsonObject();

        ShellConfig shellConfig = buildShellConfig(shellJson);
        InjectorConfig injectorConfig = buildInjectorConfig(injJson);
        ShellToolConfig toolConfig = buildToolConfig(shellConfig.getShellTool(), toolJson);

        MemShellResult result = MemShellGenerator.generate(shellConfig, injectorConfig, toolConfig);

        Map<String, Object> mem = new LinkedHashMap<String, Object>();
        mem.put("shellClassName", result.getShellClassName());
        mem.put("shellSize", result.getShellSize());
        mem.put("shellBytesBase64Str", result.getShellBytesBase64Str());
        mem.put("injectorClassName", result.getInjectorClassName());
        mem.put("injectorSize", result.getInjectorSize());
        mem.put("injectorBytesBase64Str", result.getInjectorBytesBase64Str());
        mem.put("shellToolConfig", extractToolConfig(result.getShellToolConfig()));

        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("memShellResult", mem);
        return out;
    }

    private static JsonObject requiredObject(JsonObject root, String key) {
        if (!root.has(key) || !root.get(key).isJsonObject()) {
            throw new IllegalArgumentException("missing object field: " + key);
        }
        return root.getAsJsonObject(key);
    }

    private static ShellConfig buildShellConfig(JsonObject o) {
        String server = str(o, "server", null);
        String tool = str(o, "shellTool", null);
        String type = str(o, "shellType", null);
        if (server == null || server.isEmpty()) {
            throw new IllegalArgumentException("shellConfig.server required");
        }
        if (tool == null || tool.isEmpty()) {
            throw new IllegalArgumentException("shellConfig.shellTool required");
        }
        if (type == null || type.isEmpty()) {
            throw new IllegalArgumentException("shellConfig.shellType required");
        }
        int targetJre = intVal(o, "targetJreVersion", 50);
        return ShellConfig.builder()
                .server(server)
                .serverVersion(str(o, "serverVersion", "Unknown"))
                .shellTool(tool)
                .shellType(type)
                .targetJreVersion(targetJre)
                .debug(bool(o, "debug", false))
                .byPassJavaModule(bool(o, "byPassJavaModule", false))
                .shrink(bool(o, "shrink", true))
                .lambdaSuffix(bool(o, "lambdaSuffix", false))
                .probe(bool(o, "probe", false))
                .jakarta(bool(o, "jakarta", false))
                .build();
    }

    private static InjectorConfig buildInjectorConfig(JsonObject o) {
        InjectorConfig cfg = new InjectorConfig();
        String url = str(o, "urlPattern", null);
        cfg.setUrlPattern(url != null && !url.isEmpty() ? url : "/*");
        String injName = str(o, "injectorClassName", null);
        if (injName != null && !injName.isEmpty()) {
            cfg.setInjectorClassName(injName);
        }
        String shellName = str(o, "shellClassName", null);
        if (shellName != null && !shellName.isEmpty()) {
            cfg.setShellClassName(shellName);
        }
        cfg.setStaticInitialize(bool(o, "staticInitialize", false));
        return cfg;
    }

    private static ShellToolConfig buildToolConfig(String tool, JsonObject o) {
        String shellClassName = str(o, "shellClassName", null);
        String headerName = str(o, "headerName", null);
        String headerValue = str(o, "headerValue", null);

        if (ShellTool.Godzilla.equals(tool)) {
            return GodzillaConfig.builder()
                    .shellClassName(shellClassName)
                    .pass(str(o, "godzillaPass", str(o, "pass", null)))
                    .key(str(o, "godzillaKey", str(o, "key", null)))
                    .headerName(headerName)
                    .headerValue(headerValue)
                    .build();
        }
        if (ShellTool.Behinder.equals(tool)) {
            return BehinderConfig.builder()
                    .shellClassName(shellClassName)
                    .pass(str(o, "behinderPass", str(o, "pass", null)))
                    .headerName(headerName)
                    .headerValue(headerValue)
                    .build();
        }
        if (ShellTool.Command.equals(tool)) {
            CommandConfig.CommandConfigBuilder<?, ?> b = CommandConfig.builder()
                    .shellClassName(shellClassName)
                    .paramName(str(o, "commandParamName", str(o, "paramName", null)))
                    .headerName(headerName)
                    .headerValue(headerValue);
            String template = str(o, "commandTemplate", str(o, "template", null));
            if (template != null) {
                b.template(template);
            }
            String encryptor = str(o, "encryptor", null);
            if (encryptor != null) {
                b.encryptor(CommandConfig.Encryptor.fromString(encryptor));
            }
            String impl = str(o, "implementationClass", null);
            if (impl != null) {
                b.implementationClass(CommandConfig.ImplementationClass.fromString(impl));
            }
            return b.build();
        }
        if (ShellTool.AntSword.equals(tool)) {
            return AntSwordConfig.builder()
                    .shellClassName(shellClassName)
                    .pass(str(o, "antSwordPass", str(o, "antswordPass", str(o, "pass", null))))
                    .headerName(headerName)
                    .headerValue(headerValue)
                    .build();
        }
        if (ShellTool.Suo5.equals(tool) || ShellTool.Suo5v2.equals(tool)) {
            return Suo5Config.builder()
                    .shellClassName(shellClassName)
                    .headerName(headerName)
                    .headerValue(headerValue)
                    .build();
        }
        if (ShellTool.NeoreGeorg.equals(tool)) {
            return NeoreGeorgConfig.builder()
                    .shellClassName(shellClassName)
                    .headerName(headerName)
                    .headerValue(headerValue)
                    .build();
        }
        if (ShellTool.Proxy.equals(tool)) {
            return ProxyConfig.builder()
                    .shellClassName(shellClassName)
                    .headerName(headerName)
                    .headerValue(headerValue)
                    .build();
        }
        if (ShellTool.Custom.equals(tool)) {
            CustomConfig.CustomConfigBuilder<?, ?> b = CustomConfig.builder()
                    .shellClassName(shellClassName);
            String b64 = str(o, "shellClassBase64", null);
            if (b64 != null) {
                b.shellClassBase64(b64);
            }
            return b.build();
        }
        throw new IllegalArgumentException("unsupported shellTool: " + tool);
    }

    private static Map<String, Object> extractToolConfig(ShellToolConfig cfg) {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        if (cfg == null) {
            return m;
        }
        if (cfg.getShellClassName() != null) {
            m.put("shellClassName", cfg.getShellClassName());
        }
        if (cfg instanceof GodzillaConfig) {
            GodzillaConfig g = (GodzillaConfig) cfg;
            m.put("pass", g.getPass());
            m.put("godzillaPass", g.getPass());
            m.put("key", g.getKey());
            m.put("godzillaKey", g.getKey());
            m.put("headerName", g.getHeaderName());
            m.put("headerValue", g.getHeaderValue());
        } else if (cfg instanceof BehinderConfig) {
            BehinderConfig b = (BehinderConfig) cfg;
            m.put("pass", b.getPass());
            m.put("behinderPass", b.getPass());
            m.put("headerName", b.getHeaderName());
            m.put("headerValue", b.getHeaderValue());
        } else if (cfg instanceof CommandConfig) {
            CommandConfig c = (CommandConfig) cfg;
            m.put("paramName", c.getParamName());
            m.put("commandParamName", c.getParamName());
            m.put("headerName", c.getHeaderName());
            m.put("headerValue", c.getHeaderValue());
        } else if (cfg instanceof AntSwordConfig) {
            AntSwordConfig a = (AntSwordConfig) cfg;
            m.put("pass", a.getPass());
            m.put("antSwordPass", a.getPass());
            m.put("headerName", a.getHeaderName());
            m.put("headerValue", a.getHeaderValue());
        } else if (cfg instanceof Suo5Config) {
            Suo5Config s = (Suo5Config) cfg;
            m.put("headerName", s.getHeaderName());
            m.put("headerValue", s.getHeaderValue());
        } else if (cfg instanceof NeoreGeorgConfig) {
            NeoreGeorgConfig n = (NeoreGeorgConfig) cfg;
            m.put("headerName", n.getHeaderName());
            m.put("headerValue", n.getHeaderValue());
        } else if (cfg instanceof ProxyConfig) {
            ProxyConfig p = (ProxyConfig) cfg;
            m.put("headerName", p.getHeaderName());
            m.put("headerValue", p.getHeaderValue());
        }
        return m;
    }

    private static String str(JsonObject o, String key, String def) {
        if (o == null || !o.has(key) || o.get(key).isJsonNull()) {
            return def;
        }
        JsonElement e = o.get(key);
        if (e.isJsonPrimitive()) {
            String v = e.getAsString();
            return v == null || v.isEmpty() ? def : v;
        }
        return def;
    }

    private static int intVal(JsonObject o, String key, int def) {
        if (o == null || !o.has(key) || o.get(key).isJsonNull()) {
            return def;
        }
        JsonElement e = o.get(key);
        if (e.isJsonPrimitive()) {
            try {
                if (e.getAsJsonPrimitive().isNumber()) {
                    return e.getAsInt();
                }
                return Integer.parseInt(e.getAsString().trim());
            } catch (Exception ignore) {
                return def;
            }
        }
        return def;
    }

    private static boolean bool(JsonObject o, String key, boolean def) {
        if (o == null || !o.has(key) || o.get(key).isJsonNull()) {
            return def;
        }
        JsonElement e = o.get(key);
        if (e.isJsonPrimitive()) {
            if (e.getAsJsonPrimitive().isBoolean()) {
                return e.getAsBoolean();
            }
            String s = e.getAsString().trim().toLowerCase();
            if ("true".equals(s) || "1".equals(s) || "yes".equals(s)) {
                return true;
            }
            if ("false".equals(s) || "0".equals(s) || "no".equals(s)) {
                return false;
            }
        }
        return def;
    }
}
