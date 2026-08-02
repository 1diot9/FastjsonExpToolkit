package com.fastjsonlab;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/** 导出 BcelProbe / H2Probe / EvilH2 .class。 */
public class ExportProofClass {
    public static void main(String[] args) throws Exception {
        String bcelOut = args.length > 0 ? args[0] : "BcelProbe.class";
        String h2Out = args.length > 1 ? args[1] : "H2Probe.class";
        String evilOut = args.length > 2 ? args[2] : "EvilH2.class";
        writeClass(BcelProbe.class, bcelOut);
        writeClass(H2Probe.class, h2Out);
        Path evil = Paths.get("target/proof-classes/EvilH2.class");
        if (!Files.isRegularFile(evil)) {
            throw new IllegalStateException("missing " + evil + " (compile-evil-h2 failed?)");
        }
        Files.copy(evil, Paths.get(evilOut), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        System.out.println("wrote " + evilOut);
    }

    private static void writeClass(Class<?> clazz, String out) throws Exception {
        String resource = "/" + clazz.getName().replace('.', '/') + ".class";
        try (InputStream in = ExportProofClass.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("missing " + resource);
            }
            Files.write(Paths.get(out), readAll(in));
        }
        System.out.println("wrote " + out);
    }

    private static byte[] readAll(InputStream in) throws Exception {
        byte[] buf = new byte[8192];
        int n;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        while ((n = in.read(buf)) >= 0) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }
}
