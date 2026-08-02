package com.fastjsonlab;

import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/** C3P0 二次反序列化证明：readObject 时写标记文件。 */
public class ProofTouch implements Serializable {
    private static final long serialVersionUID = 1L;

    private String markerPath = "/tmp/fj1247_c3p0";

    public ProofTouch() {
    }

    public ProofTouch(String markerPath) {
        this.markerPath = markerPath;
    }

    public static void touch(String path, String tag) {
        try {
            Path p = Paths.get(path);
            Path parent = p.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            String body = tag + "-" + System.currentTimeMillis() + "\n";
            try (FileOutputStream fos = new FileOutputStream(p.toFile(), false)) {
                fos.write(body.getBytes(StandardCharsets.UTF_8));
            }
        } catch (Throwable ignored) {
            // lab proof only
        }
    }

    private void writeObject(ObjectOutputStream out) throws Exception {
        out.defaultWriteObject();
    }

    private void readObject(ObjectInputStream in) throws Exception {
        in.defaultReadObject();
        String path = markerPath == null || markerPath.isEmpty() ? "/tmp/fj1247_c3p0" : markerPath;
        touch(path, "readObject");
    }
}
