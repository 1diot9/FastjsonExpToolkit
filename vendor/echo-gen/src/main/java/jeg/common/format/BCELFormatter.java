package jeg.common.format;

import jeg.common.config.Config;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPOutputStream;

/**
 * Lightweight BCEL encoder (Apache Utility.encode 子集)，去掉 woodpecker-bcel 依赖。
 * echo-gen CLI 默认走 CLASS；BCEL 仅作备用。
 */
public class BCELFormatter implements IFormatter {
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

    public byte[] transform(byte[] bytes, Config config) throws IOException {
        byte[] raw = config != null && config.getClassBytesInFormatter() != null
                ? config.getClassBytesInFormatter()
                : bytes;
        String encoded = "$$BCEL$$" + encode(raw, true);
        return encoded.getBytes("UTF-8");
    }

    static String encode(byte[] data, boolean compress) throws IOException {
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

    private static byte[] gzip(byte[] data) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gos = new GZIPOutputStream(bos)) {
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
}
