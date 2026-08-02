/** 仅导出字节码供 H2 defineClass 证明，不打进运行时 jar。 */
public class EvilH2 {
    static {
        try {
            java.io.FileOutputStream out = new java.io.FileOutputStream("/tmp/fj1247_h2");
            try {
                out.write("h2-define".getBytes("UTF-8"));
            } finally {
                out.close();
            }
        } catch (Throwable ignored) {
        }
    }
}
