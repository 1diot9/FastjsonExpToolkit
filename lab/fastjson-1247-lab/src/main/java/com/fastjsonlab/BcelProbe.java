package com.fastjsonlab;

/**
 * BCEL / MyBatis 证明类：仅依赖 JDK，类初始化时写标记。
 * 经 BCEL ClassLoader 加载时类名是 $$BCEL$$...，与 classpath 上的本类不冲突。
 */
public class BcelProbe {
    static {
        try {
            java.io.File f = new java.io.File("/tmp/fj1247_bcel");
            java.io.FileOutputStream out = new java.io.FileOutputStream(f);
            try {
                out.write(("bcel-" + System.currentTimeMillis()).getBytes("UTF-8"));
            } finally {
                out.close();
            }
        } catch (Throwable ignored) {
            // lab proof only
        }
    }
}
