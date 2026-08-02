package com.fastjsonlab;

/** H2 defineClass 证明：初始化写 /tmp/fj1247_h2。不放进运行时主动加载路径依赖。 */
public class H2Probe {
    static {
        try {
            java.io.FileOutputStream out = new java.io.FileOutputStream("/tmp/fj1247_h2");
            try {
                out.write("h2-ok".getBytes("UTF-8"));
            } finally {
                out.close();
            }
        } catch (Throwable ignored) {
        }
    }
}
