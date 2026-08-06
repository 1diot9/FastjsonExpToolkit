---
title: 写文件落地 RCE
description: Fastjson 高版本写文件链之后的落地手法：计划任务、webshell、覆盖 JRE jar、jre/classes、SPI、tomcat-docbase
order: 7
---

# 写文件落地 RCE

高版本 Fastjson 利用里，**写文件链**出现得很频繁（commons-io、JDK `MarshalOutputStream` 等）。写完文件之后如何落到 RCE，可按部署形态与 JDK 版本选型。供安全研究与本地复现参考。

相关阅读：

- [springboot 环境下的写文件 RCE](https://mp.weixin.qq.com/s/n8RW0NIllcQ0sn3nI9uceA)
- [≤1.2.68 利用技巧](/docs/fastjson-1.2.68)（io 读写链）
- [≤1.2.80 利用技巧](/docs/fastjson-1.2.80)（jackson / ognl + io）
- [1.2.83 利用技巧](/docs/fastjson-1.2.83)（写文件 + `@JSONType`）
- [LandGrey：覆盖 charsets.jar](https://github.com/LandGrey/spring-boot-upload-file-lead-to-rce-tricks)
- [c0ny1/ascii-jar](https://github.com/c0ny1/ascii-jar)
- [threedr3am：jre/classes](https://threedr3am.github.io/2021/04/13/JDK8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E5%86%99%E5%9C%BA%E6%99%AF%E4%B8%8B%E7%9A%84Fastjson%20RCE/)

前置：能任意写（最好还能读 / 列目录以定位 JDK、`tomcat-docbase` 等路径）。写链本身见各版本「io 写文件」章节；本文只谈**落地**。

---

## 0. 手法总览

| # | 手法 | 典型条件 | JDK 备注 |
|---|------|----------|----------|
| 1 | 计划任务 / sshkey | 通常要 **root**；路径与权限明确 | 与 JDK 无关 |
| 2 | 写 jsp 等 webshell | 有可访问的 web 目录；**不适用于纯 jar 部署** | 与 JDK 无关 |
| 3 | 写 jar 覆盖 `jre/lib`（如 `charsets.jar`） | 知 JDK 路径；目标 jar **尚未被 Opened**；能写二进制或改用 ascii jar | **基本仅 JDK8** |
| 4 | 写 `jre/classes` | 知目录、能**创建目录**；有可触发的入口类 | **基本仅 JDK8** |
| 5 | 写 classes + SPI | 同 4；走 `CharsetProvider` 等 SPI | **基本仅 JDK8** |
| 6 | 写 `tomcat-docbase` class | 知 / 爆破目录；依赖 **WebappClassLoader** 类加载路径 | Fastjson 场景下较常见 |

方法 **3～5** 依赖 JDK8 的 Bootstrap / Ext 类路径布局；JDK9+ 模块化后路径与加载行为大变，多数姿势失效或极不稳定。

选型直觉：

- 传统 war / 有 jsp → 优先看 **2**
- 纯 Spring Boot fat jar → 看 **3～6**
- 低权限、无写 JRE 权限 → **6** 更现实；有 root → **1 / 3～5** 都可尝试
- 写链只能写 ASCII / UTF-8 文本 → **3** 用 [ascii-jar](https://github.com/c0ny1/ascii-jar)，或改走 **4 / 5 / 6**（`.class` 仍可能需二进制写链）

---

## 1. 计划任务 / sshkey

思路最直接：写 crontab、systemd unit、`authorized_keys` 等，等系统调度或下次登录落地。

限制：

- 多半要 **root**（或对应用户对本机对应路径可写）
- 无交互 shell 时，密钥登录还依赖 sshd 配置与网络可达
- 容器 / 只读根文件系统常见，成功率偏低

适合作为「有 root + 持久化」备选，而不是高版本 Fastjson 的默认路径。

---

## 2. 写 jsp / webshell

把 jsp / 其它脚本写到 webapp 可解析目录，再 HTTP 访问触发。

限制：

- **纯 jar / 内嵌容器、无 jsp 引擎**时无效（典型 Spring Boot fat jar）
- 需要猜或读出真实 docBase / 静态资源路径
- 部分环境禁止脚本执行或路径沙箱

有独立 Tomcat / 传统 war 时仍可用；fat jar 场景请直接跳到 3～6。

---

## 3. 写 jar 覆盖 `jre/lib`

最经典的是覆盖 **`jre/lib/charsets.jar`**（也可尝试 `jre/lib/ext/` 下尚未加载的 jar，如 `nashorn.jar`、`dnsns.jar` 等）。覆盖后用 Fastjson 触发加载，例如：

```json
{
  "x": {
    "@type": "java.nio.charset.Charset",
    "val": "GBK"
  }
}
```

要点：

- **路径**：需 JDK home；可读 `/proc/self/cmdline`、`file://` 列目录，或按常见路径字典盲打（见 LandGrey 仓库附录）
- **只触发一次**：某个 jar 一旦被 JVM `Opened`，再覆盖同名文件通常不会重新加载；业务里若已用过对应 Charset，该 jar 可能已废
- **体积与版本**：完整恶意 `charsets.jar` 往往很大，且最好贴近目标 JDK 小版本，否则易伤业务
- **二进制写入**：多数文本型 io 链（UTF-8 / `UTF8Decoder`）写不了任意字节。可选：
  - 换支持二进制的写链（如 Inflater / `iso-8859-1` 等，见 1.2.68 / 1.2.80 文档）
  - 或构造 **ASCII 范围内的 jar**： [c0ny1/ascii-jar](https://github.com/c0ny1/ascii-jar)，再覆盖如 `ext/nashorn.jar` / `dnsns.jar`，用对应 `@type` 触发

JDK8 的 `sun.boot.class.path` / `java.ext.dirs` 使「换 jar → Fastjson `@type` 拉起来」这条路很顺；JDK11+ 不再适用同一套布局。

---

## 4. 写 `jre/classes`

JDK8 Bootstrap 路径里通常带 `.../jre/classes`（默认**不存在**）。若能创建该目录并写入恶意 `.class`，可用很小的类文件替代巨型 jar。

典型触发（≤1.2.68 expectClass 场景示例）：恶意类实现 `AutoCloseable`，静态块执行命令：

```json
{
  "@type": "java.lang.AutoCloseable",
  "@type": "Evil"
}
```

要点：

- 必须**知道并创建** `jre/classes`（及包路径子目录）
- 类名需能被当前 Fastjson 规则加载（白名单 / expectClass / `@JSONType` 等，视版本而定）
- 文件远小于 charsets.jar，且不必按目标 JDK 拼一整包 jar
- 仍基本锁在 **JDK8**；JDK11+ Bootstrap 路径与类加载已变

---

## 5. 写 classes + SPI

不依赖「类名刚好能直接 `@type`」时，可走 **SPI**。例如实现 `java.nio.charset.spi.CharsetProvider`：

1. 在可被 Bootstrap 搜到的路径写下实现类（常仍是 `jre/classes/...`）
2. 写入 `META-INF/services/java.nio.charset.spi.CharsetProvider`，内容为实现类全名
3. 触发 `Charset.forName(...)`（Fastjson 反序列化 `java.nio.charset.Charset` 即可走到 lookup / providers）

与方法 4 相同：要目录创建能力 + JDK 路径；SPI 多一步「服务配置文件」，但触发面更贴近 charset 白名单类。同样 **JDK8 友好，高版本 JDK 基本告别**。

---

## 6. 写 `tomcat-docbase` class

Spring Boot 内嵌 Tomcat 常在 `/tmp/tomcat-docbase.<port>.<random>/` 下展开。把恶意 class 写到：

```text
/tmp/tomcat-docbase.*/WEB-INF/classes/<包路径>/<Evil>.class
```

再靠 **WebappClassLoader**（线程上下文 ClassLoader）加载，而不是 AppClassLoader / Bootstrap。

Fastjson 侧注意：

- 默认 `TypeUtils.loadClass` 若走 AppClassLoader，**加载不到** docbase 下的类
- 需要走到会使用 **当前线程 ContextClassLoader** 的路径（例如部分 expectClass / Exception 形态、或带 `@JSONType` 的类再 `@type` 触发；1.2.83 还可配合 `@JSONType` 绕过白名单）
- 目录名含随机串 → 几乎必须先 **读文件 / 列目录爆破** `/tmp`
- 写链最好能 **自动创建多级目录**（如部分 io5 / io6 / io7）

这是 fat jar / 无 jsp 场景下很常见的落地；限制也明确：依赖 Tomcat docbase + 能被 WebappClassLoader 加载的触发方式，**不是**通用「任意写文件即 RCE」。

---

## 7. 实战检查清单

1. **写能力**：文本 only 还是二进制？能否建目录？单次大小上限（不少链卡 8KB）？
2. **读 / 列目录**：JDK home、`/tmp/tomcat-docbase.*`、web 根
3. **权限与部署**：root？war 还是 fat jar？有无 jsp？
4. **JDK 大版本**：8 → 3～5 可优先；11+ → 更多押 2 / 6 或其它非 JRE 覆盖思路
5. **触发一次原则**：覆盖的 jar / 已加载过的类名不要重复浪费；先本地对齐再打目标
6. **与版本链配合**：写链来自 1.2.68 / 1.2.80 / 1.2.83 等文档；落地后再用 `@type` / expectClass / `@JSONType` 完成加载

本仓库 MCP / PoC **不代发** exploit；写出文件后的触发 payload 请按环境自行组装，或对照各版本文档中的触发示例。
