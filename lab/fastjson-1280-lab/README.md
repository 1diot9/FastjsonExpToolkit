# Fastjson 1.2.80 Exception Cache Lab

Exception expectClass + `ParserConfig.getDeserializer` 缓存绕过证明靶场（**AutoType 关闭**，共享 CFG）。
**RCE 证明标准：写 `/tmp/fj1280_*` 文件。**

## 启动

```bash
docker compose up --build -d
curl http://127.0.0.1:18280/api/health
```

## 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 版本 / 依赖 / 缓存大小 |
| POST | `/api/reset` | 新建 ParserConfig（清反序列化器缓存） |
| POST | `/api/fastjson` 或 `/json` | `JSON.parse`，AutoType off，共享 CFG |
| GET | `/api/markers` | `/tmp/fj1280_*` 证明文件 |
| DELETE | `/api/markers` | 清理证明文件（保留 read_src） |
| GET | `/attack/evil.jar` | Groovy SPI 写文件 jar |
| GET | `/attack/bean-postgresql.xml` | Spring XML → ProcessBuilder 写文件 |
| GET | `/attack/bean-jython.xml` | 同上（jython marker） |

## 一键验证

仓库根目录：

```bash
python scripts/lab_test_1280_gadgets.py
```

## 约束

- 运行时 **JDK 11**（Nashorn `URLReader`）
- jackson-core **2.13.5**、commons-io **2.6**、ant **1.10.12**（LazyFileOutputStream 写文件）、groovy **2.4.21**
- aspectjtools、mysql-connector 5.1.48、postgresql 42.3.1、spring-context、jython-standalone
- 多步链（jackson→io / groovy）依赖共享 ParserConfig，勿对每请求 `new ParserConfig()`
