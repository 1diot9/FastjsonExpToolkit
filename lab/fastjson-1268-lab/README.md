# Fastjson 1.2.68 AutoCloseable Lab

expectClass（`java.lang.AutoCloseable`）绕过 + commons-io / JDK / JDBC 证明靶场（**AutoType 关闭**）。

## 启动

```bash
docker compose up --build -d
curl http://127.0.0.1:18268/api/health
```

## 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 版本 / 依赖探测 |
| POST | `/api/fastjson` 或 `/json` | `JSON.parse`，AutoType off |
| GET | `/api/markers` | `/tmp/fj1268_*` 证明文件 |
| DELETE | `/api/markers` | 清理证明文件（保留 copy 源） |

## 一键验证

仓库根目录：

```bash
python tests/lab/lab_test_1268_gadgets.py
```

## 约束

- 运行时 **JDK 11**（MarshalOutputStream `array/limit` 写文件 + Nashorn `URLReader`）
- commons-io **2.6**（io1 / ioFinal 参数名）；2.7+ 见 payload 的 `io2_write`
- aspectjtools 1.9.6、ant 1.10.12、mysql-connector 5.1.48、postgresql 42.3.1、spring-context
