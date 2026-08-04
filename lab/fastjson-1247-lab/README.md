# Fastjson 1.2.47 Gadget Lab

Class 缓存绕过 + 依赖 gadget 证明靶场（AutoType 关闭）。

## 启动

```bash
docker compose up --build -d
curl http://127.0.0.1:18247/api/health
```

## 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 版本 / `bcel_classloader` |
| POST | `/api/fastjson` 或 `/json` | `JSON.parse`，AutoType off |
| GET | `/api/markers` | `/tmp/fj1247_*` 证明文件 |
| DELETE | `/api/markers` | 清理证明文件 |

## 一键验证

仓库根目录：

```bash
python tests/lab/lab_test_1247_gadgets.py
```

覆盖：JdbcRowSet、BCEL×4（tomcat/commons dbcp/dbcp2）、MyBatis、C3P0、H2（Class.forName + defineClass）。

## 约束

- 运行时 **JDK ≤ 8u251**（镜像 `openjdk:8u242-jdk`）
- `tomcat-dbcp` 7.x 与 9.x 包名不同，同时挂在 `/app/lib`
