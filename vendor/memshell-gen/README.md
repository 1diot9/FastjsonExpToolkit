# memshell-gen

FastjsonExpToolkit 内置的 **一次性** MemShellParty 生成器（方案 C）。

- 依赖 Maven Central：`io.github.reajason:generator/packer:2.8.0`
- **不**启动 Spring Boot；stdin/stdout JSON
- 用法：

```bash
# 构建并安装到 Python 包内 jars/
./build.ps1   # Windows
./build.sh    # Unix

java -jar target/memshell-gen.jar config
echo '{...}' | java -jar target/memshell-gen.jar generate
```

Python 侧默认 `ms_api=jar`，通过 `FJ_MEMSHELL_JAR` 可覆盖 jar 路径；也可填 `http(s)://...` 回退到外部 MemShellParty boot。

fat jar 约 40MB+，默认不入库（见仓库根 `.gitignore`）。
