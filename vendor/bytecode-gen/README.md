# bytecode-gen

通用 touch / exec 预设字节码生成器（+ BCEL encode / serialize 子命令）。

## 构建

```powershell
cd vendor/bytecode-gen
.\build.ps1
```

产物：`src/fastjson_toolkit/poc/bytecode/jars/bytecode-gen.jar`。可用 `FJ_BYTECODE_JAR` 覆盖。

## 用法

```bash
java -jar bytecode-gen.jar generate < '{"mode":"exec","cmd":"id","proofPath":"/tmp/x"}'
java -jar bytecode-gen.jar encode   < '{"classBytesBase64":"..."}'
java -jar bytecode-gen.jar serialize < '{"classBytesBase64":"...","className":"PresetSer"}'
```
