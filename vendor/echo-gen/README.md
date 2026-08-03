# echo-gen

基于 [pen4uin/java-echo-generator](https://github.com/pen4uin/java-echo-generator) 的一次性 CLI（无 GUI），产出回显类 Base64。

## 构建

```powershell
cd vendor/echo-gen
.\build.ps1
```

产物安装到 `src/fastjson_toolkit/poc/echo/jars/echo-gen.jar`。可用环境变量 `FJ_ECHO_JAR` 覆盖。

## 用法

```bash
java -jar echo-gen.jar config
java -jar echo-gen.jar generate < req.json
```

请求示例：

```json
{
  "engine": "tomcat",
  "className": "EchoPayload",
  "cmdHeader": "X-Cmd",
  "model": "Command"
}
```
