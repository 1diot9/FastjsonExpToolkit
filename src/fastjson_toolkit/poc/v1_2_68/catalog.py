"""Fastjson ≤1.2.68（AutoCloseable expectClass）gadget 目录。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


GadgetKind = Literal[
    "file_truncate",
    "file_writer_truncate",
    "jdk11_write",
    "file_copy",
    "io1_write",
    "io2_write",
    "io3_write",
    "io4_write",
    "io5_write",
    "io_final",
    "io_read_error",
    "io_read_echo",
    "mysql_jdbc_51",
    "mysql_jdbc_60",
    "mysql_jdbc_80",
    "postgresql_ssrf",
]


@dataclass(frozen=True)
class GadgetEntry:
    id: GadgetKind
    title: str
    description: str
    requires: tuple[str, ...]
    jdk: str
    input_fields: tuple[str, ...]
    references: tuple[str, ...] = ()
    hidden: bool = False


GADGETS: tuple[GadgetEntry, ...] = (
    GadgetEntry(
        id="file_truncate",
        title="FileOutputStream 清空/截断",
        description="双 @type AutoCloseable → FileOutputStream(file, append=false) 截断文件。",
        requires=("JDK",),
        jdk="8+",
        input_fields=("file",),
        references=("https://github.com/threedr3am/learnjavabug",),
    ),
    GadgetEntry(
        id="file_writer_truncate",
        title="Writer 清空/截断",
        description=(
            "AutoCloseable → OutputStreamWriter(FileOutputStream)；"
            "JDK11 下直接 FileWriter(String,Charset,boolean) 易匹配失败。"
        ),
        requires=("JDK",),
        jdk="8+",
        input_fields=("file",),
    ),
    GadgetEntry(
        id="jdk11_write",
        title="JDK11 MarshalOutputStream 任意写",
        description=(
            "MarshalOutputStream → InflaterOutputStream → FileOutputStream；"
            "Inflater.input 使用 array/limit（JDK11 形态）。内容为 zlib 压缩后 Base64。"
        ),
        requires=("JDK sun.rmi.server.MarshalOutputStream",),
        jdk="11（array/limit）；8 可用字符串 input 变体",
        input_fields=("file", "content"),
        references=(
            "https://github.com/threedr3am/learnjavabug/blob/master/fastjson/src/main/java/com/threedr3am/bug/fastjson/file/FileWriteBypassAutoType1_2_68.java",
        ),
    ),
    GadgetEntry(
        id="file_copy",
        title="SafeFileOutputStream 文件复制",
        description="aspectjtools SafeFileOutputStream(tempPath→targetPath)。",
        requires=("org.aspectj:aspectjtools",),
        jdk="8+",
        input_fields=("file", "source"),
        references=("https://su18.org/post/fastjson-1.2.68/",),
    ),
    GadgetEntry(
        id="io_final",
        title="commons-io 写文件（推荐）",
        description=(
            "最通用 io 写链：BOMInputStream + TeeInputStream + CharSequenceInputStream，"
            "$ref $.bOM 触发 getBOM 落盘。默认仅依赖 commons-io；"
            "靶场稳定形态用 LazyFileOutputStream（ant）。覆盖原 io1–io5 / ioFinal 场景。"
        ),
        requires=("commons-io",),
        jdk="8+",
        input_fields=("file", "content"),
        references=(
            "https://su18.org/post/fastjson-1.2.68/",
            "https://b1ue.cn/archives/506.html",
        ),
    ),
    # --- 以下 io 写变体默认隐藏，CLI/API 仍可按 id 生成 ---
    GadgetEntry(
        id="io1_write",
        title="commons-io io1 写文件",
        description=(
            "笔记 io1 数据流；证明态与 io_final 同构（LazyFile）。"
            "经典 XmlStreamReader/FileWriterWithEncoding+WriterOutputStream 受构造随机影响。"
        ),
        requires=("commons-io", "ant LazyFileOutputStream"),
        jdk="8+",
        input_fields=("file", "content"),
        references=(
            "https://mp.weixin.qq.com/s/6fHJ7s6Xo4GEdEGpKFLOyg",
            "https://su18.org/post/fastjson-1.2.68/",
        ),
        hidden=True,
    ),
    GadgetEntry(
        id="io2_write",
        title="commons-io io2 写文件 (2.7–2.8)",
        description="同 io1，参数改为 inputStream / charsetName；内容建议 ≥8192。",
        requires=("commons-io 2.7–2.8.0",),
        jdk="8+",
        input_fields=("file", "content"),
        hidden=True,
    ),
    GadgetEntry(
        id="io3_write",
        title="commons-io io3 写文件 (su18)",
        description="BOMInputStream.getBOM + TeeInputStream + Currency/$ref 触发（su18）。",
        requires=("commons-io",),
        jdk="8+",
        input_fields=("file", "content"),
        references=("https://su18.org/post/fastjson-1.2.68/", "https://github.com/su18/fastjson-commons-io"),
        hidden=True,
    ),
    GadgetEntry(
        id="io4_write",
        title="io4 Base64 二进制写 (aspectj)",
        description="Base64InputStream + CharSequenceInputStream + SafeFileOutputStream；$ref bOM。",
        requires=("commons-io≥2.2", "commons-codec", "aspectjtools"),
        jdk="8+",
        input_fields=("file", "content"),
        references=("https://i.blackhat.com/USA21/Wednesday-Handouts/US-21-Xing-How-I-Used-a-JSON.pdf",),
        hidden=True,
    ),
    GadgetEntry(
        id="io5_write",
        title="io5 LazyFileOutputStream (ant)",
        description="io4 换 ant LazyFileOutputStream；可写任意大小；LockableFileWriter 可建目录。",
        requires=("commons-io", "commons-codec", "ant"),
        jdk="8+",
        input_fields=("file", "content"),
        references=("https://mp.weixin.qq.com/s/WbYi7lPEvFg-vAUB4Nlvew",),
        hidden=True,
    ),
    GadgetEntry(
        id="io_read_error",
        title="commons-io 报错读文件/目录",
        description=(
            "BOMInputStream + URLReader(file://) + CharSequenceReader($ref BOM)；"
            "首字节猜对时报错。需 Nashorn URLReader（JDK≤14）。"
        ),
        requires=("commons-io", "jdk.nashorn.api.scripting.URLReader"),
        jdk="8–14（含 Nashorn）",
        input_fields=("url", "guess_byte"),
        references=("https://b1ue.cn/archives/506.html",),
    ),
    GadgetEntry(
        id="io_read_echo",
        title="commons-io 回显读 (BOM $ref)",
        description="正确时 $ref $.abc.BOM 带回显；需原本就有序列化回显点。",
        requires=("commons-io", "URLReader"),
        jdk="8–14",
        input_fields=("url", "bom_bytes"),
        references=("https://b1ue.cn/archives/506.html",),
    ),
    GadgetEntry(
        id="mysql_jdbc_51",
        title="MySQL JDBC 5.1.x 出网",
        description="JDBC4Connection + ServerStatusDiffInterceptor + autoDeserialize。",
        requires=("mysql-connector-java 5.1.1–5.1.48",),
        jdk="8+",
        input_fields=("host", "port", "user"),
    ),
    GadgetEntry(
        id="mysql_jdbc_60",
        title="MySQL JDBC 6.0.2/6.0.3 出网",
        description="LoadBalancedMySQLConnection + connectionString url。",
        requires=("mysql-connector-java 6.0.2/6.0.3",),
        jdk="8+",
        input_fields=("jdbc_url",),
    ),
    GadgetEntry(
        id="mysql_jdbc_80",
        title="MySQL JDBC ≤8.0.19 出网",
        description="ReplicationMySQLConnection + LoadBalancedConnectionProxy。",
        requires=("mysql-connector-java ≤8.0.19",),
        jdk="8+",
        input_fields=("host", "port", "user"),
    ),
    GadgetEntry(
        id="postgresql_ssrf",
        title="PostgreSQL socketFactory SSRF",
        description=(
            "PgConnection.info.socketFactory=ClassPathXmlApplicationContext；"
            "可 file/http 加载 XML（需 Spring）。"
        ),
        requires=(
            "org.postgresql:postgresql 9.4.1208–42.2.24 或 42.3.0–42.3.1",
            "spring-context（ClassPathXmlApplicationContext）",
        ),
        jdk="8+",
        input_fields=("socket_factory_arg", "host", "port"),
    ),
)


def get_gadget(gadget_id: str) -> GadgetEntry:
    for g in GADGETS:
        if g.id == gadget_id:
            return g
    raise KeyError(f"未知 gadget: {gadget_id}")


def list_gadgets(*, include_hidden: bool = False) -> list[dict]:
    return [
        {
            "id": g.id,
            "title": g.title,
            "description": g.description,
            "requires": list(g.requires),
            "jdk": g.jdk,
            "input_fields": list(g.input_fields),
            "references": list(g.references),
            "hidden": g.hidden,
        }
        for g in GADGETS
        if include_hidden or not g.hidden
    ]
