"""Fastjson ≤1.2.80 RCE 证明 gadget 目录（一律以写文件为成功标准）。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


GadgetKind = Literal[
    "io_write",
    "io_copy_write",
    "postgresql",
    "mysql_jdbc",
    "groovy",
    "jython",
    "aspectj_write",
]


@dataclass(frozen=True)
class GadgetEntry:
    id: GadgetKind
    title: str
    description: str
    requires: tuple[str, ...]
    jdk: str
    input_fields: tuple[str, ...]
    steps: int
    marker_file: str
    marker_content: str
    references: tuple[str, ...] = ()


GADGETS: tuple[GadgetEntry, ...] = (
    GadgetEntry(
        id="io_write",
        title="jackson+commons-io 写文件 RCE",
        description=(
            "Exception 缓存 InputStream 后，BOMInputStream→Tee→StringReader→"
            "ant LazyFileOutputStream 写入 marker。证明 jackson 缓存链可 RCE。"
        ),
        requires=("jackson-core", "commons-io", "org.apache.ant:ant"),
        jdk="8+",
        input_fields=("file", "content"),
        steps=3,
        marker_file="/tmp/fj1280_io_write",
        marker_content="FJ1280_IO_WRITE",
        references=(
            "https://github.com/luelueking/CVE-2022-25845-In-Spring",
            "https://github.com/kezibei/fastjson_payload",
        ),
    ),
    GadgetEntry(
        id="io_copy_write",
        title="URLReader 拷贝写文件 RCE",
        description=(
            "jackson 缓存后，URLReader(file://)→Tee→LazyFileOutputStream，"
            "把源文件内容写入目标 marker（读链路转化为写文件证明）。"
        ),
        requires=("jackson-core", "commons-io", "ant", "jdk.nashorn.api.scripting.URLReader"),
        jdk="8–14（含 Nashorn）",
        input_fields=("file", "url"),
        steps=3,
        marker_file="/tmp/fj1280_io_copy_write",
        marker_content="FJ1280_READ_SRC",
        references=("https://github.com/luelueking/CVE-2022-25845-In-Spring",),
    ),
    GadgetEntry(
        id="postgresql",
        title="PostgreSQL socketFactory RCE 写文件",
        description=(
            "jackson 缓存后 PGCopyInputStream→PgConnection；"
            "socketFactory=ClassPathXmlApplicationContext 加载远程 XML，"
            "ProcessBuilder 写 marker（Spring）。"
        ),
        requires=(
            "jackson-core",
            "org.postgresql:postgresql 9.4.1208–42.2.24 或 42.3.0–42.3.1",
            "spring-context",
        ),
        jdk="8+",
        input_fields=("socket_factory_arg", "host", "port"),
        steps=3,
        marker_file="/tmp/fj1280_postgresql",
        marker_content="FJ1280_POSTGRESQL",
        references=("https://github.com/su18/hack-fastjson-1.2.80",),
    ),
    GadgetEntry(
        id="mysql_jdbc",
        title="MySQL 链缓存 + 写文件 RCE",
        description=(
            "jackson 缓存后经 CompressedInputStream 走 MySQL 类路径，"
            "再用 commons-io LazyFileOutputStream 写 marker 证明 RCE。"
        ),
        requires=("jackson-core", "mysql-connector-java ≤5.1.48", "commons-io", "ant"),
        jdk="8+",
        input_fields=("file", "content"),
        steps=4,
        marker_file="/tmp/fj1280_mysql_jdbc",
        marker_content="FJ1280_MYSQL_JDBC",
    ),
    GadgetEntry(
        id="groovy",
        title="Groovy SPI 远程 jar RCE 写文件",
        description=(
            "CompilationFailedException 缓存 ProcessingUnit 后，"
            "JavaStubCompilationUnit.classpathList 加载恶意 jar；"
            "ASTTransformation 静态块写 marker。"
        ),
        requires=("org.codehaus.groovy:groovy",),
        jdk="8+",
        input_fields=("classpath",),
        steps=2,
        marker_file="/tmp/fj1280_groovy",
        marker_content="FJ1280_GROOVY",
        references=(
            "https://github.com/su18/hack-fastjson-1.2.80",
            "https://godownio.github.io/2025/05/28/fastjson-1.2.76-1.2.80-groovy-lian/",
        ),
    ),
    GadgetEntry(
        id="jython",
        title="Jython+PgConnection RCE 写文件",
        description=(
            "ParseException 缓存后 PyConnection→PgConnection socketFactory "
            "拉 XML，ProcessBuilder 写 marker。"
        ),
        requires=(
            "org.python:jython-standalone",
            "org.postgresql:postgresql",
            "spring-context",
        ),
        jdk="8+",
        input_fields=("socket_factory_arg", "host", "port"),
        steps=1,
        marker_file="/tmp/fj1280_jython",
        marker_content="FJ1280_JYTHON",
    ),
    GadgetEntry(
        id="aspectj_write",
        title="aspectjtools SafeFileOutputStream 写文件 RCE",
        description=(
            "jackson 缓存 InputStream 后，Tee→SafeFileOutputStream（aspectjtools）写 marker；"
            "内容 pad≥8193 以冲刷 BufferedOutputStream（未 close 也能落盘）。"
        ),
        requires=("jackson-core", "commons-io", "org.aspectj:aspectjtools"),
        jdk="8+",
        input_fields=("file", "content"),
        steps=3,
        marker_file="/tmp/fj1280_aspectj_write",
        marker_content="FJ1280_ASPECTJ_WRITE",
        references=("https://github.com/su18/hack-fastjson-1.2.80",),
    ),
)


def get_gadget(gadget_id: str) -> GadgetEntry:
    for g in GADGETS:
        if g.id == gadget_id:
            return g
    raise KeyError(f"未知 gadget: {gadget_id}")


def list_gadgets() -> list[dict]:
    return [
        {
            "id": g.id,
            "title": g.title,
            "description": g.description,
            "requires": list(g.requires),
            "jdk": g.jdk,
            "input_fields": list(g.input_fields),
            "steps": g.steps,
            "marker_file": g.marker_file,
            "marker_content": g.marker_content,
            "references": list(g.references),
        }
        for g in GADGETS
    ]
