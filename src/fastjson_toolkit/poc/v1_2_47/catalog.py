"""Fastjson ≤1.2.47（java.lang.Class 缓存绕过）gadget 目录。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


GadgetKind = Literal[
    "jdbc_rowset",
    "bcel_tomcat_dbcp",
    "bcel_tomcat_dbcp2",
    "bcel_commons_dbcp",
    "bcel_commons_dbcp2",
    "c3p0_wrapper",
    "mybatis_bcel",
    "h2_jdbc",
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


GADGETS: tuple[GadgetEntry, ...] = (
    GadgetEntry(
        id="jdbc_rowset",
        title="JdbcRowSetImpl (JNDI) RCE",
        description=(
            "Class 缓存预热 com.sun.rowset.JdbcRowSetImpl 后触发 dataSourceName JNDI。"
            "经典出网链；JDK8u191+ 需高版本 LDAP/本地工厂等额外条件。"
        ),
        requires=("JDK (JdbcRowSetImpl)",),
        jdk="任意（JNDI 策略受 JDK 版本影响）",
        input_fields=("jndi_url",),
        references=(
            "https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.47-rce",
            "https://github.com/safe6Sec/Fastjson",
        ),
    ),
    GadgetEntry(
        id="bcel_tomcat_dbcp",
        title="BCEL + tomcat-dbcp RCE",
        description="org.apache.tomcat.dbcp.dbcp.BasicDataSource + BCEL ClassLoader；$ref 触发 connection。",
        requires=(
            "tomcat-dbcp <= 7.0.109",
            "com.sun.org.apache.bcel.internal.util.ClassLoader",
        ),
        jdk="<= 8u251（内置 BCEL ClassLoader）",
        input_fields=("bcel_code", "class_b64"),
    ),
    GadgetEntry(
        id="bcel_tomcat_dbcp2",
        title="BCEL + tomcat-dbcp2 RCE",
        description="org.apache.tomcat.dbcp.dbcp2.BasicDataSource + BCEL ClassLoader。",
        requires=(
            "tomcat-dbcp 8.0.0-RC1 .. 10.1.0-M2",
            "com.sun.org.apache.bcel.internal.util.ClassLoader",
        ),
        jdk="<= 8u251",
        input_fields=("bcel_code", "class_b64"),
    ),
    GadgetEntry(
        id="bcel_commons_dbcp",
        title="BCEL + commons-dbcp RCE",
        description="org.apache.commons.dbcp.BasicDataSource + BCEL ClassLoader。",
        requires=("commons-dbcp <= 1.4", "BCEL ClassLoader"),
        jdk="<= 8u251",
        input_fields=("bcel_code", "class_b64"),
    ),
    GadgetEntry(
        id="bcel_commons_dbcp2",
        title="BCEL + commons-dbcp2 RCE",
        description="org.apache.commons.dbcp2.BasicDataSource + BCEL ClassLoader。",
        requires=("commons-dbcp2 <= 2.13.0", "BCEL ClassLoader"),
        jdk="<= 8u251",
        input_fields=("bcel_code", "class_b64"),
    ),
    GadgetEntry(
        id="c3p0_wrapper",
        title="C3P0 WrapperConnectionPoolDataSource RCE",
        description=(
            "userOverridesAsString=HexAsciiSerializedMap:...; 二次反序列化。"
            "可配合 CommonsCollections 等本地 gadget 做出网/回显。"
        ),
        requires=("c3p0", "二次反序列化 gadget 字节码"),
        jdk="视二次 gadget 而定",
        input_fields=("user_overrides", "serialized_b64"),
        references=("https://github.com/safe6Sec/Fastjson",),
    ),
    GadgetEntry(
        id="mybatis_bcel",
        title="MyBatis UnpooledDataSource (BCEL) RCE",
        description=(
            "org.apache.ibatis.datasource.unpooled.UnpooledDataSource；"
            "默认 $ref 触发 getConnection；getter_trigger=json_key 为 JSONObject 作 Map key 形态。"
        ),
        requires=("mybatis", "BCEL ClassLoader"),
        jdk="<= 8u251",
        input_fields=("bcel_code", "class_b64"),
        references=(
            "https://www.anquanke.com/post/id/283079",
            "https://xz.aliyun.com/news/16117",
        ),
    ),
    GadgetEntry(
        id="h2_jdbc",
        title="H2 JdbcDataSource (INIT/ALIAS) RCE",
        description=(
            "org.h2.jdbcx.JdbcDataSource；INIT 中 CREATE ALIAS + Base64 defineClass。"
            "默认 $ref 触发 connection；getter_trigger=json_key/currency* 可换 Map key / Currency 套层。"
            "依赖 H2 且允许 INIT；com.h2database:h2 <= 2.2.224。"
        ),
        requires=("com.h2database:h2 <= 2.2.224",),
        jdk="含 java.util.Base64（8+）",
        input_fields=("class_b64", "h2_url"),
        references=(
            "https://xz.aliyun.com/news/16117",
            "https://mp.weixin.qq.com/s/7c_zi5Pv4a69IV0zzJo5Ww",
        ),
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
            "references": list(g.references),
        }
        for g in GADGETS
    ]
