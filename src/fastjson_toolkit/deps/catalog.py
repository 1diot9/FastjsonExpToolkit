"""Builtin Fastjson dependency class catalog for jar existence probes."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DepEntry:
    """One dependency probe target."""

    clazz: str
    description: str
    category: str = "other"


# class // description — mirrors common jarScan lists used in Fastjson recon.
DEFAULT_DEP_ENTRIES: tuple[DepEntry, ...] = (
    DepEntry(
        "org.springframework.web.bind.annotation.RequestMapping",
        "SpringBoot",
        "spring",
    ),
    DepEntry("org.apache.catalina.startup.Tomcat", "Tomcat", "tomcat"),
    DepEntry("groovy.lang.GroovyShell", "Groovy - 1.2.80", "groovy"),
    DepEntry("com.mchange.v2.c3p0.DataSources", "C3P0", "c3p0"),
    DepEntry(
        "org.apache.ibatis.datasource.unpooled.UnpooledDataSource",
        "mybatis",
        "mybatis",
    ),
    DepEntry("org.h2.jdbcx.JdbcDataSource", "h2", "jdbc"),
    DepEntry("com.mysql.jdbc.Buffer", "mysql-jdbc-5", "jdbc"),
    DepEntry(
        "com.mysql.cj.api.authentication.AuthenticationProvider",
        "mysql-connect-6",
        "jdbc",
    ),
    DepEntry(
        "com.mysql.cj.protocol.AuthenticationProvider",
        "mysql-connect-8",
        "jdbc",
    ),
    DepEntry("jdk.nashorn.tools.Shell", "JDK8", "jdk"),
    DepEntry("java.net.http.HttpClient", "JDK11", "jdk"),
    DepEntry(
        "com.sun.org.apache.bcel.internal.util.ClassLoader",
        "<= jdk8u251",
        "jdk",
    ),
    DepEntry("org.apache.ibatis.type.Alias", "Mybatis", "mybatis"),
    DepEntry(
        "org.apache.tomcat.dbcp.dbcp.BasicDataSource",
        "tomcat-dbcp-7-BCEL",
        "tomcat",
    ),
    DepEntry(
        "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
        "tomcat-dbcp-8及以后-BCEL",
        "tomcat",
    ),
    DepEntry(
        "org.apache.commons.dbcp.BasicDataSource",
        "commons-dbcp <= 1.4",
        "commons",
    ),
    DepEntry(
        "org.apache.commons.dbcp2.BasicDataSource",
        "commons-dbcp2 <= 2.13.0",
        "commons",
    ),
    DepEntry(
        "org.apache.commons.io.ByteOrderMark",
        "commons-io-通用类,不确定版本",
        "commons-io",
    ),
    DepEntry(
        "org.apache.commons.io.Java7Support",
        "commons-io-2.5独有",
        "commons-io",
    ),
    DepEntry(
        "org.apache.commons.io.IOIndexedException",
        "commons-io-2.7独有",
        "commons-io",
    ),
    DepEntry(
        "org.apache.commons.io.file.Counters",
        "commons-io-2.7-2.8独有",
        "commons-io",
    ),
    DepEntry(
        "org.apache.commons.io.FileSystem",
        "commons-io-2.7独有",
        "commons-io",
    ),
    DepEntry(
        "org.apache.commons.io.file.PathUtils",
        "commons-io-2.7独有",
        "commons-io",
    ),
    DepEntry(
        "org.apache.commons.io.function.IOConsumer",
        "commons-io-2.7独有",
        "commons-io",
    ),
    DepEntry("org.aspectj.ajde.Ajde", "aspectjtools", "aspectj"),
    DepEntry(
        "com.fasterxml.jackson.core.exc.InputCoercionException",
        "jackson",
        "jackson",
    ),
    DepEntry("org.python.antlr.ParseException", "jython", "jython"),
    DepEntry("org.postgresql.jdbc.PgConnection", "postgre", "jdbc"),
)


def parse_jar_list_text(text: str) -> list[DepEntry]:
    """Parse `class // description` lines (comments / blanks ignored)."""
    entries: list[DepEntry] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "//" not in line:
            continue
        clazz, description = line.split("//", 1)
        clazz = clazz.strip()
        description = description.strip()
        if not clazz:
            continue
        entries.append(DepEntry(clazz=clazz, description=description or clazz))
    return entries


def default_catalog() -> list[DepEntry]:
    return list(DEFAULT_DEP_ENTRIES)
