# Fastjson 1.2.80 Exception cache gadget lab
# JDK11：Nashorn URLReader；预编译 groovy evil.jar（SPI 写文件证明）
FROM maven:3.9.9-eclipse-temurin-11 AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
COPY attack ./attack
RUN mvn -q -DskipTests package \
    && test -f target/lib/jackson-core-2.13.5.jar \
    && test -f target/lib/commons-io-2.6.jar \
    && test -f target/lib/groovy-2.4.21.jar \
    && test -f target/lib/ant-1.10.12.jar \
    && mkdir -p attack/out/META-INF/services \
    && javac -cp "target/lib/groovy-2.4.21.jar" -d attack/out attack/EvilAst.java \
    && cp attack/META-INF/services/org.codehaus.groovy.transform.ASTTransformation \
          attack/out/META-INF/services/ \
    && jar cf attack/evil.jar -C attack/out . \
    && sed -e 's|__CONTENT__|FJ1280_POSTGRESQL|g' -e 's|__FILE__|/tmp/fj1280_postgresql|g' \
          attack/bean-write.xml.template > attack/bean-postgresql.xml \
    && sed -e 's|__CONTENT__|FJ1280_JYTHON|g' -e 's|__FILE__|/tmp/fj1280_jython|g' \
          attack/bean-write.xml.template > attack/bean-jython.xml

FROM eclipse-temurin:11-jdk
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* || true

COPY --from=build /src/target/fastjson-1280-lab-1.0.0.jar /app/app.jar
COPY --from=build /src/target/lib /app/lib
COPY --from=build /src/attack/evil.jar /app/attack/evil.jar
COPY --from=build /src/attack/bean-postgresql.xml /app/attack/bean-postgresql.xml
COPY --from=build /src/attack/bean-jython.xml /app/attack/bean-jython.xml

ENV SERVER_PORT=18080
EXPOSE 18080

HEALTHCHECK --interval=10s --timeout=3s --start-period=35s --retries=10 \
  CMD curl -fsS http://127.0.0.1:${SERVER_PORT}/api/health || exit 1

ENTRYPOINT ["sh", "-c", "java -cp '/app/app.jar:/app/lib/*' com.fastjsonlab.GadgetLabServer"]
