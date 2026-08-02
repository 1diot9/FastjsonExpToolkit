# Fastjson 1.2.47 gadget lab
# 运行时必须 JDK <= 8u251，否则无 com.sun.org.apache.bcel.internal.util.ClassLoader
FROM maven:3.9.9-eclipse-temurin-8 AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN mvn -q -DskipTests package \
    && test -f target/BcelProbe.class \
    && test -f target/H2Probe.class \
    && test -f target/EvilH2.class \
    && test -f target/c3p0-proof.hex \
    && test -f target/lib/tomcat-dbcp-7.0.109.jar \
    && test -f target/lib/tomcat-dbcp-9.0.83.jar

# 8u242 < 8u251：保留内部 BCEL ClassLoader
FROM openjdk:8u242-jdk
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* || true

COPY --from=build /src/target/fastjson-1247-lab-1.0.0.jar /app/app.jar
COPY --from=build /src/target/lib /app/lib
COPY --from=build /src/target/BcelProbe.class /app/proof/BcelProbe.class
COPY --from=build /src/target/H2Probe.class /app/proof/H2Probe.class
COPY --from=build /src/target/EvilH2.class /app/proof/EvilH2.class
COPY --from=build /src/target/c3p0-proof.hex /app/proof/c3p0-proof.hex

ENV SERVER_PORT=18080
EXPOSE 18080

HEALTHCHECK --interval=10s --timeout=3s --start-period=25s --retries=10 \
  CMD curl -fsS http://127.0.0.1:${SERVER_PORT}/api/health || exit 1

# 7.x + 9.x tomcat-dbcp 同时在 lib/；应用 jar 在最前
ENTRYPOINT ["sh", "-c", "java -cp '/app/app.jar:/app/lib/*' com.fastjsonlab.GadgetLabServer"]
