# Fastjson 1.2.68 AutoCloseable gadget lab
# JDK11：MarshalOutputStream 任意写 + Nashorn URLReader 读文件
FROM maven:3.9.9-eclipse-temurin-11 AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN mvn -q -DskipTests package \
    && test -f target/lib/commons-io-2.6.jar \
    && test -f target/lib/aspectjtools-1.9.6.jar

FROM eclipse-temurin:11-jdk
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* || true

COPY --from=build /src/target/fastjson-1268-lab-1.0.0.jar /app/app.jar
COPY --from=build /src/target/lib /app/lib

ENV SERVER_PORT=18080
EXPOSE 18080

HEALTHCHECK --interval=10s --timeout=3s --start-period=25s --retries=10 \
  CMD curl -fsS http://127.0.0.1:${SERVER_PORT}/api/health || exit 1

ENTRYPOINT ["sh", "-c", "java -cp '/app/app.jar:/app/lib/*' com.fastjsonlab.GadgetLabServer"]
