ARG FASTJSON_VERSION=1.2.83

FROM maven:3.9.6-eclipse-temurin-8 AS build
ARG FASTJSON_VERSION
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn -q -DskipTests -Dfastjson.version=${FASTJSON_VERSION} package

FROM eclipse-temurin:8-jre
ARG FASTJSON_VERSION
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/fastjson-version-lab-1.0.0.jar app.jar
ENV SERVER_PORT=18080
ENV FASTJSON_LAB_VERSION=${FASTJSON_VERSION}
EXPOSE 18080
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=10 \
  CMD curl -fsS http://127.0.0.1:${SERVER_PORT}/api/health || exit 1
ENTRYPOINT ["sh", "-c", "java -Dfastjson.lab.version=${FASTJSON_LAB_VERSION} -jar app.jar"]
