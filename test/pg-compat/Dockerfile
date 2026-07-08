# ---- Go builder: static behavior binary (no runtime needed in final) ----
FROM golang:1.23-bookworm AS gobuild
WORKDIR /src
COPY drivers/go/ .
RUN CGO_ENABLED=0 go build -o /out/behaviors-go .

# ---- Java builder: compile against a pinned pgjdbc jar ----
FROM eclipse-temurin:21-jdk AS javabuild
WORKDIR /src
# Pin the driver version explicitly; record bumps in README's driver table.
ARG PGJDBC_VERSION=42.7.4
RUN curl -fsSLo /pgjdbc.jar "https://repo1.maven.org/maven2/org/postgresql/postgresql/${PGJDBC_VERSION}/postgresql-${PGJDBC_VERSION}.jar"
COPY drivers/java/Behaviors.java .
RUN javac -cp /pgjdbc.jar Behaviors.java -d /out

# ---- Node deps: install node-postgres against the lockfile ----
FROM node:22-bookworm-slim AS nodebuild
WORKDIR /app
COPY drivers/node/package.json drivers/node/package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev
COPY drivers/node/behaviors.js .

# ---- Final: python base + JRE + node runtime + artifacts ----
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 curl default-jre-headless \
    && rm -rf /var/lib/apt/lists/*
# Node runtime copied from the official image (bookworm-glibc compatible).
COPY --from=nodebuild /usr/local/bin/node /usr/local/bin/node
WORKDIR /pg-compat
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Language artifacts under /pg-compat/bin with uniform CLI wrappers.
COPY --from=gobuild /out/behaviors-go /pg-compat/bin/behaviors-go
COPY --from=javabuild /out/ /pg-compat/bin/java-classes/
COPY --from=javabuild /pgjdbc.jar /pg-compat/bin/pgjdbc.jar
COPY --from=nodebuild /app /pg-compat/node-app
RUN printf '#!/bin/sh\nexec java -cp /pg-compat/bin/java-classes:/pg-compat/bin/pgjdbc.jar Behaviors "$@"\n' > /pg-compat/bin/behaviors-java \
 && printf '#!/bin/sh\nexec node /pg-compat/node-app/behaviors.js "$@"\n' > /pg-compat/bin/behaviors-node \
 && chmod +x /pg-compat/bin/behaviors-*
ENTRYPOINT ["pytest", "-q"]
