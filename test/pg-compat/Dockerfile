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
RUN javac --release 17 -cp /pgjdbc.jar Behaviors.java -d /out

# ---- Node deps: install node-postgres against the lockfile ----
FROM node:22-bookworm-slim AS nodebuild
WORKDIR /app
COPY drivers/node/package.json drivers/node/package-lock.json* ./
# The `npm install` fallback must never be reached in normal operation
# (package-lock.json is committed, so `npm ci` succeeds); it exists only
# for first-bootstrap before a lockfile exists.
RUN npm ci --omit=dev || npm install --omit=dev
COPY drivers/node/behaviors.js .

# ---- Prisma deps + client generation (ORM tier, SP3-Task 5) ----
# npm ci pulls prisma (CLI, a devDependency) AND @prisma/client, then
# `prisma generate` produces the client + downloads the query-engine binary
# for binaryTargets=["debian-openssl-3.0.x"] (matching the bookworm/OpenSSL-3
# final image). This stage is bookworm/OpenSSL-3 too, so the engine it
# fetches is the exact one the final stage runs. The engine download needs
# network egress -> the build runs with --network=host (see
# run-pg-compat.bash). PGCOMPAT_PRISMA_URL only has to EXIST for `generate`
# (it does not connect); behaviors.mjs overwrites it at runtime.
FROM node:22-bookworm-slim AS prismabuild
WORKDIR /app
COPY drivers/prisma/package.json drivers/prisma/package-lock.json* ./
# devDependencies (the prisma CLI) are REQUIRED here for `prisma generate`,
# so this is a full install, not --omit=dev. The `npm install` fallback must
# never be reached in normal operation (package-lock.json is committed).
RUN npm ci || npm install
COPY drivers/prisma/schema.prisma drivers/prisma/behaviors.mjs ./
ENV PGCOMPAT_PRISMA_URL="postgresql://build:build@localhost:5432/build?sslmode=disable"
RUN npx prisma generate

# ---- Final: python base + JRE + node runtime + artifacts ----
FROM python:3.11-slim
# openssl/libssl3: the Prisma query engine (debian-openssl-3.0.x) links
# against libssl.so.3 / libcrypto.so.3 at load time.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 curl default-jre-headless openssl \
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
# Prisma app: node_modules (with the generated @prisma/client + .prisma
# client + query-engine binary), schema.prisma, behaviors.mjs.
# Known size trade-off: this copies the whole prismabuild dev tree,
# including the prisma CLI devDependency and its non-query engines
# (schema/format engines), not just what behaviors.mjs needs at runtime --
# simple and correct over minimal. Task 6's image-size measurement accounts
# for it; prune here if the numbers demand it.
COPY --from=prismabuild /app /pg-compat/prisma-app
RUN printf '#!/bin/sh\nexec java -cp /pg-compat/bin/java-classes:/pg-compat/bin/pgjdbc.jar Behaviors "$@"\n' > /pg-compat/bin/behaviors-java \
 && printf '#!/bin/sh\nexec node /pg-compat/node-app/behaviors.js "$@"\n' > /pg-compat/bin/behaviors-node \
 && printf '#!/bin/sh\nexec node /pg-compat/prisma-app/behaviors.mjs "$@"\n' > /pg-compat/bin/behaviors-prisma \
 && chmod +x /pg-compat/bin/behaviors-*
ENTRYPOINT ["pytest", "-q"]
