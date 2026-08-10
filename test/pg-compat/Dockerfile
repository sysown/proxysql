# ---- Go builder: static behavior binary (no runtime needed in final) ----
FROM golang:1.23-bookworm AS gobuild
WORKDIR /src
COPY drivers/go/ .
RUN CGO_ENABLED=0 go build -o /out/behaviors-go .

# ---- Java builder: compile against a pinned pgjdbc jar ----
FROM eclipse-temurin:21-jdk AS javabuild
WORKDIR /src
# Pin the driver version explicitly; record bumps in README's driver table.
# PGJDBC_SHA256 must be updated together with PGJDBC_VERSION: verifying the
# digest turns a silent substitution of the downloaded jar into a build failure.
# (Maven Central publishes .sha1 but not .sha256 for this artifact, so the value
# below is the SHA-256 of the jar whose SHA-1 matches the published digest.)
ARG PGJDBC_VERSION=42.7.4
ARG PGJDBC_SHA256=188976721ead8e8627eb6d8389d500dccc0c9bebd885268a3047180274a6031e
# --proto/--proto-redir '=https': -L follows redirects, and without these a
# redirect could downgrade the transfer to plaintext HTTP.
RUN curl -fsSL --proto '=https' --proto-redir '=https' \
        -o /pgjdbc.jar "https://repo1.maven.org/maven2/org/postgresql/postgresql/${PGJDBC_VERSION}/postgresql-${PGJDBC_VERSION}.jar" \
 && echo "${PGJDBC_SHA256}  /pgjdbc.jar" | sha256sum -c -
COPY drivers/java/Behaviors.java .
RUN javac --release 17 -cp /pgjdbc.jar Behaviors.java -d /out

# ---- Node deps: install node-postgres against the lockfile ----
FROM node:22-bookworm-slim AS nodebuild
WORKDIR /app
COPY drivers/node/package.json drivers/node/package-lock.json* ./
# No `|| npm install` fallback: package-lock.json is committed, so `npm ci`
# always succeeds, and the fallback only ever fired when the lockfile was
# missing -- resolving fresh, unlocked versions precisely when reproducibility
# mattered most. Failing loudly is the correct behaviour there.
# --ignore-scripts: `pg` needs no lifecycle scripts, so nothing from the
# dependency tree gets to execute at install time.
RUN npm ci --omit=dev --ignore-scripts
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
# so this is a full install, not --omit=dev. No `|| npm install` fallback --
# package-lock.json is committed (see the node stage for the rationale).
# --ignore-scripts is safe here even though @prisma/client's postinstall
# normally runs `prisma generate`: the explicit `prisma generate` below does
# that job, so the only effect is that no dependency executes code at install
# time.
RUN npm ci --ignore-scripts
COPY drivers/prisma/schema.prisma drivers/prisma/behaviors.mjs ./
ENV PGCOMPAT_PRISMA_URL="postgresql://build:build@localhost:5432/build?sslmode=disable"
# --no-install: run ONLY the prisma CLI already pinned by package-lock.json.
# Bare `npx` silently fetches an unpinned package from the registry when the
# binary is missing locally, which would defeat the lockfile.
RUN npx --no-install prisma generate

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
# --only-binary :all: installs from wheels exclusively, so no package gets to
# run a setup.py at install time. --require-hashes then makes the install abort
# unless every downloaded artifact -- direct and transitive -- matches a SHA-256
# recorded in requirements.txt, which is fully locked for that purpose.
RUN pip install --no-cache-dir --only-binary :all: --require-hashes -r requirements.txt
# Copy exactly what the suite needs rather than `COPY . .`, which would sweep
# in the build context wholesale -- README/SPIKE notes, the driver sources
# already compiled into the earlier stages, run-pg-compat.bash (a host-side
# script), local __pycache__, and anything untracked that happens to be
# sitting in the directory.
COPY conftest.py pytest.ini xfail.toml ./
COPY harness/ ./harness/
COPY behaviors/ ./behaviors/
COPY cases/ ./cases/
COPY tests/ ./tests/
# drivers/: only the Python tier is needed at runtime -- tests/test_behaviors.py
# imports drivers.python.adapter in-process, whereas the go/java/node/prisma
# tiers are compiled or installed in the earlier stages and arrive via their own
# COPY --from lines below. drivers/__init__.py is required for the package import.
COPY drivers/__init__.py ./drivers/
COPY drivers/python/ ./drivers/python/
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
# Drop privileges: nothing here needs root at runtime. This suite exists to
# execute third-party driver code (pgx, pgjdbc, node-postgres, Prisma) against
# a live backend, so running it unprivileged bounds what a compromised
# dependency can reach. /pg-compat is chowned because pytest writes
# .pytest_cache and __pycache__ into the rootdir.
RUN useradd --create-home --uid 10001 pgcompat \
 && chown -R pgcompat:pgcompat /pg-compat
USER pgcompat
ENTRYPOINT ["pytest", "-q"]
