###############################################################################
# Multi-stage Dockerfile for building ProxySQL from source
###############################################################################

# ------------------ Stage 1: Build ------------------------------------------
FROM ubuntu:24.04 AS builder

ARG MAKEOPT=-j$(nproc)
ARG PROXYSQL_BUILD_TYPE=clickhouse

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    automake \
    bzip2 \
    cmake \
    make \
    g++ \
    gcc \
    git \
    openssl \
    libssl-dev \
    libgnutls28-dev \
    libmysqlclient-dev \
    libunwind8 \
    libunwind-dev \
    uuid-dev \
    libncurses-dev \
    libicu-dev \
    libevent-dev \
    libtirpc-dev \
    patch \
    python3 \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/proxysql

COPY . .

RUN make build_deps ${MAKEOPT} \
    && make ${MAKEOPT}

# ------------------ Stage 2: Runtime ----------------------------------------
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3t64 \
    libgnutls30t64 \
    libunwind8 \
    libuuid1 \
    libncurses6 \
    libicu74 \
    libevent-2.1-7t64 \
    libtirpc3t64 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -U -s /bin/false proxysql \
    && mkdir -p /var/lib/proxysql \
    && chown proxysql:proxysql /var/lib/proxysql

COPY --from=builder /opt/proxysql/src/proxysql /usr/bin/proxysql
COPY --from=builder /opt/proxysql/etc/proxysql.cnf /etc/proxysql.cnf

# Admin interface
EXPOSE 6032
# MySQL traffic
EXPOSE 6033
# REST API
EXPOSE 6070

ENTRYPOINT ["proxysql"]
CMD ["-f", "--idle-threads"]
