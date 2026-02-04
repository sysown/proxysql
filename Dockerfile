###############################################################################
# Multi-stage Dockerfile for building ProxySQL from source
###############################################################################

# ------------------ Stage 1: Build ------------------------------------------
FROM ubuntu:24.04 AS builder

ARG GIT_VERSION
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    bison \
    bzip2 \
    ca-certificates \
    cmake \
    make \
    g++ \
    gcc \
    flex \
    gawk \
    git \
    libtool \
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
    zlib1g-dev \
    patch \
    python3 \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/proxysql

COPY . .

RUN export GIT_VERSION="${GIT_VERSION:-$(git describe --long --abbrev=7 2>/dev/null || echo '3.0.6-0-unknown')}" \
    && make build_deps \
    && make -j$(nproc)

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
