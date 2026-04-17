FROM ubuntu:22.04

ARG DBDEPLOYER_VERSION=2.2.1
ARG MYSQL_TARBALL_URL=https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-5.7.44-linux-glibc2.12-x86_64.tar.gz

ENV DEBIAN_FRONTEND=noninteractive

# System dependencies required by MySQL 5.7
RUN apt-get update && apt-get install -y --no-install-recommends \
    libaio1 \
    libnuma1 \
    libncurses5 \
    perl \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install dbdeployer
RUN curl -fsSL "https://github.com/ProxySQL/dbdeployer/releases/download/v${DBDEPLOYER_VERSION}/dbdeployer-${DBDEPLOYER_VERSION}.linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin/ \
    && chmod +x /usr/local/bin/dbdeployer

# Download and unpack MySQL 5.7 tarball (pre-baked so no download at runtime).
# Cleanup in the same layer: drop mysqld-debug if present, and strip all ELF binaries/shared
# libs. binutils is installed temporarily for strip and purged after.
RUN mkdir -p /root/downloads /root/opt/mysql \
    && curl -fsSL -o /root/downloads/mysql-5.7.44-linux-glibc2.12-x86_64.tar.gz "${MYSQL_TARBALL_URL}" \
    && dbdeployer unpack /root/downloads/mysql-5.7.44-linux-glibc2.12-x86_64.tar.gz \
    && rm -f /root/downloads/mysql-5.7.44-linux-glibc2.12-x86_64.tar.gz \
    && rm -f /root/opt/mysql/*/bin/mysqld-debug \
    && rm -f /root/opt/mysql/*/lib/libmysqld.a /root/opt/mysql/*/lib/libmysqld-debug.a \
    && apt-get update && apt-get install -y --no-install-recommends binutils \
    && find /root/opt/mysql -type f \( -path '*/bin/*' -o -name '*.so' -o -name '*.so.*' \) \
         -exec sh -c 'strip --strip-unneeded "$1" 2>/dev/null || true' _ {} \; \
    && apt-get purge -y binutils \
    && apt-get autoremove -y --purge \
    && rm -rf /var/lib/apt/lists/*

# Clear reserved ports so dbdeployer allows base-port 3305 (nodes get 3306,3307,3308)
# dbdeployer reserves 1186,3306,5432,33060,33062 by default; replace with harmless value
RUN dbdeployer defaults update reserved-ports '0'

# Make MySQL client available in PATH for docker exec health checks
ENV PATH="/root/opt/mysql/5.7.44/bin:${PATH}"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3306 3307 3308

ENTRYPOINT ["/entrypoint.sh"]
