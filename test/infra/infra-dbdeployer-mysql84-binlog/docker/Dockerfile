# NOTE: v2.3 is required for MySQL 8.4 (v2.1 uses SHOW MASTER STATUS which is removed in 8.4)
# Build it from https://github.com/sysown/proxysql_mysqlbinlog (tag 2.3+):
#   cd /tmp/proxysql_mysqlbinlog && make build-debian12
#   cp binaries/proxysql-mysqlbinlog_*.deb test/infra/docker-mysql84-binlogreader/
#   bash test/infra/docker-mysql84-binlogreader/build.sh
FROM proxysql/ci-infra:proxysql-mysqlbinlog-v2.3 AS binlog-reader

FROM ubuntu:22.04

ARG DBDEPLOYER_VERSION=2.2.1

ENV DEBIAN_FRONTEND=noninteractive

# System dependencies required by MySQL 8.4
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

# Download and unpack MySQL 8.4 tarball using dbdeployer (pre-baked so no download at runtime).
# Cleanup in the same layer: remove the downloaded tarball, drop mysqld-debug, and strip
# all ELF binaries/shared libs. binutils is installed temporarily for strip and purged after.
RUN mkdir -p /root/opt/mysql \
    && dbdeployer downloads get-unpack mysql-8.4.8-linux-glibc2.17-x86_64.tar.xz \
    && rm -f /*.tar.xz /*.tar.gz \
    && rm -f /root/opt/mysql/*/bin/mysqld-debug \
    && apt-get update && apt-get install -y --no-install-recommends binutils \
    && find /root/opt/mysql -type f \( -path '*/bin/*' -o -name '*.so' -o -name '*.so.*' \) \
         -exec sh -c 'strip --strip-unneeded "$1" 2>/dev/null || true' _ {} \; \
    && apt-get purge -y binutils \
    && apt-get autoremove -y --purge \
    && rm -rf /var/lib/apt/lists/*

# Clear reserved ports so dbdeployer allows base-port 3305 (nodes get 3306,3307,3308)
RUN dbdeployer defaults update reserved-ports '0'

# Copy proxysql_binlog_reader from the binlog reader image
COPY --from=binlog-reader /usr/bin/proxysql_binlog_reader /usr/local/bin/proxysql_binlog_reader

# Make MySQL client available in PATH for docker exec health checks
ENV PATH="/root/opt/mysql/8.4.8/bin:${PATH}"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3306 3307 3308 6020 6021 6022

ENTRYPOINT ["/entrypoint.sh"]
