# The binlog reader is pinned to the release that carries MariaDB GTID support.
# It is the reader image contract that test/tap/groups/test_binlog_reader_infra.py
# enforces for every binlog infra: this exact tag, and the CI TLS policy
# (--ssl-mode=REQUIRED --ssl-verify-server-cert=0) in entrypoint.sh.
FROM ghcr.io/sysown/proxysql-mysqlbinlog:2.5.0-ubuntu22 AS binlog-reader

FROM ubuntu:22.04

# 2.4.1 is the first release carrying the fix for #82, where a MariaDB version
# with a major >= 11 was classified as newer than MySQL 8.0.23 and the generated
# replication SQL used CHANGE REPLICATION SOURCE TO, which MariaDB rejects. Keep
# this at 2.4.0 or newer.
ARG DBDEPLOYER_VERSION=2.4.2

ENV DEBIAN_FRONTEND=noninteractive

# System dependencies required by MariaDB, plus openssl for generating the TLS
# material. dbdeployer does not produce SSL certificates for MariaDB sandboxes
# (it does for MySQL), so the entrypoint has to create them; see gen_tls_certs().
RUN apt-get update && apt-get install -y --no-install-recommends \
    libaio1 \
    libnuma1 \
    libncurses5 \
    libsystemd0 \
    perl \
    curl \
    ca-certificates \
    openssl \
    && rm -rf /var/lib/apt/apt/lists/*

# Install dbdeployer
RUN curl -fsSL "https://github.com/ProxySQL/dbdeployer/releases/download/v${DBDEPLOYER_VERSION}/dbdeployer-${DBDEPLOYER_VERSION}.linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin/ \
    && chmod +x /usr/local/bin/dbdeployer

# Download and unpack the MariaDB tarball via dbdeployer.
#
# Resolved by *version*, not by tarball name, on purpose. `downloads
# get-unpack <tarball-name>` only looks the name up in dbdeployer's static
# downloads/tarball_list.json, which carries five MariaDB entries and the newest
# 10.11 is 10.11.9 -- so a name like mariadb-10.11.19-... fails with "tarball
# with name ... not found" even though MariaDB publishes it. `get-by-version`
# misses the static list and falls back to the MariaDB downloads API, which
# resolves 10.11 to the current 10.11.x. The glob below keeps `unpack` correct as
# that patch level moves.
#
# Cleanup in the same layer: remove mysqld-debug if present and strip all ELF
# binaries/shared libs. binutils is installed temporarily for strip and purged.
RUN mkdir -p /root/opt/mysql \
    && cd /root/opt/mysql \
    && dbdeployer downloads get-by-version 10.11 --flavor mariadb --OS linux --arch amd64 \
    && dbdeployer unpack \
         /root/opt/mysql/mariadb-10.11.*-linux-systemd-x86_64.tar.gz \
    && rm -f /root/opt/mysql/*.tar.gz /root/opt/mysql/*.tar.xz \
    && rm -f /root/opt/mysql/*/bin/mysqld-debug \
    && apt-get update && apt-get install -y --no-install-recommends binutils \
    && find /root/opt/mysql -type f \( -path '*/bin/*' -o -name '*.so' -o -name '*.so.*' \) \
         -exec sh -c 'strip --strip-unneeded "$1" 2>/dev/null || true' _ {} \; \
    && apt-get purge -y binutils \
    && apt-get autoremove -y --purge \
    && rm -rf /var/lib/apt/apt/lists/*

# Clear reserved ports so dbdeployer allows base-port 3305 (nodes get 3306,3307,3308).
# dbdeployer reserves 1186,3306,5432,33060,33062 by default; replace with a
# harmless value.
RUN dbdeployer defaults update reserved-ports '0'

# Copy proxysql_binlog_reader from the binlog reader image
COPY --from=binlog-reader /bin/proxysql_binlog_reader /usr/local/bin/proxysql_binlog_reader

# Make MariaDB client available in PATH for docker exec health checks
ENV PATH="/root/opt/mysql/10.11.19/bin:${PATH}"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3306 3307 3308 6020 6021 6022

ENTRYPOINT ["/entrypoint.sh"]
