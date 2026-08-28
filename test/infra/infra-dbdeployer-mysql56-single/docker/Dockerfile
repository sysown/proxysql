FROM ubuntu:22.04

ARG DBDEPLOYER_VERSION=2.2.1
ARG MYSQL_TARBALL_URL=https://dev.mysql.com/get/Downloads/MySQL-5.6/mysql-5.6.49-linux-glibc2.12-x86_64.tar.gz

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libaio1 \
    libnuma1 \
    libncurses5 \
    perl \
    curl \
    ca-certificates \
    openssl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/ProxySQL/dbdeployer/releases/download/v${DBDEPLOYER_VERSION}/dbdeployer-${DBDEPLOYER_VERSION}.linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin/ \
    && chmod +x /usr/local/bin/dbdeployer

RUN mkdir -p /root/downloads /root/opt/mysql \
    && curl -fsSL -o /root/downloads/mysql-5.6.49-linux-glibc2.12-x86_64.tar.gz "${MYSQL_TARBALL_URL}" \
    && dbdeployer unpack /root/downloads/mysql-5.6.49-linux-glibc2.12-x86_64.tar.gz \
    && rm -f /root/downloads/mysql-5.6.49-linux-glibc2.12-x86_64.tar.gz /root/opt/mysql/*/bin/mysqld-debug \
    && apt-get update && apt-get install -y --no-install-recommends binutils \
    && find /root/opt/mysql -type f \( -path '*/bin/*' -o -name '*.so' -o -name '*.so.*' \) \
         -exec sh -c 'strip --strip-unneeded "$1" 2>/dev/null || true' _ {} \; \
    && apt-get purge -y binutils \
    && apt-get autoremove -y --purge \
    && rm -rf /var/lib/apt/lists/*

RUN dbdeployer defaults update reserved-ports '0'

ENV PATH="/root/opt/mysql/5.6.49/bin:${PATH}"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3306

ENTRYPOINT ["/entrypoint.sh"]
