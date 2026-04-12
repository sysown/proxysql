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

# Download and unpack MySQL 5.7 tarball (pre-baked so no download at runtime)
RUN mkdir -p /root/downloads \
    && curl -fsSL -o /root/downloads/mysql-5.7.44.tar.gz "${MYSQL_TARBALL_URL}" \
    && dbdeployer unpack /root/downloads/mysql-5.7.44.tar.gz \
    && rm -f /root/downloads/mysql-5.7.44.tar.gz

# Clear reserved ports so dbdeployer allows 3306
RUN dbdeployer defaults update reserved-ports ''

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3306 3307 3308

ENTRYPOINT ["/entrypoint.sh"]
