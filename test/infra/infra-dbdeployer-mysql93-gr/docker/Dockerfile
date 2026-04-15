FROM ubuntu:22.04

ARG DBDEPLOYER_VERSION=2.2.1

ENV DEBIAN_FRONTEND=noninteractive

# System dependencies required by MySQL 9.3
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

# Download and unpack MySQL 9.3 tarball using dbdeployer (pre-baked so no download at runtime)
RUN mkdir -p /root/opt/mysql \
    && dbdeployer downloads get-unpack mysql-9.3.0-linux-glibc2.28-x86_64.tar.xz

# Clear reserved ports so dbdeployer allows base-port 3305 (nodes get 3306,3307,3308)
# dbdeployer reserves 1186,3306,5432,33060,33062 by default; replace with harmless value
RUN dbdeployer defaults update reserved-ports '0'

# Make MySQL client available in PATH for docker exec health checks
ENV PATH="/root/opt/mysql/9.3.0/bin:${PATH}"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3306 3307 3308

ENTRYPOINT ["/entrypoint.sh"]
