FROM ubuntu:22.04

ARG DBDEPLOYER_VERSION=2.3.0

ENV DEBIAN_FRONTEND=noninteractive

# System dependencies required by MariaDB 10.11 + Galera runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libaio1 \
    libnuma1 \
    libncurses5 \
    libsystemd0 \
    socat \
    rsync \
    lsof \
    perl \
    curl \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Galera wsrep provider (libgalera_smm.so) in the MariaDB 10.11 tarball
# was linked against OpenSSL 1.0. Install compat library from Ubuntu 18.04
# archive since Ubuntu 22.04 ships OpenSSL 3.x only.
RUN wget -q \
    'http://archive.ubuntu.com/ubuntu/pool/main/o/openssl1.0/libssl1.0.0_1.0.2n-1ubuntu5_amd64.deb' \
    -O /tmp/libssl1.0.0.deb \
    && dpkg -i /tmp/libssl1.0.0.deb \
    && rm /tmp/libssl1.0.0.deb

# Install dbdeployer
RUN curl -fsSL "https://github.com/ProxySQL/dbdeployer/releases/download/v${DBDEPLOYER_VERSION}/dbdeployer-${DBDEPLOYER_VERSION}.linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin/ \
    && chmod +x /usr/local/bin/dbdeployer

# Download and unpack MariaDB 10.11 tarball via dbdeployer.
RUN mkdir -p /root/opt/mysql \
    && dbdeployer downloads get-unpack mariadb-10.11.9-linux-systemd-x86_64.tar.gz \
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

ENV PATH="/root/opt/mysql/10.11.9/bin:${PATH}"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3306 3307 3308

ENTRYPOINT ["/entrypoint.sh"]
