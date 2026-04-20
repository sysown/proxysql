FROM ubuntu:22.04

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
    passwd \
    procps \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r mysql && useradd -r -g mysql -d /var/lib/mysql -s /bin/bash mysql

RUN mkdir -p /opt /etc/mysql /var/lib/mysql /var/log/mysql \
    && curl -fsSL -o /tmp/mysql-5.6.49-linux-glibc2.12-x86_64.tar.gz "${MYSQL_TARBALL_URL}" \
    && tar -xzf /tmp/mysql-5.6.49-linux-glibc2.12-x86_64.tar.gz -C /opt \
    && ln -s /opt/mysql-5.6.49-linux-glibc2.12-x86_64 /opt/mysql \
    && rm -f /tmp/mysql-5.6.49-linux-glibc2.12-x86_64.tar.gz /opt/mysql/bin/mysqld-debug \
    && chown -R mysql:mysql /var/lib/mysql /var/log/mysql

ENV PATH="/opt/mysql/bin:${PATH}"

COPY mysql1/my.cnf /etc/mysql/my.cnf
COPY ssl/configure_ssl.sh /usr/local/bin/configure_ssl.sh
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/configure_ssl.sh /usr/local/bin/docker-entrypoint.sh

EXPOSE 3306

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
