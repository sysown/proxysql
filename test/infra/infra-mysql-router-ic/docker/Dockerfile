FROM proxysql/ci-infra:dbdeployer-mysql84

ARG MYSQL_SHELL_VERSION=8.4.8

RUN curl -fsSL "https://cdn.mysql.com/archives/mysql-shell/mysql-shell-${MYSQL_SHELL_VERSION}-linux-glibc2.17-x86-64bit.tar.gz" \
      | tar -xz -C /opt \
    && ln -s "/opt/mysql-shell-${MYSQL_SHELL_VERSION}-linux-glibc2.17-x86-64bit/bin/mysqlsh" /usr/local/bin/mysqlsh

COPY entrypoint.sh /entrypoint-mysql-router-ic.sh
RUN chmod +x /entrypoint-mysql-router-ic.sh

EXPOSE 3306 3307 3308 3309
ENTRYPOINT ["/entrypoint-mysql-router-ic.sh"]
