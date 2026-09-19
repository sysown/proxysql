# syntax=docker/dockerfile:1
#
# MySQL 8.4 sandbox servers (the server version is irrelevant for Routing
# Guidelines) plus an UNMODIFIED MySQL Shell 9.x, which creates InnoDB Cluster
# metadata schema 2.3+ and exposes the Routing Guidelines AdminAPI.
#
# The InnoDB Cluster entrypoint is shared with infra-mysql-router-ic and is
# supplied by build.sh through the "router_ic" named build context.
FROM proxysql/ci-infra:dbdeployer-mysql84

ARG MYSQL_SHELL_VERSION=9.7.0
ARG MYSQL_SHELL_GLIBC=2.28

RUN curl -fsSL "https://cdn.mysql.com/archives/mysql-shell/mysql-shell-${MYSQL_SHELL_VERSION}-linux-glibc${MYSQL_SHELL_GLIBC}-x86-64bit.tar.gz" \
      | tar -xz -C /opt \
    && ln -s "/opt/mysql-shell-${MYSQL_SHELL_VERSION}-linux-glibc${MYSQL_SHELL_GLIBC}-x86-64bit/bin/mysqlsh" /usr/local/bin/mysqlsh \
    && mysqlsh --version | grep -F "Ver ${MYSQL_SHELL_VERSION} "

COPY --from=router_ic entrypoint.sh /entrypoint-mysql-router-ic.sh
COPY rg-shell.sh mysqlsh-queue.sh /usr/local/bin/
COPY rg-shell-prelude.js /usr/local/share/mysql-router-ic/rg-shell-prelude.js
RUN chmod +x /entrypoint-mysql-router-ic.sh /usr/local/bin/rg-shell.sh /usr/local/bin/mysqlsh-queue.sh

EXPOSE 3306 3307 3308 3309
ENTRYPOINT ["/entrypoint-mysql-router-ic.sh"]
