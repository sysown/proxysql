FROM ubuntu:24.04

ARG MYSQL_CONNECTOR_PYTHON_VERSION=9.7.0
ARG PSYCOPG_VERSION=3.2.13

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
    mysql-client \
    mysql-shell \
    mycli \
    postgresql-client \
    iputils-ping \
    curl \
    wget \
    ca-certificates \
    net-tools \
    iproute2 \
    vim \
    git \
    sudo \
    python3 \
    python3-pip \
    python3-pymysql \
    python3-requests \
    python3-yaml \
    python3-packaging \
    python3-structlog \
    sysbench \
    php-cli \
    php-mysql \
    lcov \
    gcc-11 \
    && pip3 install --break-system-packages fastcov \
        "psycopg[binary]==${PSYCOPG_VERSION}" \
        "mysql-connector-python==${MYSQL_CONNECTOR_PYTHON_VERSION}" \
        "mysqlx-connector-python==${MYSQL_CONNECTOR_PYTHON_VERSION}" \
    && wget https://github.com/proxysql/orchestrator/releases/download/v4.31.1/orchestrator-client_4.31.1_amd64.deb -O /tmp/orc.deb \
    && apt-get install -y /tmp/orc.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/orc.deb

WORKDIR /var/lib/proxysql
