FROM ubuntu:24.04

ARG MYSQL_CONNECTOR_PYTHON_VERSION=9.7.0

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
    && pip3 install --break-system-packages fastcov \
        "mysql-connector-python==${MYSQL_CONNECTOR_PYTHON_VERSION}" \
        "mysqlx-connector-python==${MYSQL_CONNECTOR_PYTHON_VERSION}" \
    && wget https://github.com/openark/orchestrator/releases/download/v3.2.6/orchestrator-client_3.2.6_amd64.deb -O /tmp/orc.deb \
    && apt-get install -y /tmp/orc.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/orc.deb

WORKDIR /var/lib/proxysql
