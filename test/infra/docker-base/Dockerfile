FROM ubuntu:24.04

ARG MYSQL_CONNECTOR_PYTHON_VERSION=9.7.0
ARG PSYCOPG_VERSION=3.2.13
# orchestrator-client is published per architecture (amd64/arm64 .deb); the
# matching package is picked from dpkg at build time so the image builds on
# both x86_64 and arm64 hosts (e.g. Apple Silicon). See GH issue #6200.
ARG ORCHESTRATOR_CLIENT_VERSION=4.32.0

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
    mysql-client \
    # mysql-server-core pulls in mysqlbinlog, which test_com_binlog_dump_enables_fast_forward-t
    # shells out to at runtime. mysql-client does NOT (its core package only ships
    # mysql / mysqladmin / mysqldump etc., not mysqlbinlog). Without this the binlog
    # TAP tests fail with sh: 1: .../mysqlbinlog: not found even after the runner
    # fallback in test/infra/control/run-tests-isolated.bash succeeds at creating the
    # symlink -- the symlink target just doesn't exist. ~118 MB extra in the base
    # image; cost is paid once and shared by every consumer. See GH issue #6092.
    mysql-server-core-8.0 \
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
        "psycopg[binary]==${PSYCOPG_VERSION}" \
        "mysql-connector-python==${MYSQL_CONNECTOR_PYTHON_VERSION}" \
        "mysqlx-connector-python==${MYSQL_CONNECTOR_PYTHON_VERSION}" \
    && python3 -c "import psycopg; assert psycopg.__version__ == '${PSYCOPG_VERSION}'" \
    && ORC_ARCH="$(dpkg --print-architecture)" \
    && case "${ORC_ARCH}" in amd64|arm64) ;; *) echo "orchestrator-client: unsupported architecture ${ORC_ARCH}" >&2; exit 1 ;; esac \
    && wget "https://github.com/proxysql/orchestrator/releases/download/v${ORCHESTRATOR_CLIENT_VERSION}/orchestrator-client_${ORCHESTRATOR_CLIENT_VERSION}_${ORC_ARCH}.deb" -O /tmp/orc.deb \
    && apt-get install -y /tmp/orc.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/orc.deb

WORKDIR /var/lib/proxysql
