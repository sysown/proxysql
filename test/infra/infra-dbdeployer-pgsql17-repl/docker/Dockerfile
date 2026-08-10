FROM ubuntu:22.04

ARG DBDEPLOYER_VERSION=2.2.1

# PostgreSQL point release to bake in. Pinned so the dbdeployer-derived ports
# stay fixed at 16710/16711/16712 (ports = 15000 + major*100 + minor, per the
# Task 1 spike). If PGDG retires this exact point release, bump all three of
# PG_VERSION/PG_DEB_VERSION and the ports in .env / env.sh together (the ENV
# PATH below auto-follows PG_VERSION).
ARG PG_MAJOR=17
ARG PG_VERSION=17.10
ARG PG_DEB_VERSION=17.10-1.pgdg22.04+1

ENV DEBIAN_FRONTEND=noninteractive

# Base tooling: dbdeployer install (curl|tar), PGDG repo setup (gnupg/wget),
# and su/psql helpers. PostgreSQL runtime shared libraries are installed later
# from the downloaded PGDG .debs (the Debian PG binaries are NOT self-contained).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Install dbdeployer (ProxySQL fork release; tarball member is already named
# 'dbdeployer', no rename needed).
RUN curl -fsSL "https://github.com/ProxySQL/dbdeployer/releases/download/v${DBDEPLOYER_VERSION}/dbdeployer-${DBDEPLOYER_VERSION}.linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin/ \
    && chmod +x /usr/local/bin/dbdeployer

# Add the PGDG apt repo (ubuntu:22.04 = jammy).
RUN install -d /usr/share/postgresql-common/pgdg \
    && wget -q -O /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
       https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt jammy-pgdg main" \
       > /etc/apt/sources.list.d/pgdg.list

# Non-root user: initdb / postgres refuse to run as root, so every dbdeployer
# PG command (unpack at build time, deploy at runtime) runs as pguser.
RUN useradd -m -s /bin/bash pguser

# Download the PGDG .debs (raw packages, NOT a system install of PG) plus all
# their dependency .debs into /root/pgdebs. dbdeployer unpack consumes the two
# server/client .debs directly; the dependency .debs supply the runtime shared
# libraries the Debian PG binaries need (libpq5, libicu70, libllvm15, tzdata, ...).
RUN mkdir -p /root/pgdebs \
    && apt-get update \
    && apt-get install -y -qq --download-only --reinstall -o Dir::Cache::archives=/root/pgdebs \
       postgresql-${PG_MAJOR}=${PG_DEB_VERSION} \
       postgresql-client-${PG_MAJOR}=${PG_DEB_VERSION} \
       postgresql-common postgresql-client-common \
    # Install every downloaded dependency .deb (the shared libs + apt housekeeping
    # packages) system-wide, but NOT the two main postgresql server/client packages
    # -- those must be unpacked by dbdeployer into pguser's home instead.
    && DEP_DEBS=$(ls /root/pgdebs/*.deb | grep -vE "/(postgresql-${PG_MAJOR}|postgresql-client-${PG_MAJOR})_[0-9]") \
    && apt-get install -y -qq ${DEP_DEBS} \
    && ldconfig \
    && rm -rf /var/lib/apt/lists/*

# Copy the two main .debs to a pguser-readable path (/root is mode 700) and
# unpack them via dbdeployer as pguser -> /home/pguser/opt/postgresql/<version>/.
RUN mkdir -p /home/pguser/pgdebs \
    && cp /root/pgdebs/postgresql-${PG_MAJOR}_*.deb /home/pguser/pgdebs/ \
    && cp /root/pgdebs/postgresql-client-${PG_MAJOR}_*.deb /home/pguser/pgdebs/ \
    && chown -R pguser:pguser /home/pguser/pgdebs \
    && su - pguser -c "cd /home/pguser/pgdebs && dbdeployer unpack --provider=postgresql postgresql-${PG_MAJOR}_*.deb postgresql-client-${PG_MAJOR}_*.deb"

# The Debian PG build's compiled-in sharedir (/usr/share/postgresql/<major>) is
# NOT relocatable; symlink it to the unpacked share tree so initdb finds its
# timezonesets / templates.
RUN mkdir -p /usr/share/postgresql \
    && ln -sf "/home/pguser/opt/postgresql/${PG_VERSION}/share/postgresql/${PG_MAJOR}" \
       "/usr/share/postgresql/${PG_MAJOR}"

# Make the unpacked psql/pg_isready available on PATH for docker-exec health
# checks. ${PG_VERSION} (build ARG, in scope in this stage) is expanded at build
# time, so the baked ENV holds the concrete versioned path.
ENV PATH="/home/pguser/opt/postgresql/${PG_VERSION}/bin:${PATH}"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# dbdeployer auto-derives PG ports for 17.10 as 16710 (primary), 16711/16712 (replicas).
EXPOSE 16710 16711 16712

ENTRYPOINT ["/entrypoint.sh"]
