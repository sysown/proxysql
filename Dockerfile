FROM debian:bullseye AS builder
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 python3-pip && \
    apt-get install -y --no-install-recommends zlib1g-dev && \
    apt-get install -y --no-install-recommends uuid-dev && \
    apt-get install -y wget default-mysql-client inotify-tools automake bzip2 \
    cmake make g++ gcc git openssl libssl-dev libgnutls28-dev libtool patch python gawk
COPY . /var/proxysql
WORKDIR /var/proxysql
RUN make
RUN make install
FROM debian:bullseye
COPY --from=builder /usr/bin/proxysql /usr/bin/proxysql
RUN apt-get update && \
    apt-get install -y default-mysql-client inotify-tools bzip2 openssl \
    libssl-dev libgnutls30
RUN rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
#CMD ["/bin/bash"]

