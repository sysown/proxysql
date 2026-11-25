# Development container for ProxySQL
# Based on: https://github.com/ProxySQL/docker-images/blob/main/build-images/build-ubuntu24/Dockerfile

FROM ubuntu:24.04
LABEL authors="Miro Stauder <miro@sysown.com>"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && \
	apt full-upgrade -y

# gcc & build tools
RUN apt install -y \
	make cmake automake bison flex \
	git wget \
	gcc g++ \
	libtool \
	gdb gdbserver \
	equivs \
	python3 \
	zstd \
	pkg-config \
	sudo

# proxysql build dependencies
RUN apt install -y \
	libssl-dev gnutls-dev libgnutls28-dev \
	libmysqlclient-dev \
	libunwind8 libunwind-dev \
	uuid-dev \
	libncurses-dev \
	libicu-dev \
	libevent-dev \
	libtirpc-dev

# debug images need valgrind
RUN apt install -y \
	valgrind

# mysql client for testing
RUN apt install -y \
	mariadb-client

# clean apt cache
RUN apt clean && \
	rm -rf /var/cache/apt/* && \
	rm -rf /var/lib/apt/lists/*

# fetch needed include
RUN wget -q -O /usr/include/mysql/hash.h https://raw.githubusercontent.com/mysql/mysql-server/5.7/include/hash.h

# configure git safe dir
RUN git config --global --add safe.directory '*'

ENV CC=gcc
ENV CXX=g++

RUN ${CXX} --version
