# We're using Ubuntu 14:04 because ProxySQL compilation needs one of the latest
# g++ compilers. Also, it's a long term release.
FROM ubuntu:14.04
MAINTAINER Andrei Ismail <iandrei@gmail.com>
RUN apt-get update
RUN apt-get install -y git
RUN apt-get install -y make
RUN apt-get install -y cmake
RUN apt-get install -y gcc
RUN apt-get install -y g++
RUN apt-get install -y libssl-dev
RUN apt-get install -y libmysqlclient-dev
# This will enable us to clone the ProxySQL repo without git prompting us for
# the validity of the RSA fingerprint.
RUN cd /opt; git clone https://github.com/sysown/proxysql-0.2.git
RUN cd /opt/proxysql-0.2; make clean && make
RUN mkdir -p /var/run/proxysql
RUN cp /opt/proxysql-0.2/proxysql.cfg /etc