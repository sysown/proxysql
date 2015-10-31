FROM ubuntu:14.04
MAINTAINER Andrei Ismail <iandrei@gmail.com>

LABEL vendor=proxysql\
      com.proxysql.type=proxysql\
      com.proxysql.os=ubuntu14\
      com.proxysql.interactive=false\
      com.proxysql.config=simple\
      com.proxysql.purpose=packaging

RUN apt-get update && apt-get install -y\
    automake\
    cmake\
    equivs\
    make\
    g++\
    gcc\
    gdb\
    gdbserver\
    git\
    libmysqlclient-dev\
    libssl-dev\
    libtool

RUN cd /opt; git clone https://github.com/sysown/proxysql.git proxysql
RUN cd /opt/proxysql; make clean && make -j

ADD ./proxysql.ctl /opt/proxysql/proxysql.ctl
RUN cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl
