# We're using Ubuntu 14:04 because ProxySQL compilation needs one of the latest
# g++ compilers. Also, it's a long term release.
FROM ubuntu:14.04
MAINTAINER Andrei Ismail <iandrei@gmail.com>
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

RUN apt-get install -y wget unzip
#RUN cd /opt; git clone https://github.com/sysown/proxysql-0.2.git proxysql
RUN cd /opt ; wget https://github.com/sysown/proxysql-0.2/archive/1.0.zip ; unzip 1.0.zip ; mv proxysql-0.2-1.0 proxysql
RUN cd /opt/proxysql; make clean && make -j

ADD ./proxysql.ctl /opt/proxysql/proxysql.ctl
RUN cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl
