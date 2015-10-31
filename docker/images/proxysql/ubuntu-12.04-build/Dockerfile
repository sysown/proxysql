FROM ubuntu:12.04
MAINTAINER Andrei Ismail <iandrei@gmail.com>

LABEL vendor=proxysql\
      com.proxysql.type=proxysql\
      com.proxysql.os=ubuntu12\
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
    libtool\
    wget

RUN cd /root ; wget http://www.cmake.org/files/v3.3/cmake-3.3.1.tar.gz ; tar -zxf cmake-3.3.1.tar.gz ; cd cmake-3.3.1 ; mkdir _build ; cd _build ; cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr ; make -j 5 ; make install ; ldconfig

RUN cd /opt; git clone https://github.com/sysown/proxysql-0.2.git proxysql
RUN cd /opt/proxysql; make clean && make -j

ADD ./proxysql.ctl /opt/proxysql/proxysql.ctl
RUN cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl
