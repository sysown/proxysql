FROM centos:centos7
MAINTAINER Andrei Ismail <iandrei@gmail.com>

LABEL vendor=proxysql\
      com.proxysql.type=proxysql\
      com.proxysql.os=centos7\
      com.proxysql.interactive=false\
      com.proxysql.config=simple\
      com.proxysql.purpose=packaging

RUN yum install -y automake
RUN yum install -y bzip2
RUN yum install -y cmake
RUN yum install -y make
RUN yum install -y gcc-c++
RUN yum install -y gcc
RUN yum install -y git
RUN yum install -y openssl
RUN yum install -y openssl-devel
RUN yum install -y patch


RUN cd /opt; git clone https://github.com/sysown/proxysql.git proxysql
RUN cd /opt/proxysql; make clean && make -j 5

RUN cd /opt/proxysql ; mkdir -p proxysql/usr/bin; mkdir -p proxysql/etc; cp src/proxysql proxysql/usr/bin/; cp -a etc proxysql ; mv proxysql proxysql-1.0.1 ; tar czvf proxysql-1.0.1.tar.gz proxysql-1.0.1

RUN mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}

ADD ./rpmmacros /root/.rpmmacros
ADD ./proxysql.spec /root/rpmbuild/SPECS/proxysql.spec

RUN cp /opt/proxysql/proxysql-1.0.1.tar.gz /root/rpmbuild/SOURCES

RUN yum install -y rpm-build
RUN cd /root/rpmbuild; rpmbuild -ba SPECS/proxysql.spec
RUN cp /root/rpmbuild/RPMS/x86_64/proxysql-1.0.1-1.x86_64.rpm /root/rpm
