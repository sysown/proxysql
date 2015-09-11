# We're using Ubuntu 14:04 because ProxySQL compilation needs one of the latest
# g++ compilers. Also, it's a long term release.
FROM centos:centos7
MAINTAINER Andrei Ismail <iandrei@gmail.com>

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


RUN cd /opt; git clone https://github.com/sysown/proxysql-0.2.git proxysql
RUN cd /opt/proxysql; make clean && make -j 5

RUN cd /opt/proxysql ; mkdir -p proxysql-0.2/usr/bin; mkdir -p proxysql-0.2/etc; cp src/proxysql proxysql-0.2/usr/bin/; cp -a etc proxysql-0.2 ; mv proxysql-0.2 proxysql-0.2.0902 ; tar czvf proxysql-0.2.0902.tar.gz proxysql-0.2.0902

RUN mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}

ADD ./rpmmacros /root/.rpmmacros
ADD ./proxysql.spec /root/rpmbuild/SPECS/proxysql.spec

RUN cp /opt/proxysql/proxysql-0.2.0902.tar.gz /root/rpmbuild/SOURCES

RUN yum install -y rpm-build
RUN cd /root/rpmbuild; rpmbuild -ba SPECS/proxysql.spec
RUN cp /root/rpmbuild/RPMS/x86_64/proxysql-0.2.0902-1.x86_64.rpm /root/rpm
