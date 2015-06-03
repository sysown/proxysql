# We're using Ubuntu 14:04 because ProxySQL compilation needs one of the latest
# g++ compilers. Also, it's a long term release.
FROM ubuntu:14.04
MAINTAINER Andrei Ismail <iandrei@gmail.com>
RUN apt-get update && apt-get install -y\
	cmake\
	make\
	g++\
	gcc\
	git\
	libssl-dev\
	libmysqlclient-dev

RUN cd /opt; git clone https://github.com/sysown/proxysql-0.2.git proxysql
RUN cd /opt/proxysql; make clean && make
RUN mkdir -p /var/run/proxysql
ADD ./proxysql.cnf /etc/

WORKDIR /opt/proxysql/src
CMD ["/opt/proxysql/src/proxysql", "--initial"]