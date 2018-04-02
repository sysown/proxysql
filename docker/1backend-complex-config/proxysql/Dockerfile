# We're using Ubuntu 14:04 because ProxySQL compilation needs one of the latest
# g++ compilers. Also, it's a long term release.
FROM ubuntu:14.04
MAINTAINER Andrei Ismail <iandrei@gmail.com>
RUN apt-get update && apt-get install -y\
	automake\
	cmake\
	make\
	g++\
	gcc\
	gdb\
	gdbserver\
	git\
	libmysqlclient-dev\
	libssl-dev\
	pkg-config\
	libtool

RUN cd /opt; git clone https://github.com/akopytov/sysbench.git
RUN cd /opt/sysbench; ./autogen.sh; ./configure --bindir=/usr/bin; make; make install

ADD ./proxysql.cnf /etc/
RUN mkdir -p /var/lib/proxysql
ADD ./compile_and_start_proxysql.sh /tmp/
RUN chmod +x /tmp/compile_and_start_proxysql.sh

CMD ["/tmp/compile_and_start_proxysql.sh"]
