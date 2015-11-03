O0=-O0
O2=-O2
O1=-O1
O3=-O3 -mtune=native
#OPTZ=$(O2)
EXTRALINK=#-pg
ALL_DEBUG=-ggdb -DDEBUG
NO_DEBUG=
DEBUG=${ALL_DEBUG}
#export DEBUG
#export OPTZ
export EXTRALINK

all:
	OPTZ="${O2}" make default

.PHONY: default
default:
	make deps
	make lib
	make src

.PHONY: debug
debug:
	OPTZ="${O0}" DEBUG="${ALL_DEBUG}" make default

.PHONY: deps
deps:
	cd deps && make -j 5

.PHONY: lib
lib:
	cd lib && make -j 5

.PHONY: src
src:
	cd src && make

.PHONY: clean
clean:
	cd lib && make clean
	cd src && make clean

packages: centos7 ubuntu12 ubuntu14
.PHONY: packages

centos7: binaries/proxysql-1.0.1-1.x86_64.rpm
.PHONY: centos

ubuntu12: binaries/proxysql_1.0.1-ubuntu12_amd64.deb
.PHONY: ubuntu12

ubuntu14: binaries/proxysql_1.0.1-ubuntu14_amd64.deb
.PHONY: ubuntu14

binaries/proxysql-1.0.1-1.x86_64.rpm:
	# Create CentOS 7 rpm file by creating docker image, running a container and extracting the RPM from the temp container
	docker build -t centos7_proxysql --no-cache=true ./docker/images/proxysql/centos7-build
	docker run -i --name=centos7_build centos7_proxysql bash &
	sleep 5
	docker cp centos7_build:/root/rpmbuild/RPMS/x86_64/proxysql-1.0.1-1.x86_64.rpm ./binaries
#	docker kill centos7_build
	docker rm centos7_build

binaries/proxysql_1.0.1-ubuntu12_amd64.deb:
	docker build -t ubuntu12_proxysql --no-cache=true ./docker/images/proxysql/ubuntu-12.04-build
	docker run -i --name=ubuntu12_build ubuntu12_proxysql bash &
	sleep 5
	docker cp ubuntu12_build:/opt/proxysql/proxysql_1.0.1_amd64.deb ./binaries/proxysql_1.0.1-ubuntu12_amd64.deb
#	docker kill ubuntu12_build
	docker rm ubuntu12_build

binaries/proxysql_1.0.1-ubuntu14_amd64.deb:
	docker stop ubuntu14_build || true
	docker rm ubuntu14_build || true
	docker create --name ubuntu14_build renecannao/proxysql:build-ubuntu14 bash -c "while : ; do sleep 10 ; done"
	docker start ubuntu14_build
	docker exec ubuntu14_build bash -c "apt-get install -y python"
	docker exec ubuntu14_build bash -c "cd /opt; git clone https://github.com/sysown/proxysql.git proxysql"
	docker exec ubuntu14_build bash -c "cd /opt/proxysql; make clean && make -j"
	docker cp docker/images/proxysql/ubuntu-14.04-build/proxysql.ctl ubuntu14_build:/opt/proxysql/
	docker exec ubuntu14_build bash -c "cd /opt/proxysql; cp src/proxysql . ; equivs-build proxysql.ctl"
	docker cp ubuntu14_build:/opt/proxysql/proxysql_1.0.1_amd64.deb ./binaries/proxysql_1.0.1-ubuntu14_amd64.deb
	docker stop ubuntu14_build
	docker rm ubuntu14_build
#	docker build -t ubuntu14_proxysql --no-cache=true ./docker/images/proxysql/ubuntu-14.04-build
#	docker run -i --name=ubuntu14_build ubuntu14_proxysql bash &
#	sleep 5
#	docker cp ubuntu14_build:/opt/proxysql/proxysql_1.0.1_amd64.deb ./binaries/proxysql_1.0.1-ubuntu14_amd64.deb
#	docker kill ubuntu14_build
#	docker rm ubuntu14_build


.PHONY: cleanall
cleanall:
	cd deps && make cleanall
	cd lib && make clean
	cd src && make clean
	rm binaries/*deb || true
	rm binaries/*rpm || true

install: src/proxysql
	install -m 0755 src/proxysql /usr/local/bin
	install -m 0600 etc/proxysql.cnf /etc
	install -m 0755 etc/init.d/proxysql /etc/init.d
	if [ ! -d /var/run/proxysql ]; then mkdir /var/run/proxysql ; fi
	update-rc.d proxysql defaults
.PHONY: install

uninstall:
	rm /etc/init.d/proxysql
	rm /etc/proxysql.cnf
	rm /usr/local/bin/proxysql
	rmdir /var/run/proxysql 2>/dev/null || true
	update-rc.d proxysql remove
.PHONY: uninstall
