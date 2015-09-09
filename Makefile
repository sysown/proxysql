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
	cd deps && make

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

packages:
	# Wipe out binaries directory entirely
	rm -rf binaries && mkdir binaries

	# Create CentOS 7 rpm file by creating docker image, running a container and extracting the RPM from the temp container
	docker build -t centos7_proxysql --no-cache=true ./scenarios/centos7-build
	docker run -i --name=centos7_build centos7_proxysql bash &
	sleep 5
	docker cp centos7_build:/root/rpmbuild/RPMS/x86_64/proxysql-0.3-1.x86_64.rpm ./binaries
	docker kill centos7_build
	docker rm centos7_build

	# Create DEB rpm
	docker build -t ubuntu14_proxysql --no-cache=true ./scenarios/ubuntu-14.04-build
	docker run -i --name=ubuntu14_build ubuntu14_proxysql bash &
	sleep 5
	docker cp ubuntu14_build:/opt/proxysql/src/proxysql_0.3_all.deb ./binaries
	docker kill ubuntu14_build
	docker rm ubuntu14_build

.PHONY: cleanall
cleanall:
	cd deps && make cleanall
	cd lib && make clean
	cd src && make clean

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
