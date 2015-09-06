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
