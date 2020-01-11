DEPS_PATH=../../../deps

MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include
MARIADB_LDIR=$(MARIADB_PATH)/libmariadb

JEMALLOC_PATH=$(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR=$(JEMALLOC_PATH)/include/jemalloc
JEMALLOC_LDIR=$(JEMALLOC_PATH)/lib

PROXYSQL_PATH=../../..
PROXYSQL_IDIR=$(PROXYSQL_PATH)/include

SQLITE3_DIR=$(DEPS_PATH)/sqlite3/sqlite3
JSON_IDIR=$(DEPS_PATH)/json

RE2_PATH=$(DEPS_PATH)/re2/re2
RE2_IDIR=$(RE2_PATH)

SQLITE3_DIR=$(DEPS_PATH)/sqlite3/sqlite3

LIBHTTPSERVER_DIR=$(DEPS_PATH)/libhttpserver/libhttpserver
LIBHTTPSERVER_IDIR=$(LIBHTTPSERVER_DIR)/src
LIBHTTPSERVER_LDIR=$(LIBHTTPSERVER_DIR)/build/src/.libs/

LIBCONFIG_PATH=$(DEPS_PATH)/libconfig/libconfig
LIBCONFIG_IDIR=-I$(LIBCONFIG_PATH)/lib
LIBCONFIG_LDIR=-L$(LIBCONFIG_PATH)/lib/.libs

CURL_DIR=$(DEPS_PATH)/curl/curl
CURL_IDIR=$(CURL_DIR)/include
CURL_LDIR=$(CURL_DIR)/lib/.libs

DAEMONPATH=$(DEPS_PATH)/libdaemon/libdaemon
DAEMONPATH_IDIR=$(DAEMONPATH)
DAEMONPATH_LDIR=$(DAEMONPATH)/libdaemon/.libs

PCRE_PATH=$(DEPS_PATH)/pcre/pcre
PCRE_LDIR=$(PCRE_PATH)/.libs

MICROHTTPD_DIR=$(DEPS_PATH)/libmicrohttpd/libmicrohttpd/src
MICROHTTPD_IDIR=$(MICROHTTPD_DIR)/include
MICROHTTPD_LDIR=$(MICROHTTPD_DIR)/microhttpd/.libs

LIBINJECTION_DIR=$(DEPS_PATH)/libinjection/libinjection
LIBINJECTION_IDIR=$(LIBINJECTION_DIR)/src
LIBINJECTION_LDIR=$(LIBINJECTION_DIR)/src

SSL_DIR=$(DEPS_PATH)/libssl/openssl/
SSL_IDIR=$(SSL_DIR)/include
SSL_LDIR=$(SSL_DIR)

EV_DIR=$(DEPS_PATH)/libev/libev/
EV_IDIR=$(EV_DIR)
EV_LDIR=$(EV_DIR)/.libs

IDIR=../../../include
LDIR=../../../lib
TAP_LIBDIR=../tap

ODIR=../../../obj

EXECUTABLE=proxysql

OBJ=../../../src/obj/proxysql_global.o ../../../src/obj/main.o

INCLUDEDIRS=-I../tap -I$(RE2_PATH) -I$(IDIR) -I$(JEMALLOC_IDIR) -I$(SQLITE3_DIR) -I$(LIBHTTPSERVER_IDIR) -I$(CURL_IDIR) -I$(DAEMONPATH_IDIR) -I$(MARIADB_IDIR) -I$(SSL_IDIR) -I$(JSON_IDIR)
LDIRS=-L$(TAP_LIBDIR) -L$(LDIR) -L$(JEMALLOC_LDIR) $(LIBCONFIG_LDIR) -L$(RE2_PATH)/obj -L$(MARIADB_LDIR) -L$(DAEMONPATH_LDIR) -L$(PCRE_LDIR) -L$(MICROHTTPD_LDIR) -L$(LIBHTTPSERVER_LDIR) -L$(LIBINJECTION_LDIR) -L$(CURL_LDIR) -L$(EV_LDIR) -L$(SSL_LDIR)

MYLIBS=-Wl,--export-dynamic -Wl,-Bstatic -lconfig -lproxysql -ldaemon -ljemalloc -lconfig++ -lre2 -lpcrecpp -lpcre -lmariadbclient -lhttpserver -lmicrohttpd -linjection -lcurl -lssl -lcrypto -lev -Wl,-Bdynamic -lgnutls -lpthread -lm -lz -lrt $(EXTRALINK)
STATIC_LIBS=$(MARIADB_LDIR)/libmariadbclient.a

.PHONY: all
all: tests

.PHONY: clean
clean:
	rm -f basic-t set_character_set-t charset_unsigned_int-t select_config_file-t sqlite3-t galera_1_timeout_count galera_2_timeout_no_count aurora test_set_character_results-t test_ps_large_result-t set_testing-t || true

OPT=-O2

SRC=basic-t.cpp set_character_set-t.cpp charset_unsigned_int-t.cpp select_config_file-t.cpp sqlite3-t.cpp  galera_1_timeout_count.cpp galera_2_timeout_no_count.cpp aurora.cpp test_set_character_results-t.cpp test_ps_large_result-t.cpp set_testing-t.cpp

tests: basic-t set_character_set-t charset_unsigned_int-t select_config_file-t sqlite3-t test_set_character_results-t test_ps_large_result-t set_testing-t
testgalera: galera_1_timeout_count galera_2_timeout_no_count
testaurora: aurora

sqlite3-t: $(TAP_LIBDIR)/libtap.a sqlite3-t.cpp
	g++ sqlite3-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) ../../../lib/libproxysql.a $(MYLIBS) -lpthread -ldl -std=c++11 -ltap -o sqlite3-t

basic-t: $(TAP_LIBDIR)/libtap.a
	g++ basic-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 -ltap -o basic-t

set_character_set-t: set_character_set-t.cpp $(TAP_LIBDIR)/libtap.a
	g++ set_character_set-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 -ltap -ldl $(MYLIBS) -o set_character_set-t

charset_unsigned_int-t: charset_unsigned_int-t.cpp $(TAP_LIBDIR)/libtap.a
	g++ charset_unsigned_int-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 -ltap -ldl $(MYLIBS) -o charset_unsigned_int-t

select_config_file-t: select_config_file-t.cpp $(TAP_LIBDIR)/libtap.a
	g++ select_config_file-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 -ltap -ldl $(MYLIBS) -o select_config_file-t

test_set_character_results-t: test_set_character_results-t.cpp $(TAP_LIBDIR)/libtap.a
	g++ test_set_character_results-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 $(MYLIBS) -ltap -lssl -lcrypto -ldl -lpthread -o test_set_character_results-t

test_ps_large_result-t: test_ps_large_result-t.cpp $(TAP_LIBDIR)/libtap.a
	g++ test_ps_large_result-t.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 $(MYLIBS) -ltap -lssl -lcrypto -ldl -lpthread -o test_ps_large_result-t

galera_1_timeout_count: galera_1_timeout_count.cpp $(TAP_LIBDIR)/libtap.a
	g++ -DTEST_GALERA -DDEBUG galera_1_timeout_count.cpp ../tap/SQLite3_Server.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 $(OBJ) $(MYLIBS) -ltap -ldl -o galera_1_timeout_count -DGITVERSION=\"$(GIT_VERSION)\"

galera_2_timeout_no_count: galera_2_timeout_no_count.cpp $(TAP_LIBDIR)/libtap.a
	g++ -DTEST_GALERA -DDEBUG galera_2_timeout_no_count.cpp ../tap/SQLite3_Server.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 $(OBJ) $(MYLIBS) -ltap -ldl -o galera_2_timeout_no_count -DGITVERSION=\"$(GIT_VERSION)\"

aurora: aurora.cpp $(TAP_LIBDIR)/libtap.a
	g++ -DTEST_AURORA -DDEBUG aurora.cpp ../tap/SQLite3_Server.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 $(OBJ) $(MYLIBS) -ltap -ldl -o aurora -DGITVERSION=\"$(GIT_VERSION)\"

set_testing-t: set_testing-t.cpp $(TAP_LIBDIR)/libtap.a
	g++ set_testing-t.cpp -Wall $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 $(MYLIBS) -ltap -pthread -O0 -ggdb -ldl -lssl -lcrypto -o set_testing-t
