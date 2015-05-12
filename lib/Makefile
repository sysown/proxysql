



DEPS_PATH=../deps


MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include

#LIBEVENT_PATH=$(DEPS_PATH)/libevent/libevent
#LIBEVENT_IDIR=-I$(LIBEVENT_PATH)/include


JEMALLOC_PATH=$(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR=$(JEMALLOC_PATH)/include/jemalloc

#GLIB_PATH=$(DEPS_PATH)/glib/glib
#GLIB_IDIRS=-I$(GLIB_PATH) -I$(GLIB_PATH)/glib


LIBCONFIG_PATH=$(DEPS_PATH)/libconfig/libconfig-1.4.9
LIBCONFIG_IDIR=-I$(LIBCONFIG_PATH)/lib


INJECTION_PATH=$(DEPS_PATH)/libinjection
INJECTION_IDIR=$(INJECTION_PATH)


RE2_PATH=$(DEPS_PATH)/re2/re2
RE2_IDIR=$(RE2_PATH)

IDIR=../include

#IDIRS=-I$(IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) $(LIBEVENT_IDIR) $(GLIB_IDIRS) $(LIBCONFIG_IDIR)
IDIRS=-I$(IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) $(LIBCONFIG_IDIR) -I$(RE2_IDIR)

LDIRS=-L$(JEMALLOC_PATH)/lib -L$(RE2_PATH)/obj -L$(INJECTION_PATH)

LIBS=-rdynamic -Wl,-Bstatic -ljemalloc_pic -lre2 -Wl,-Bdynamic -ldl -lpthread -lm -lz -lrt $(EXTRALINK)


ODIR= obj

CC=gcc
CPP=g++
#CC=clang

CFLAGS=$(IDIRS) $(OPTZ) $(DEBUG) -Wall #-lcrypto
CPPFLAGS=-std=c++0x $(CFLAGS) $(LDIRS) $(LIBS)

#default: libproxysql.a
default: libproxysql.a DYN_LIB libproxysql.so
.PHONY: default

#_OBJ = mysql_protocol.o debug.o global_variables.o mysql_data_stream.o network.o proxysql_global.o
_OBJ = sqlite3.o c_tokenizer.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))
#_OBJ_CPP = Standard_Query_Cache.oo SpookyV2.oo Standard_MySQL_Thread.oo gen_utils.oo mysql_connection_pool.oo simple_kv.oo advanced_kv.oo sqlite3db.oo mysql_connection.oo global_variables.oo proxysql_mem.oo mysql_protocol.oo mysql_data_stream.oo mysql_session.oo mysql_backend.oo
#_OBJ_CPP = ProxySQL_GloVars.oo network.oo debug.oo proxysql_global.oo configfile.oo Standard_Query_Cache.oo SpookyV2.oo Standard_MySQL_Thread.oo Standard_MySQL_Authentication.oo gen_utils.oo mysql_connection_pool.oo simple_kv.oo advanced_kv.oo sqlite3db.oo mysql_connection.oo global_variables.oo proxysql_mem.oo MySQL_Protocol.oo mysql_data_stream.oo mysql_session.oo mysql_backend.oo
#_OBJ_CPP = ProxySQL_GloVars.oo network.oo debug.oo proxysql_global.oo configfile.oo Standard_Query_Cache.oo SpookyV2.oo Standard_MySQL_Authentication.oo gen_utils.oo mysql_connection_pool.oo simple_kv.oo advanced_kv.oo sqlite3db.oo mysql_connection.oo global_variables.oo proxysql_mem.oo MySQL_Protocol.oo mysql_data_stream.oo mysql_session.oo mysql_backend.oo
#_OBJ_CPP = ProxySQL_GloVars.oo network.oo debug.oo configfile.oo Standard_Query_Cache.oo SpookyV2.oo Standard_MySQL_Authentication.oo gen_utils.oo mysql_connection_pool.oo simple_kv.oo advanced_kv.oo sqlite3db.oo mysql_connection.oo global_variables.oo proxysql_mem.oo MySQL_Protocol.oo mysql_data_stream.oo MySQL_Session.oo mysql_backend.oo MySQL_HostGroups_Manager.oo
_OBJ_CPP = ProxySQL_GloVars.oo network.oo debug.oo configfile.oo Standard_Query_Cache.oo SpookyV2.oo MySQL_Authentication.oo gen_utils.oo simple_kv.oo sqlite3db.oo global_variables.oo proxysql_mem.oo mysql_connection.oo MySQL_HostGroups_Manager.oo mysql_data_stream.oo MySQL_Thread.oo MySQL_Session.oo MySQL_Protocol.oo mysql_backend.oo
OBJ_CPP = $(patsubst %,$(ODIR)/%,$(_OBJ_CPP))

#_SHARED_OBJ= Standard_Query_Cache.ko Standard_MySQL_Thread.ko

#Standard_MySQL_Thread.so: Standard_MySQL_Thread.cpp MySQL_Protocol.cpp mysql_data_stream.cpp MySQL_Session.cpp mysql_backend.cpp mysql_connection.cpp MySQL_HostGroups_Manager.cpp libproxysql.a
#	$(CPP) -shared -fPIC -o $@ $(CPPFLAGS) Standard_MySQL_Thread.cpp MySQL_Protocol.cpp mysql_data_stream.cpp MySQL_Session.cpp mysql_backend.cpp mysql_connection.cpp MySQL_HostGroups_Manager.cpp libproxysql.a -lcrypto $(LIBS)

Standard_ProxySQL_Admin.so: Standard_ProxySQL_Admin.cpp libproxysql.a
#	$(CPP) -shared -fPIC -o $@ $(CPPFLAGS) MySQL_Thread.cpp Standard_ProxySQL_Admin.cpp MySQL_Protocol.cpp mysql_data_stream.cpp MySQL_Session.cpp mysql_backend.cpp mysql_connection.cpp MySQL_HostGroups_Manager.cpp libproxysql.a -lcrypto $(LIBS)
	$(CPP) -shared -fPIC -o $@ $(CPPFLAGS) Standard_ProxySQL_Admin.cpp libproxysql.a -lcrypto $(LIBS)

#Standard_ProxySQL_Admin.so: Standard_ProxySQL_Admin.ko Standard_MySQL_Thread.ko libproxysql.a
#	$(CPP) -shared -fPIC -o $@ $(CPPFLAGS) Standard_ProxySQL_Admin.ko Standard_MySQL_Thread.ko libproxysql.a -lcrypto $(LIBS)

Standard_Query_Processor.so: Standard_Query_Processor.ko libproxysql.a
	$(CPP) -shared -fPIC -o $@ $(CPPFLAGS) Standard_Query_Processor.ko libproxysql.a -lcrypto $(LIBS) -linjection

#Standard_MySQL_Authentication.so: Standard_MySQL_Authentication.ko libproxysql.a
#	$(CPP) -shared -fPIC -o $@ $(CPPFLAGS) Standard_MySQL_Authentication.ko libproxysql.a -lcrypto $(LIBS)

Standard_Query_Cache.so: Standard_Query_Cache.ko libproxysql.a
	$(CPP) -shared -fPIC -o $@ $(CPPFLAGS) Standard_Query_Cache.ko libproxysql.a -lcrypto $(LIBS)
#	$(CC) -shared -fPIC -o $@ $(CPPFLAGS) $(ODIR)/Standard_Query_Cache.oo $(ODIR)/SpookyV2.oo $(ODIR)/gen_utils.oo

#Standard_MySQL_Thread.so: Standard_MySQL_Thread.ko libproxysql.a
#	$(CPP) -shared -fPIC -o $@ $(CPPFLAGS) Standard_MySQL_Thread.ko libproxysql.a -lcrypto $(LIBS)
#	$(CC) -shared -fPIC -o $@ $(CPPFLAGS) $(ODIR)/Standard_MySQL_Thread.oo $(ODIR)/mysql_session.oo

LOADABLE_LIB = Standard_ProxySQL_Admin.so Standard_Query_Processor.so Standard_Query_Cache.so

DYN_LIB: $(LOADABLE_LIB)
.PHONY: DYN_LIB

%.ko: %.cpp
	$(CPP) -fPIC -c -o $@ $< $(CPPFLAGS)

$(ODIR)/%.o: %.c
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

$(ODIR)/%.oo: %.cpp
	$(CPP) -fPIC -c -o $@ $< $(CPPFLAGS)

#mysql_data_stream.oo: mysql_data_stream.cpp
#	g++ -c -o mysql_data_stream.oo mysql_data_stream.cpp $(CFLAGS) -Wall
	

libproxysql.a: $(ODIR) $(OBJ) $(OBJ_CPP)
	ar rcs $@ $(OBJ) $(OBJ_CPP)

libproxysql.so: $(ODIR) $(OBJ) $(OBJ_CPP)
	$(CPP) -shared -fPIC -o $@ $(OBJ) $(OBJ_CPP)

$(ODIR):
	mkdir $(ODIR)

#all: $(EXECUTABLE)



clean:
	rm -f *.pid $(ODIR)/*.oo $(ODIR)/*.o *.ko *.so *~ core libproxysql.a

