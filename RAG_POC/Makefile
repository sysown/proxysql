CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2

PROXYSQL_PATH := $(abspath ..)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk

INCLUDES := \
	-I$(JSON_IDIR) \
	-I$(MARIADB_IDIR) \
	-I$(CURL_IDIR) \
	-I$(SSL_IDIR)

LIBDIRS := \
	-L$(MARIADB_LDIR)

# Use static libcurl
CURL_STATIC_LIB := $(CURL_LDIR)/libcurl.a

LIBS := -lmariadbclient $(CURL_STATIC_LIB) $(OPENSSL_STATIC_LIBS) \
	-lcrypt -ldl -lpthread -lz

TARGET := rag_ingest
SOURCES := rag_ingest.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(LIBDIRS) $^ -o $@ $(LIBS)

clean:
	rm -f $(TARGET)
