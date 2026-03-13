# ProxySQL K8s Auth Plugin Makefile

PROXYSQL_ROOT := ../../..
CXX := g++
CXXFLAGS := -std=c++17 -fPIC -O2 -Wall
INCLUDES := -I$(PROXYSQL_ROOT)/include -I$(PROXYSQL_ROOT)/deps/json -I$(PROXYSQL_ROOT)/deps/curl/curl/include
CURL_LIB := $(PROXYSQL_ROOT)/deps/curl/curl/lib/.libs/libcurl.a
# curl dependencies (for static linking)
LDFLAGS := -lssl -lcrypto -lz -lpthread

TARGET := auth_k8s.so
SOURCES := auth_k8s.cpp

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -shared -o $@ $< $(CURL_LIB) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	@echo "Install location: specify with 'make install DESTDIR=/path/to/plugins'"
	@if [ -n "$(DESTDIR)" ]; then \
		mkdir -p $(DESTDIR); \
		cp $(TARGET) $(DESTDIR)/; \
		echo "Installed $(TARGET) to $(DESTDIR)"; \
	fi
