# ProxySQL Static Auth Plugin Makefile

PROXYSQL_ROOT := ../../..
CXX := g++
CXXFLAGS := -std=c++17 -fPIC -O2 -Wall
INCLUDES := -I$(PROXYSQL_ROOT)/include -I$(PROXYSQL_ROOT)/deps/json

TARGET := auth_static.so
SOURCES := auth_static.cpp

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -shared -o $@ $<

clean:
	rm -f $(TARGET)

install: $(TARGET)
	@echo "Install location: specify with 'make install DESTDIR=/path/to/plugins'"
	@if [ -n "$(DESTDIR)" ]; then \
		mkdir -p $(DESTDIR); \
		cp $(TARGET) $(DESTDIR)/; \
		echo "Installed $(TARGET) to $(DESTDIR)"; \
	fi
