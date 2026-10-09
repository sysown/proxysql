# Standalone live-transport regression; no ProxySQL daemon or database needed.
# Run: PROXYSQL40=1 make -f http_raw_request.mk test-http-raw-request
PROXYSQL_PATH := $(abspath ../../../..)
include $(PROXYSQL_PATH)/include/makefiles_paths.mk
CXX ?= g++
PYTHON ?= python3

.PHONY: test-http-raw-request
test-http-raw-request: http_raw_request_driver
	$(PYTHON) test_http_raw_request.py -v

http_raw_request_driver: http_raw_request_driver.cpp $(LIBHTTPSERVER_LDIR)/libhttpserver.a $(MICROHTTPD_LDIR)/libmicrohttpd.a
	$(CXX) -std=c++17 -Wall -Wextra -Werror -pthread -I$(LIBHTTPSERVER_IDIR) -I$(MICROHTTPD_IDIR) -I$(RE2_IDIR) -I$(JSON_IDIR) $< $(LIBHTTPSERVER_LDIR)/libhttpserver.a $(MICROHTTPD_LDIR)/libmicrohttpd.a $(RE2_STATIC_LIBS) -lgnutls -o $@
