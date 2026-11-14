# Standalone tests for the core-independent tcp_proxy engine.
#
# Usage:
#   make -C plugins/tcp_proxy/tests            # build
#   make -C plugins/tcp_proxy/tests run        # build and run
#   make -C plugins/tcp_proxy/tests asan       # ASan/UBSan build and run
#   make -C plugins/tcp_proxy/tests clean
#
# This Makefile deliberately depends only on the C++17 standard library and
# POSIX/Linux sockets.  It never links against the ProxySQL core tree.

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpedantic -Werror -O2 -g -pthread
CPPFLAGS += -I../include
LDFLAGS  ?=
LDLIBS   ?=
# Explicit engine-only source list.  Admin/plugin.cpp, admin.cpp and
# metrics.cpp will be added by the integration worker; a wildcard would pull
# those into the standalone engine test and break the core-independent build.
SRCS     := ../src/config.cpp ../src/engine.cpp
HDRS     := $(wildcard ../include/*.h) $(wildcard ../src/*.h)

.PHONY: all run asan clean

all: engine_unit

engine_unit: $(SRCS) engine_unit.cpp $(HDRS) Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SRCS) engine_unit.cpp $(LDFLAGS) $(LDLIBS) -o $@

run: engine_unit
	./engine_unit

asan: engine_unit-asan
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./engine_unit-asan

engine_unit-asan: $(SRCS) engine_unit.cpp $(HDRS) Makefile
	$(CXX) $(CPPFLAGS) -std=c++17 -Wall -Wextra -Wpedantic -Werror -O1 -g -pthread \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		$(SRCS) engine_unit.cpp $(LDFLAGS) $(LDLIBS) -o $@

clean:
	rm -f engine_unit engine_unit-asan
