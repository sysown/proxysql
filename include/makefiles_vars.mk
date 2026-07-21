#!/bin/make -f


GIT_VERSION ?= $(shell git describe --long --abbrev=7)
ifndef GIT_VERSION
    $(error GIT_VERSION is not set)
endif

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
SHLIB_EXT  := .dylib
SHARED_FLAGS := -dynamiclib
FORCE_LOAD := -force_load
else
SHLIB_EXT  := .so
SHARED_FLAGS := -shared
FORCE_LOAD := -Wl,--whole-archive
endif

DISTRO := $(shell if [ -f /etc/os-release ]; then grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"'; else echo "unknown"; fi)

CENTOSVER := Unknown
ifneq (,$(wildcard /etc/system-release))
	CENTOSVER := $(shell rpm --eval %rhel)
endif

# NOTE: CENTOSVER is still used in deps/Makefile for CentOS 6 workarounds.
# IS_ARM and IS_CENTOS were removed when jemalloc page-size detection
# switched from arch-specific to auto-detection (see deps/Makefile).


### detect compiler support for c++11/17
CPLUSPLUS := $(shell ${CC} -std=c++17 -dM -E -x c++ /dev/null 2>/dev/null | grep -F __cplusplus | egrep -o '[0-9]{6}L')
ifneq ($(CPLUSPLUS),201703L)
	CPLUSPLUS := $(shell ${CC} -std=c++11 -dM -E -x c++ /dev/null 2>/dev/null| grep -F __cplusplus | egrep -o '[0-9]{6}L')
ifneq ($(CPLUSPLUS),201103L)
    $(error Compiler must support at least c++11)
endif
endif
STDCPP := -std=c++$(shell echo $(CPLUSPLUS) | cut -c3-4) -DCXX$(shell echo $(CPLUSPLUS) | cut -c3-4)


WGCOV :=
ifeq ($(WITHGCOV),1)
	WGCOV := -DWITHGCOV -lgcov --coverage
endif

WASAN :=
ifeq ($(WITHASAN),1)
	WASAN := -fsanitize=address
	# Force the disable of JEMALLOC, since ASAN isn't compatible.
	export NOJEMALLOC=1
	# workaroud ASAN limitation ASLR > 28bits
	# https://github.com/google/sanitizers/issues/1716
	# sudo sysctl vm.mmap_rnd_bits=28
    $(warning ASAN needs ASLR =< 28bits, make sure 'sysctl vm.mmap_rnd_bits=28' is set.)
endif
ifeq ($(TEST_WITHASAN),1)
	WASAN += -DTEST_WITHASAN
endif

# ThreadSanitizer support. Mutually exclusive with WITHASAN — both
# sanitizers reroute the same memory-management hooks and the linker
# rejects the combination outright. Like ASAN, TSAN is incompatible
# with jemalloc, so NOJEMALLOC is forced. The flag is added to both
# CXX_FLAGS and LD_FLAGS via $(WASAN) — TSAN piggybacks on the same
# variable name to keep the propagation paths unchanged across deps/
# lib/ src/ test/ Makefiles. Reuse means a build is *either* ASAN
# *or* TSAN, never both. TSAN inherits ASAN's ASLR width constraint
# (Linux 5.18+ defaults vm.mmap_rnd_bits=32; TSAN expects 28).
ifeq ($(WITHTSAN),1)
ifeq ($(WITHASAN),1)
    $(error WITHASAN=1 and WITHTSAN=1 are mutually exclusive — pick one)
endif
	WASAN := -fsanitize=thread
	export NOJEMALLOC=1
    $(warning TSAN needs ASLR =< 28bits, make sure 'sysctl vm.mmap_rnd_bits=28' is set.)
endif

NOJEM :=
ifeq ($(NOJEMALLOC),1)
	NOJEM := -DNOJEM
endif
