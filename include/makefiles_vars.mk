#!/bin/make -f


GIT_VERSION ?= $(shell git describe --long --abbrev=7)
ifndef GIT_VERSION
    $(error GIT_VERSION is not set)
endif

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

DISTRO := $(shell grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')

CENTOSVER := Unknown
ifneq (,$(wildcard /etc/system-release))
	CENTOSVER := $(shell rpm --eval %rhel)
endif

IS_ARM := $(if $(findstring aarch64, $(UNAME_M)),true,false)
IS_CENTOS := $(if $(findstring Unknown, $(CENTOSVER)),false,true)


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

NOJEM :=
ifeq ($(NOJEMALLOC),1)
	NOJEM := -DNOJEM
endif
