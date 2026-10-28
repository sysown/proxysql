# Dependency recipes use autotools, CMake and direct compiler calls. Export
# the TSAN flags in the standard variables so every source build sees them;
# explicit recipe overrides below retain the same compiler/linker flags.
ifeq ($(WITHTSAN),1)
override DEPS_MODE := source
export DEPS_MODE
TSAN_DEP_FLAGS := -fsanitize=thread -fno-omit-frame-pointer -fPIC
override CFLAGS := $(strip $(CFLAGS) $(filter-out $(CFLAGS),$(TSAN_DEP_FLAGS)))
override CXXFLAGS := $(strip $(CXXFLAGS) $(filter-out $(CXXFLAGS),$(TSAN_DEP_FLAGS)))
override LDFLAGS := $(strip $(LDFLAGS) $(filter-out $(LDFLAGS),$(TSAN_DEP_FLAGS)))
export CFLAGS CXXFLAGS LDFLAGS
# MAKEFLAGS otherwise forwards the caller's original command-line flags,
# taking precedence over the corrected environment in recursive custom builds.
TSAN_MAKE_FLAGS := CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" LDFLAGS="$(LDFLAGS)"
TSAN_CMAKE_FLAGS := -DCMAKE_C_FLAGS="$(CFLAGS)" -DCMAKE_CXX_FLAGS="$(CXXFLAGS)" \
	-DCMAKE_EXE_LINKER_FLAGS="$(LDFLAGS)" -DCMAKE_SHARED_LINKER_FLAGS="$(LDFLAGS)"
endif
