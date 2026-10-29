# Keep TSAN dependency preparation out of the normal artifact cache. Compiler
# settings belong to each dependency's configure/build system; replacing them
# on recursive make command lines discards required package-specific flags.
ifeq ($(WITHTSAN),1)
# Validate an explicit selection before TSAN replaces it with source mode.
ifneq ($(origin DEPS_MODE),undefined)
ifneq ($(words $(DEPS_MODE)),1)
$(error DEPS_MODE must be auto, source, or prebuilt)
endif
ifeq ($(filter auto source prebuilt,$(DEPS_MODE)),)
$(error DEPS_MODE must be auto, source, or prebuilt)
endif
endif
override DEPS_MODE := source
export DEPS_MODE
endif
