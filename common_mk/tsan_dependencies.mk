# Keep TSAN dependency preparation out of the normal artifact cache. Compiler
# settings belong to each dependency's configure/build system; replacing them
# on recursive make command lines discards required package-specific flags.
ifeq ($(WITHTSAN),1)
override DEPS_MODE := source
export DEPS_MODE
endif
