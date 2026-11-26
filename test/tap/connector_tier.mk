# Standalone TAP builds can use an existing core without explicit tier flags.
# Select the connector for that core before makefiles_paths.mk sets its paths.
LIBPROXYSQLAR ?= $(PROXYSQL_PATH)/lib/libproxysql.a
ifeq ($(origin PROXYSQL40),undefined)
ifneq ($(shell nm $(LIBPROXYSQLAR) 2>/dev/null | grep -c invoke_register_schemas_phase),0)
PROXYSQL40 := 1
export PROXYSQL40
endif
endif
