# Keep the in-tree connector's headers and archive selected together.
MARIADB_VENDOR_DIR := mariadb-client-library
MARIADB_V40_VERSION := 3.4.11
MARIADB_V40_SOURCE := mariadb-connector-c-$(MARIADB_V40_VERSION)-src

ifeq ($(PROXYSQL40),1)
MARIADB_SOURCE := $(MARIADB_V40_SOURCE)
else
MARIADB_SOURCE := mariadb_client
endif

MARIADB_PATH := $(DEPS_PATH)/$(MARIADB_VENDOR_DIR)/$(MARIADB_SOURCE)
MARIADB_IDIR := $(MARIADB_PATH)/include
MARIADB_LDIR := $(MARIADB_PATH)/libmariadb
