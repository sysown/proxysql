CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -g -O2
CPPFLAGS = -I./include -I./third_party/googletest/googletest/include

# MySQL and PostgreSQL client libraries
MYSQL_CFLAGS = $(shell mysql_config --cflags 2>/dev/null)
MYSQL_LIBS = $(shell mysql_config --libs 2>/dev/null)
PG_CFLAGS = -I$(shell pg_config --includedir 2>/dev/null || echo /usr/include/postgresql)
PG_LIBS = -L$(shell pg_config --libdir 2>/dev/null || echo /usr/lib/x86_64-linux-gnu) -lpq

PROJECT_ROOT = .
SRC_DIR = $(PROJECT_ROOT)/src/sql_parser
ENGINE_SRC_DIR = $(PROJECT_ROOT)/src/sql_engine
INCLUDE_DIR = $(PROJECT_ROOT)/include/sql_parser
TEST_DIR = $(PROJECT_ROOT)/tests

# Library sources
LIB_SRCS = $(SRC_DIR)/arena.cpp $(SRC_DIR)/parser.cpp
LIB_OBJS = $(LIB_SRCS:.cpp=.o)
LIB_TARGET = $(PROJECT_ROOT)/libsqlparser.a

# SQL Engine sources
ENGINE_SRCS = $(ENGINE_SRC_DIR)/function_registry.cpp \
              $(ENGINE_SRC_DIR)/in_memory_catalog.cpp \
              $(ENGINE_SRC_DIR)/datetime_parse.cpp \
              $(ENGINE_SRC_DIR)/tool_config_parser.cpp \
              $(ENGINE_SRC_DIR)/mysql_remote_executor.cpp \
              $(ENGINE_SRC_DIR)/pgsql_remote_executor.cpp \
              $(ENGINE_SRC_DIR)/multi_remote_executor.cpp
ENGINE_OBJS = $(ENGINE_SRCS:.cpp=.o)

# Google Test library
GTEST_DIR = $(PROJECT_ROOT)/third_party/googletest/googletest
GTEST_SRC = $(GTEST_DIR)/src/gtest-all.cc
GTEST_OBJ = $(GTEST_DIR)/src/gtest-all.o
GTEST_CPPFLAGS = -I$(GTEST_DIR)/include -I$(GTEST_DIR)

# Test sources
TEST_SRCS = $(TEST_DIR)/test_main.cpp \
            $(TEST_DIR)/test_arena.cpp \
            $(TEST_DIR)/test_tokenizer.cpp \
            $(TEST_DIR)/test_classifier.cpp \
            $(TEST_DIR)/test_expression.cpp \
            $(TEST_DIR)/test_set.cpp \
            $(TEST_DIR)/test_select.cpp \
            $(TEST_DIR)/test_emitter.cpp \
            $(TEST_DIR)/test_stmt_cache.cpp \
            $(TEST_DIR)/test_insert.cpp \
            $(TEST_DIR)/test_update.cpp \
            $(TEST_DIR)/test_delete.cpp \
            $(TEST_DIR)/test_compound.cpp \
            $(TEST_DIR)/test_digest.cpp \
            $(TEST_DIR)/test_misc_stmts.cpp \
            $(TEST_DIR)/test_value.cpp \
            $(TEST_DIR)/test_null_semantics.cpp \
            $(TEST_DIR)/test_coercion.cpp \
            $(TEST_DIR)/test_arithmetic.cpp \
            $(TEST_DIR)/test_comparison.cpp \
            $(TEST_DIR)/test_string_funcs.cpp \
            $(TEST_DIR)/test_cast.cpp \
            $(TEST_DIR)/test_registry.cpp \
            $(TEST_DIR)/test_like.cpp \
            $(TEST_DIR)/test_expression_eval.cpp \
            $(TEST_DIR)/test_eval_integration.cpp \
            $(TEST_DIR)/test_catalog.cpp \
            $(TEST_DIR)/test_row.cpp \
            $(TEST_DIR)/test_plan_builder.cpp \
            $(TEST_DIR)/test_operators.cpp \
            $(TEST_DIR)/test_plan_executor.cpp \
            $(TEST_DIR)/test_optimizer.cpp \
            $(TEST_DIR)/test_distributed_planner.cpp \
            $(TEST_DIR)/test_dml.cpp \
            $(TEST_DIR)/test_distributed_dml.cpp \
            $(TEST_DIR)/test_mysql_executor.cpp \
            $(TEST_DIR)/test_pgsql_executor.cpp \
            $(TEST_DIR)/test_distributed_real.cpp \
            $(TEST_DIR)/test_subquery.cpp \
            $(TEST_DIR)/test_local_txn.cpp \
            $(TEST_DIR)/test_session.cpp \
            $(TEST_DIR)/test_single_backend_txn.cpp \
            $(TEST_DIR)/test_distributed_txn.cpp \
            $(TEST_DIR)/test_window.cpp \
            $(TEST_DIR)/test_cte.cpp \
            $(TEST_DIR)/test_datetime_format.cpp \
            $(TEST_DIR)/test_datetime_funcs.cpp \
            $(TEST_DIR)/test_result_set.cpp \
            $(TEST_DIR)/test_ssl_config.cpp \
            $(TEST_DIR)/test_star_modifiers.cpp \
            $(TEST_DIR)/test_shard_map.cpp
TEST_OBJS = $(TEST_SRCS:.cpp=.o)
TEST_TARGET = $(PROJECT_ROOT)/run_tests

# Google Benchmark
GBENCH_DIR = $(PROJECT_ROOT)/third_party/benchmark
GBENCH_SRCS = $(filter-out $(GBENCH_DIR)/src/benchmark_main.cc, $(wildcard $(GBENCH_DIR)/src/*.cc))
GBENCH_OBJS = $(GBENCH_SRCS:.cc=.o)
GBENCH_CPPFLAGS = -I$(GBENCH_DIR)/include -I$(GBENCH_DIR)/src -DHAVE_STD_REGEX -DHAVE_STEADY_CLOCK

BENCH_DIR = $(PROJECT_ROOT)/bench
BENCH_SRCS = $(BENCH_DIR)/bench_main.cpp $(BENCH_DIR)/bench_parser.cpp $(BENCH_DIR)/bench_engine.cpp
BENCH_OBJS = $(BENCH_SRCS:.cpp=.o)
BENCH_TARGET = $(PROJECT_ROOT)/run_bench

# Corpus test
CORPUS_TEST_SRC = $(TEST_DIR)/corpus_test.cpp
CORPUS_TEST_TARGET = $(PROJECT_ROOT)/corpus_test

# SQL Engine CLI tool
SQLENGINE_SRC = $(PROJECT_ROOT)/tools/sqlengine.cpp
SQLENGINE_TARGET = sqlengine

# Distributed benchmark tool
BENCH_DISTRIBUTED_SRC = $(PROJECT_ROOT)/tools/bench_distributed.cpp
BENCH_DISTRIBUTED_TARGET = bench_distributed

# Engine stress test (direct API, multi-threaded)
ENGINE_STRESS_SRC = $(PROJECT_ROOT)/tools/engine_stress_test.cpp
ENGINE_STRESS_TARGET = engine_stress_test

# MySQL wire protocol server
MYSQL_SERVER_SRC = $(PROJECT_ROOT)/tools/mysql_server.cpp
MYSQL_SERVER_TARGET = mysql_server

.PHONY: all lib test test-sqlengine test-sqlengine-in-memory test-sqlengine-single test-sqlengine-sharded bench bench-compare bench-distributed build-corpus-test build-sqlengine engine-stress mysql-server clean

build-corpus-test: $(CORPUS_TEST_TARGET)

build-sqlengine: $(SQLENGINE_TARGET)

all: lib test

lib: $(LIB_TARGET)

$(LIB_TARGET): $(LIB_OBJS)
	ar rcs $@ $^
	@echo "Built $@"

$(SRC_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

# SQL Engine objects
$(ENGINE_SRC_DIR)/%.o: $(ENGINE_SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(MYSQL_CFLAGS) $(PG_CFLAGS) -c $< -o $@

# Google Test object
$(GTEST_OBJ): $(GTEST_SRC)
	$(CXX) $(CXXFLAGS) $(GTEST_CPPFLAGS) -c $< -o $@

# Test objects
$(TEST_DIR)/%.o: $(TEST_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(GTEST_CPPFLAGS) $(MYSQL_CFLAGS) $(PG_CFLAGS) -c $< -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Functional tests of the ./sqlengine binary itself.
# Loud failure (exit 2) if prerequisites are missing — never silent skip.
# Caller starts the required containers before invoking these targets:
#   scripts/setup_single_backend.sh   (for test-sqlengine-single / test-sqlengine)
#   scripts/start_sharding_demo.sh    (for test-sqlengine-sharded / test-sqlengine)
test-sqlengine: $(SQLENGINE_TARGET)
	./scripts/test_sqlengine.sh all

test-sqlengine-in-memory: $(SQLENGINE_TARGET)
	./scripts/test_sqlengine.sh in-memory

test-sqlengine-single: $(SQLENGINE_TARGET)
	./scripts/test_sqlengine.sh single

test-sqlengine-sharded: $(SQLENGINE_TARGET)
	./scripts/test_sqlengine.sh sharded

$(TEST_TARGET): $(TEST_OBJS) $(GTEST_OBJ) $(LIB_TARGET) $(ENGINE_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_OBJS) $(GTEST_OBJ) $(ENGINE_OBJS) -L$(PROJECT_ROOT) -lsqlparser -lpthread $(MYSQL_LIBS) $(PG_LIBS)

# Benchmark objects
$(GBENCH_DIR)/src/%.o: $(GBENCH_DIR)/src/%.cc
	$(CXX) $(CXXFLAGS) $(GBENCH_CPPFLAGS) -c $< -o $@

$(BENCH_DIR)/%.o: $(BENCH_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(GBENCH_CPPFLAGS) $(MYSQL_CFLAGS) $(PG_CFLAGS) -c $< -o $@

bench: $(BENCH_TARGET)
	./$(BENCH_TARGET) --benchmark_format=console

$(BENCH_TARGET): $(BENCH_OBJS) $(GBENCH_OBJS) $(LIB_TARGET) $(ENGINE_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(BENCH_OBJS) $(GBENCH_OBJS) $(ENGINE_OBJS) -L$(PROJECT_ROOT) -lsqlparser -lpthread $(MYSQL_LIBS) $(PG_LIBS)

# SQL Engine CLI tool
$(SQLENGINE_TARGET): $(SQLENGINE_SRC) $(LIB_TARGET) $(ENGINE_OBJS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(MYSQL_CFLAGS) $(PG_CFLAGS) -o $@ $< $(ENGINE_OBJS) -L$(PROJECT_ROOT) -lsqlparser -lpthread $(MYSQL_LIBS) $(PG_LIBS)

# Distributed benchmark
bench-distributed: $(BENCH_DISTRIBUTED_TARGET)

$(BENCH_DISTRIBUTED_TARGET): $(BENCH_DISTRIBUTED_SRC) $(LIB_TARGET) $(ENGINE_OBJS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(MYSQL_CFLAGS) $(PG_CFLAGS) -o $@ $< $(ENGINE_OBJS) -L$(PROJECT_ROOT) -lsqlparser -lpthread $(MYSQL_LIBS) $(PG_LIBS)

# Engine stress test
engine-stress: $(ENGINE_STRESS_TARGET)

$(ENGINE_STRESS_TARGET): $(ENGINE_STRESS_SRC) $(LIB_TARGET) $(ENGINE_OBJS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(MYSQL_CFLAGS) $(PG_CFLAGS) -o $@ $< $(ENGINE_OBJS) -L$(PROJECT_ROOT) -lsqlparser -lpthread $(MYSQL_LIBS) $(PG_LIBS)

# MySQL wire protocol server
mysql-server: $(MYSQL_SERVER_TARGET)

$(MYSQL_SERVER_TARGET): $(MYSQL_SERVER_SRC) $(LIB_TARGET) $(ENGINE_OBJS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(MYSQL_CFLAGS) $(PG_CFLAGS) -o $@ $< $(ENGINE_OBJS) -L$(PROJECT_ROOT) -lsqlparser -lpthread $(MYSQL_LIBS) $(PG_LIBS)

$(CORPUS_TEST_TARGET): $(CORPUS_TEST_SRC) $(LIB_TARGET)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $< -L$(PROJECT_ROOT) -lsqlparser

# libpg_query comparison benchmark
LIBPGQUERY_DIR = $(PROJECT_ROOT)/third_party/libpg_query
LIBPGQUERY_LIB = $(LIBPGQUERY_DIR)/libpg_query.a
LIBPGQUERY_CPPFLAGS = -I$(LIBPGQUERY_DIR) -I$(LIBPGQUERY_DIR)/src -I$(LIBPGQUERY_DIR)/src/postgres/include

BENCH_COMPARE_SRC = $(BENCH_DIR)/bench_comparison.cpp
BENCH_COMPARE_OBJ = $(BENCH_COMPARE_SRC:.cpp=.o)
BENCH_COMPARE_TARGET = $(PROJECT_ROOT)/run_bench_compare

$(BENCH_DIR)/bench_comparison.o: $(BENCH_COMPARE_SRC)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(GBENCH_CPPFLAGS) $(LIBPGQUERY_CPPFLAGS) -c $< -o $@

bench-compare: $(BENCH_COMPARE_TARGET)
	./$(BENCH_COMPARE_TARGET) --benchmark_format=console

$(BENCH_COMPARE_TARGET): $(BENCH_DIR)/bench_main.o $(BENCH_COMPARE_OBJ) $(GBENCH_OBJS) $(LIB_TARGET) $(LIBPGQUERY_LIB)
	$(CXX) $(CXXFLAGS) -o $@ $(BENCH_DIR)/bench_main.o $(BENCH_COMPARE_OBJ) $(GBENCH_OBJS) -L$(PROJECT_ROOT) -lsqlparser $(LIBPGQUERY_LIB) -lpthread

clean:
	rm -f $(LIB_OBJS) $(LIB_TARGET) $(TEST_OBJS) $(GTEST_OBJ) $(TEST_TARGET)
	rm -f $(ENGINE_OBJS)
	rm -f $(BENCH_OBJS) $(GBENCH_OBJS) $(BENCH_TARGET) $(CORPUS_TEST_TARGET)
	rm -f $(BENCH_COMPARE_OBJ) $(BENCH_COMPARE_TARGET)
	rm -f $(SQLENGINE_TARGET)
	rm -f $(BENCH_DISTRIBUTED_TARGET)
	rm -f $(ENGINE_STRESS_TARGET)
	rm -f $(MYSQL_SERVER_TARGET)
	@echo "Cleaned."
