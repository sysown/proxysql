#include "cpp.h"
#include "proxysql.h"

#include <ctime>
#include <iostream>
#include <thread>

#define QUERY1 "SELECT ?"
#define NUMPREP 100000
#define NUMPRO 10000
//#define NUMPREP	160
//#define NUMPRO	4
#define LOOPS 1
#define USER "root"
#define SCHEMA "test"

#define NTHREADS 4

MySQL_STMT_Manager *GloMyStmt;

typedef struct _thread_data_t {
  std::thread *thread;
  MYSQL *mysql;
  MYSQL_STMT **stmt;
} thread_data_t;

thread_data_t **GloThrData;

struct cpu_timer {
  ~cpu_timer() {
    auto end = std::clock();
    std::cout << double(end - begin) / CLOCKS_PER_SEC << " secs.\n";
  };

  const std::clock_t begin = std::clock();
};

int run_stmt(MYSQL_STMT *stmt, int int_data) {
  MYSQL_BIND bind[1];
  MYSQL_RES *prepare_meta_result;
  bind[0].buffer_type = MYSQL_TYPE_LONG;
  bind[0].buffer = (char *)&int_data;
  bind[0].is_null = 0;
  bind[0].length = 0;
  if (mysql_stmt_bind_param(stmt, bind)) {
    fprintf(stderr, " mysql_stmt_bind_param() failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    exit(EXIT_FAILURE);
  }
  prepare_meta_result =
      mysql_stmt_result_metadata(stmt); // FIXME: no error check
  if (mysql_stmt_execute(stmt)) {
    fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    exit(EXIT_FAILURE);
  }
  //	memset(bind, 0, sizeof(bind));
  if (mysql_stmt_store_result(stmt)) {
    fprintf(stderr, " mysql_stmt_store_result() failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    exit(EXIT_FAILURE);
  }
  mysql_free_result(prepare_meta_result);
  return 0;
}

void *mysql_thread(int tid) {
  std::mt19937 mt_rand(time(0));

  thread_data_t *THD;
  THD = GloThrData[tid];

  MYSQL *mysql;
  MYSQL_STMT **stmt;

  MySQL_STMTs_local *local_stmts = new MySQL_STMTs_local();
  THD->mysql = mysql_init(NULL);
  mysql = THD->mysql;

  char buff[128];
  unsigned int bl = 0;
  if (!mysql_real_connect(mysql, "127.0.0.1", USER, "", SCHEMA, 3306, NULL,
                          0)) {
    fprintf(stderr, "Failed to connect to database: Error: %s\n",
            mysql_error(mysql));
    exit(EXIT_FAILURE);
  }
  int i;
  stmt = (MYSQL_STMT **)malloc(sizeof(MYSQL_STMT *) * NUMPREP);

  {
    cpu_timer t;
    for (i = 0; i < NUMPREP; i++) {
      stmt[i] = mysql_stmt_init(mysql);
      if (!stmt[i]) {
        fprintf(stderr, " mysql_stmt_init(), out of memory\n");
        exit(EXIT_FAILURE);
      }
      sprintf(buff, "SELECT %u + ?", (uint32_t)mt_rand() % NUMPRO);
      bl = strlen(buff);
      uint64_t hash =
          local_stmts->compute_hash(0, (char *)USER, (char *)SCHEMA, buff, bl);
      MySQL_STMT_Global_info *a =
          GloMyStmt->find_prepared_statement_by_hash(hash);
      if (a == NULL) { // no prepared statement was found in global
        if (mysql_stmt_prepare(stmt[i], buff,
                               bl)) { // the prepared statement is created
          fprintf(stderr, " mysql_stmt_prepare(), failed: %s\n",
                  mysql_stmt_error(stmt[i]));
          exit(EXIT_FAILURE);
        }
        uint32_t stmid = GloMyStmt->add_prepared_statement(
            0, (char *)USER, (char *)SCHEMA, buff, bl, stmt[i]);
        if (NUMPRO < 32)
          fprintf(stdout, "SERVER_statement_id=%lu , PROXY_statement_id=%u\n",
                  stmt[i]->stmt_id, stmid);
        local_stmts->insert(stmid, stmt[i]);
      }
    }
    fprintf(stdout, "Prepared statements: %u client, %u proxy/server. ",
            NUMPREP, GloMyStmt->total_prepared_statements());
    fprintf(stdout, "Created in: ");
  }
  {
    unsigned int founds = 0;
    cpu_timer t;
    for (i = 0; i < NUMPREP * LOOPS; i++) {
      sprintf(buff, "SELECT %u + ?", (uint32_t)mt_rand() % NUMPRO);
      bl = strlen(buff);
      // uint64_t hash=local_stmts->compute_hash(0,(char *)USER,(char
      // *)SCHEMA,buff,bl);  MySQL_STMT_Global_info
      // *a=GloMyStmt->find_prepared_statement_by_hash(hash);  if (a) founds++;
    }
    fprintf(stdout, "Computed %u random strings in: ", i);
  }
  {
    unsigned int founds = 0;
    cpu_timer t;
    for (i = 0; i < NUMPREP * LOOPS; i++) {
      sprintf(buff, "SELECT %u + ?", (uint32_t)mt_rand() % NUMPRO);
      bl = strlen(buff);
      uint64_t hash =
          local_stmts->compute_hash(0, (char *)USER, (char *)SCHEMA, buff, bl);
      // MySQL_STMT_Global_info
      // *a=GloMyStmt->find_prepared_statement_by_hash(hash);  if (a) founds++;
    }
    fprintf(stdout, "Computed %u hashes in: ", i);
  }
  {
    unsigned int founds = 0;
    cpu_timer t;
    for (i = 0; i < NUMPREP * LOOPS; i++) {
      sprintf(buff, "SELECT %u + ?", (uint32_t)mt_rand() % NUMPRO);
      bl = strlen(buff);
      uint64_t hash =
          local_stmts->compute_hash(0, (char *)USER, (char *)SCHEMA, buff, bl);
      MySQL_STMT_Global_info *a =
          GloMyStmt->find_prepared_statement_by_hash(hash);
      if (a)
        founds++;
    }
    fprintf(stdout,
            "Found    %u prepared statements searching by hash in: ", founds);
  }
  {
    unsigned int founds = 0;
    cpu_timer t;
    for (i = 0; i < NUMPREP * LOOPS; i++) {
      sprintf(buff, "SELECT %u + ?", (uint32_t)mt_rand() % NUMPRO);
      bl = strlen(buff);
      uint64_t hash =
          local_stmts->compute_hash(0, (char *)USER, (char *)SCHEMA, buff, bl);
      MySQL_STMT_Global_info *a =
          GloMyStmt->find_prepared_statement_by_hash(hash);
      if (a) {
        // we have a prepared statement, we can run it
        MYSQL_STMT *stm = local_stmts->find(a->statement_id);
        if (stm) {
          run_stmt(stm, (uint32_t)mt_rand());
          founds++;
        }
      }
    }
    fprintf(stdout, "Executed %u prepared statements in: ", founds);
  }

  {
    // for comparison, we run also queries in TEXT protocol
    cpu_timer t;
    for (i = 0; i < NUMPREP * LOOPS; i++) {
      sprintf(buff, "SELECT %u + %u", i, (uint32_t)mt_rand() % NUMPRO);
      bl = strlen(buff);
      int rc = mysql_real_query(mysql, buff, bl);
      if (rc) {
        fprintf(stderr, " mysql_real_query(), failed: %s\n",
                mysql_error(mysql));
        exit(EXIT_FAILURE);
      }
      MYSQL_RES *res = mysql_store_result(mysql);
      if (res == NULL) {
        fprintf(stderr, " mysql_store_result(), failed: %s\n",
                mysql_error(mysql));
        exit(EXIT_FAILURE);
      }
      mysql_free_result(res);
    }
    fprintf(stdout, "Executed %u queries in: ", i);
  }
  return 0;
}

int main() {
  mysql_library_init(0, NULL, NULL);
  GloMyStmt = new MySQL_STMT_Manager();
  GloThrData = (thread_data_t **)malloc(sizeof(thread_data_t *) * NTHREADS);

  int i;
  for (i = 0; i < NTHREADS; i++) {
    GloThrData[i] = (thread_data_t *)malloc(sizeof(thread_data_t));
    GloThrData[i]->thread = new std::thread(&mysql_thread, i);
  }
  for (i = 0; i < NTHREADS; i++) {
    GloThrData[i]->thread->join();
  }
  return 0;
}
