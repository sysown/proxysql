/*
this is a modified version of client5.cpp
that supports async calls
*/

#include "cpp.h"
#include "proxysql.h"

#include <ctime>
#include <thread>

#define QUERY1 "SELECT ?"
#define NUMPREP 100000
#define NUMPRO 20000
//#define NUMPREP	160
//#define NUMPRO	4
#define LOOPS 1
#define USER "root"
#define SCHEMA "test"

#define NTHREADS 4

static int wait_for_mysql(MYSQL *mysql, int status) {
  struct pollfd pfd;
  int timeout, res;

  pfd.fd = mysql_get_socket(mysql);
  pfd.events = (status & MYSQL_WAIT_READ ? POLLIN : 0) |
               (status & MYSQL_WAIT_WRITE ? POLLOUT : 0) |
               (status & MYSQL_WAIT_EXCEPT ? POLLPRI : 0);
  //	if (status & MYSQL_WAIT_TIMEOUT)
  //		timeout = 1000*mysql_get_timeout_value(mysql);
  //	else
  timeout = -1;
  res = poll(&pfd, 1, timeout);
  if (res == 0)
    return MYSQL_WAIT_TIMEOUT;
  else if (res < 0)
    return MYSQL_WAIT_TIMEOUT;
  else {
    int status = 0;
    if (pfd.revents & POLLIN)
      status |= MYSQL_WAIT_READ;
    if (pfd.revents & POLLOUT)
      status |= MYSQL_WAIT_WRITE;
    if (pfd.revents & POLLPRI)
      status |= MYSQL_WAIT_EXCEPT;
    return status;
  }
}

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

int run_stmt(MYSQL *mysql, MYSQL_STMT *stmt, int int_data) {
  int async_exit_status = 0;
  int ret_int;
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
                                        /* blocking
                                                if (mysql_stmt_execute(stmt)) {
                                                        fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
                                                        fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
                                                        exit(EXIT_FAILURE);
                                                }
                                                if (mysql_stmt_store_result(stmt)) {
                                                        fprintf(stderr, " mysql_stmt_store_result() failed\n");
                                                        fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
                                                        exit(EXIT_FAILURE);
                                                }
                                        */
  async_exit_status = mysql_stmt_execute_start(&ret_int, stmt);
  while (async_exit_status) {
    async_exit_status = wait_for_mysql(mysql, async_exit_status);
    async_exit_status =
        mysql_stmt_execute_cont(&ret_int, stmt, async_exit_status);
  }
  if (ret_int) {
    fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    exit(EXIT_FAILURE);
  }
  async_exit_status = mysql_stmt_store_result_start(&ret_int, stmt);
  while (async_exit_status) {
    async_exit_status = wait_for_mysql(mysql, async_exit_status);
    async_exit_status =
        mysql_stmt_store_result_cont(&ret_int, stmt, async_exit_status);
  }
  if (ret_int) {
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

  // in this version, each mysql thread has just ONE connection
  // for now we use blocking API
  MYSQL *mysql;

  // MYSQL_STMT **stmt;

  // we intialize the local mapping : MySQL_STMTs_local()
  MySQL_STMTs_local *local_stmts = new MySQL_STMTs_local();

  // we initialize a MYSQL structure
  THD->mysql = mysql_init(NULL);
  mysql = THD->mysql;

  char buff[128];
  unsigned int bl = 0;

  // we establish a connection to the database
  if (!mysql_real_connect(mysql, "127.0.0.1", USER, "", SCHEMA, 3306, NULL,
                          0)) {
    fprintf(stderr, "Failed to connect to database: Error: %s\n",
            mysql_error(mysql));
    exit(EXIT_FAILURE);
  }
  int i;
  // set not blocking
  mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
  int async_exit_status = 0;
  int ret_int;
  // array of (MYSQL_STMT *) ; we don't use it in this version
  // stmt=(MYSQL_STMT **)malloc(sizeof(MYSQL_STMT*)*NUMPREP);

  MYSQL_STMT *stmt;
  {
    cpu_timer t;
    // in this loop we create only some the prepared statements
    for (i = 0; i < NUMPREP / 100; i++) {
      sprintf(buff, "SELECT %u + ?", (uint32_t)mt_rand() % NUMPRO);
      bl = strlen(buff);
      uint64_t hash =
          local_stmts->compute_hash(0, (char *)USER, (char *)SCHEMA, buff, bl);
      MySQL_STMT_Global_info *a =
          GloMyStmt->find_prepared_statement_by_hash(hash);
      if (a == NULL) { // no prepared statement was found in global
        stmt = mysql_stmt_init(mysql);
        if (!stmt) {
          fprintf(stderr, " mysql_stmt_init(), out of memory\n");
          exit(EXIT_FAILURE);
        }
        /* blocking call
                                if (mysql_stmt_prepare(stmt, buff, bl)) { // the
           prepared statement is created fprintf(stderr, " mysql_stmt_prepare(),
           failed: %s\n" , mysql_stmt_error(stmt)); exit(EXIT_FAILURE);
                                }
        */
        async_exit_status = mysql_stmt_prepare_start(&ret_int, stmt, buff, bl);
        while (async_exit_status) {
          async_exit_status = wait_for_mysql(mysql, async_exit_status);
          async_exit_status =
              mysql_stmt_prepare_cont(&ret_int, stmt, async_exit_status);
        }
        if (ret_int) {
          fprintf(stderr, " mysql_stmt_prepare(), failed: %s\n",
                  mysql_stmt_error(stmt));
          exit(EXIT_FAILURE);
        }

        MySQL_STMT_Global_info *stmt_info = NULL;
        stmt_info = GloMyStmt->add_prepared_statement(
            0, (char *)USER, (char *)SCHEMA, buff, bl, stmt);
        uint32_t stmid = stmt_info->statement_id;
        if (NUMPRO < 32)
          fprintf(stdout, "SERVER_statement_id=%lu , PROXY_statement_id=%u\n",
                  stmt->stmt_id, stmid);
        local_stmts->insert(stmid, stmt);
      }
    }
    fprintf(stdout, "Prepared statements: %u client, %u proxy/server. ", i,
            GloMyStmt->total_prepared_statements());
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
    unsigned int created = 0;
    unsigned int executed = 0;
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
        if (stm) { // the statement exists in local
          run_stmt(mysql, stm, (uint32_t)mt_rand());
          founds++;
          executed++;
          local_stmts->erase(a->statement_id);
        } else { // the statement doesn't exist locally
          stmt = mysql_stmt_init(mysql);
          if (!stmt) {
            fprintf(stderr, " mysql_stmt_init(), out of memory\n");
            exit(EXIT_FAILURE);
          }
          /* blocking
                                                  if (mysql_stmt_prepare(stmt,
             buff, bl)) { // the prepared statement is created fprintf(stderr, "
             mysql_stmt_prepare(), failed: %s\n" , mysql_stmt_error(stmt));
                                                          exit(EXIT_FAILURE);
                                                  }
          */
          async_exit_status =
              mysql_stmt_prepare_start(&ret_int, stmt, buff, bl);
          while (async_exit_status) {
            async_exit_status = wait_for_mysql(mysql, async_exit_status);
            async_exit_status =
                mysql_stmt_prepare_cont(&ret_int, stmt, async_exit_status);
          }
          if (ret_int) {
            fprintf(stderr, " mysql_stmt_prepare(), failed: %s\n",
                    mysql_stmt_error(stmt));
            exit(EXIT_FAILURE);
          }
          local_stmts->insert(a->statement_id, stmt);
          run_stmt(mysql, stmt, (uint32_t)mt_rand());
          created++;
          executed++;
          local_stmts->erase(a->statement_id);
        }
      } else { // no prepared statement was found in global
        stmt = mysql_stmt_init(mysql);
        if (!stmt) {
          fprintf(stderr, " mysql_stmt_init(), out of memory\n");
          exit(EXIT_FAILURE);
        }
        /* blocking
                                        if (mysql_stmt_prepare(stmt, buff, bl))
           { // the prepared statement is created fprintf(stderr, "
           mysql_stmt_prepare(), failed: %s\n" , mysql_stmt_error(stmt));
                                                exit(EXIT_FAILURE);
                                        }
        */
        async_exit_status = mysql_stmt_prepare_start(&ret_int, stmt, buff, bl);
        while (async_exit_status) {
          async_exit_status = wait_for_mysql(mysql, async_exit_status);
          async_exit_status =
              mysql_stmt_prepare_cont(&ret_int, stmt, async_exit_status);
        }
        if (ret_int) {
          fprintf(stderr, " mysql_stmt_prepare(), failed: %s\n",
                  mysql_stmt_error(stmt));
          exit(EXIT_FAILURE);
        }
        MySQL_STMT_Global_info *stmt_info = NULL;
        stmt_info = GloMyStmt->add_prepared_statement(
            0, (char *)USER, (char *)SCHEMA, buff, bl, stmt);
        uint32_t stmid = stmt_info->statement_id;
        if (NUMPRO < 32)
          fprintf(stdout, "SERVER_statement_id=%lu , PROXY_statement_id=%u\n",
                  stmt->stmt_id, stmid);
        local_stmts->insert(stmid, stmt);
        run_stmt(mysql, stmt, (uint32_t)mt_rand());
        created++;
        executed++;
        local_stmts->erase(stmid);
      }
    }
    fprintf(stdout,
            "Found %u , created %u and executed %u prepared statements in: ",
            founds, created, executed);
  }
  /*
          {
                  // for comparison, we run also queries in TEXT protocol
                  cpu_timer t;
                  for (i=0; i<NUMPREP*LOOPS; i++) {
                          sprintf(buff,"SELECT %u +
     %u",i,(uint32_t)mt_rand()%NUMPRO); bl=strlen(buff); int
     rc=mysql_real_query(mysql,buff,bl); if (rc) { fprintf(stderr, "
     mysql_real_query(), failed: %s\n" , mysql_error(mysql));
                                  exit(EXIT_FAILURE);
                          }
                          MYSQL_RES *res=mysql_store_result(mysql);
                          if (res==NULL) {
                                  fprintf(stderr, " mysql_store_result(),
     failed: %s\n" , mysql_error(mysql)); exit(EXIT_FAILURE);
                          }
                          mysql_free_result(res);
                  }
                  fprintf(stdout, "Executed %u queries in: ", i);
          }
          return 0;
  */
}

int main() {
  // initialize mysql
  mysql_library_init(0, NULL, NULL);

  // create a new MySQL_STMT_Manager()
  GloMyStmt = new MySQL_STMT_Manager();
  GloThrData = (thread_data_t **)malloc(sizeof(thread_data_t *) * NTHREADS);

  // starts N threads
  int i;
  for (i = 0; i < NTHREADS; i++) {
    GloThrData[i] = (thread_data_t *)malloc(sizeof(thread_data_t));
    GloThrData[i]->thread = new std::thread(&mysql_thread, i);
  }
  // wait for the threads to complete
  for (i = 0; i < NTHREADS; i++) {
    GloThrData[i]->thread->join();
  }
  return 0;
}
