#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include <sys/socket.h>
#include <poll.h>
#include <assert.h>

typedef int     myf;    // Type of MyFlags in my_funcs
#define MYF(v)      (myf) (v)
#define MY_KEEP_PREALLOC    1
#define MY_ALIGN(A,L)    (((A) + (L) - 1) & ~((L) - 1))
#define ALIGN_SIZE(A)    MY_ALIGN((A),sizeof(double))
void ma_free_root(MA_MEM_ROOT *root, myf MyFLAGS);
void *ma_alloc_root(MA_MEM_ROOT *mem_root, size_t Size);
//void ma_free_root(MA_MEM_ROOT *, int);
//#include "ma_global.h"
//#include "ma_sys.h"
#define MAX(a,b) (((a) > (b)) ? (a) : (b))


void * ma_alloc_root(MA_MEM_ROOT *mem_root, size_t Size)
{
#if defined(HAVE_purify) && defined(EXTRA_DEBUG)
  MA_USED_MEM *next;
  Size+=ALIGN_SIZE(sizeof(MA_USED_MEM));

  if (!(next = (MA_USED_MEM*) malloc(Size)))
  {
    if (mem_root->error_handler)
      (*mem_root->error_handler)();
    return((void *) 0);             /* purecov: inspected */
  }
  next->next=mem_root->used;
  mem_root->used=next;
  return (void *) (((char*) next)+ALIGN_SIZE(sizeof(MA_USED_MEM)));
#else
  size_t get_size;
  void * point;
  MA_USED_MEM *next= 0;
  MA_USED_MEM **prev;

  Size= ALIGN_SIZE(Size);

  if ((*(prev= &mem_root->free)))
  {
    if ((*prev)->left < Size &&
        mem_root->first_block_usage++ >= 16 &&
        (*prev)->left < 4096)
    {
      next= *prev;
      *prev= next->next;
      next->next= mem_root->used;
      mem_root->used= next;
      mem_root->first_block_usage= 0;
    }
    for (next= *prev; next && next->left < Size; next= next->next)
      prev= &next->next;
  }
  if (! next)
  {                     /* Time to alloc new block */
    get_size= MAX(Size+ALIGN_SIZE(sizeof(MA_USED_MEM)),
              (mem_root->block_size & ~1) * ( (mem_root->block_num >> 2) < 4 ? 4 : (mem_root->block_num >> 2) ) );

    if (!(next = (MA_USED_MEM*) malloc(get_size)))
    {
      if (mem_root->error_handler)
    (*mem_root->error_handler)();
      return((void *) 0);               /* purecov: inspected */
    }
    mem_root->block_num++;
    next->next= *prev;
    next->size= get_size;
    next->left= get_size-ALIGN_SIZE(sizeof(MA_USED_MEM));
    *prev=next;
  }
  point= (void *) ((char*) next+ (next->size-next->left));
  if ((next->left-= Size) < mem_root->min_malloc)
  {                     /* Full block */
    *prev=next->next;               /* Remove block from list */
    next->next=mem_root->used;
    mem_root->used=next;
    mem_root->first_block_usage= 0;
  }
  return(point);
#endif
}


void ma_free_root(MA_MEM_ROOT *root, myf MyFlags)
{ 
  MA_USED_MEM *next,*old;

  if (!root)
    return; /* purecov: inspected */
  if (!(MyFlags & MY_KEEP_PREALLOC))
    root->pre_alloc=0;

  for ( next=root->used; next ;)
  {
    old=next; next= next->next ;
    if (old != root->pre_alloc)
      free(old);
  }
  for (next= root->free ; next ; )
  {
    old=next; next= next->next ;
    if (old != root->pre_alloc)
      free(old);
  }
  root->used=root->free=0;
  if (root->pre_alloc)
  {
    root->free=root->pre_alloc;
    root->free->left=root->pre_alloc->size-ALIGN_SIZE(sizeof(MA_USED_MEM));
    root->free->next=0;
  }
}


/* Helper function to do the waiting for events on the socket. */
static int wait_for_mysql(MYSQL *mysql, int status) {
	struct pollfd pfd;
	int timeout, res;

	pfd.fd = mysql_get_socket(mysql);
	pfd.events =
		(status & MYSQL_WAIT_READ ? POLLIN : 0) |
		(status & MYSQL_WAIT_WRITE ? POLLOUT : 0) |
		(status & MYSQL_WAIT_EXCEPT ? POLLPRI : 0);
	if (status & MYSQL_WAIT_TIMEOUT)
		timeout = 1000*mysql_get_timeout_value(mysql);
	else
		timeout = -1;
	res = poll(&pfd, 1, timeout);
	if (res == 0)
		return MYSQL_WAIT_TIMEOUT;
	else if (res < 0)
		return MYSQL_WAIT_TIMEOUT;
	else {
		int status = 0;
		if (pfd.revents & POLLIN) status |= MYSQL_WAIT_READ;
		if (pfd.revents & POLLOUT) status |= MYSQL_WAIT_WRITE;
		if (pfd.revents & POLLPRI) status |= MYSQL_WAIT_EXCEPT;
		return status;
	}
}

int restore_admin(MYSQL* mysqladmin) {
	MYSQL_QUERY(mysqladmin, "load mysql query rules from disk");
	MYSQL_QUERY(mysqladmin, "load mysql query rules to runtime");
	MYSQL_QUERY(mysqladmin, "load mysql servers from disk");
	MYSQL_QUERY(mysqladmin, "load mysql servers to runtime");
	MYSQL_QUERY(mysqladmin, "load mysql variables from disk");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	return 0;
}

/**
 * @brief POC of the implementation for 'ps_buffering' for ProxySQL, this function encapsulates
 *   the core logic that is implemented in ProxySQL.
 *
 * @param query The query to be prepared and executed in the supplied 'MYSQL_STMT' that needs to
 *   be initialized.
 * @param mysql A 'MYSQL*' connection handle, already oppened.
 * @param stmt2a A 'MYSQL_STMT*' already initialized.
 *
 * @return The number of rows readed from the 'MYSQL_STMT' after this has been executed, and
 *   'mysql_stmt_store_result_cont' has finished returned all the rows for the query.
 */
int mysql_stmt_store_result_cont_poc(const std::string query, MYSQL* mysql, MYSQL_STMT* stmt2a, bool check_ids) {
	if (mysql_stmt_prepare(stmt2a, query.c_str(), query.size())) {
		fprintf(stderr, "Query error %s\n", mysql_error(mysql));
		mysql_library_end();

		return -1;
	}

	if (mysql_stmt_execute(stmt2a))
	{
		fprintf(stderr, " mysql_stmt_execute(), failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt2a));

		return -1;
	}

	MYSQL_RES* prepare_meta_result = mysql_stmt_result_metadata(stmt2a);

	int async_exit_status;
	int interr = 0;
	int cont_cnt = 0;
	int rows_read = 0;
	int prev_id3 = 0;

	async_exit_status = mysql_stmt_store_result_start(&interr, stmt2a);
	while (async_exit_status) {
		async_exit_status = wait_for_mysql(mysql, async_exit_status);
		async_exit_status = mysql_stmt_store_result_cont(&interr, stmt2a, async_exit_status);
		cont_cnt++;
		MYSQL_ROWS *r=stmt2a->result.data;
		int rows_read_inner = 0;
		if (r) {
			rows_read_inner++;
			MYSQL_ROWS *pr = r;
			while(rows_read_inner < stmt2a->result.rows) {
				rows_read_inner++;
				pr = r;
				r = r->next;
			}
			diag("Rows in buffer after calling mysql_stmt_store_result_cont(): %d", rows_read_inner);
			// we now clean up the whole storage.
			// This is the real POC
			if (rows_read_inner > 1) {
				// there is more than 1 row
				int irs = 0;
				MYSQL_ROWS *ir=stmt2a->result.data;
				// see https://dev.mysql.com/doc/internals/en/binary-protocol-resultset-row.html
				// on why we have an offset of 3
				const int row_offset = 3;
				for (irs = 0; irs < stmt2a->result.rows - 1; irs++) {
					if (check_ids) {
						int id1, id2, id3 = 0;
						memcpy(&id1, (char *)ir->data+row_offset, sizeof(int));
						memcpy(&id2, (char *)ir->data+row_offset+sizeof(int), sizeof(int));
						memcpy(&id3, (char *)ir->data+row_offset+sizeof(int)*2, sizeof(int));

						// NOTE: Uncomment to have further information on the rows being processed
						// diag("Row: %d + %d = %d", id1, id2, id3);

						// We assert in case the ids doesn't match the expected one, ids should match this
						// same pattern as it's the same performed in the 'SELECT'.
						assert(id3==id1+id2);

						// Since 'ids' are created in a sequentially increasing fashion. We can ensure
						// that no middle rows are missing by checking that in case 'id3' is bigger than
						// the previous 'id3' (seq_rows_id).
						// We ensure that no rows are eluded during counting by checking that all in case
						// of 'id3' begin bigger than the previous 'id3' ('prev_id3'), it's bigger by
						// exactly one, in case of being smaller, we reset the previous 'id3' since
						// a new sequence of row fetching has started.
						if (irs != 0 && id3 > prev_id3) {
							assert(id3 == prev_id3 + 1);
						}
						// Update 'prev_id3' with current 'id3'
						prev_id3 = id3;
					}

					rows_read++;
					if (irs <= stmt2a->result.rows - 2) {
						ir = ir->next;
					}
				}

				// at this point, ir points to the last row
				// next, we create a new MYSQL_ROWS that is a copy of the last row
				MYSQL_ROWS *lcopy = (MYSQL_ROWS *)malloc(sizeof(MYSQL_ROWS) + ir->length);
				lcopy->length = ir->length;
				lcopy->data= (MYSQL_ROW)(lcopy + 1);
				memcpy((char *)lcopy->data, (char *)ir->data, ir->length);
				// next we proceed to reset all the buffer
				ma_free_root(&stmt2a->result.alloc, MYF(MY_KEEP_PREALLOC));

				// NOTE: Left for testing purposes
				// ma_free_root(&stmt2a->result.alloc, MYF(0));

				stmt2a->result.data= NULL;
				stmt2a->result_cursor= NULL;
				stmt2a->result.rows = 0;

				// we will now copy back the last row and make it the only row available
				MYSQL_ROWS *current = (MYSQL_ROWS *)ma_alloc_root(&stmt2a->result.alloc, sizeof(MYSQL_ROWS) + lcopy->length);
				current->data= (MYSQL_ROW)(current + 1);
				stmt2a->result.data = current;
				memcpy((char *)current->data, (char *)lcopy->data, lcopy->length);
				// We update the length of the copied 'MYSQL_ROWS' data
				current->length = lcopy->length;

				// we free the copy
				free(lcopy);
				// change the rows count to 1
				stmt2a->result.rows = 1;
				// we should also configure the cursor, but because we scan it using our own
				// algorithm, this is not needed
			}
		}
	}
	diag("mysql_stmt_store_result_cont called %d times", cont_cnt);

	if (prepare_meta_result) {
		mysql_free_result(prepare_meta_result);
	}

	return rows_read;
}

/**
 * @brief Count the number of rows present in the supplied 'MYSQL_STMT*' parameter, and
 *   returns the counted value.
 * @param stmt The 'MYSQL_STMT*' which rows are going to be counted.
 * @return The number of rows present in the 'MYSQL_STMT' parameter.
 */
int count_stmt_rows(MYSQL_STMT* stmt) {
	int row_count2a=0;
	int stmt2aRC = 0;

	// Count the rows from the resulting 'STMT'
	{
		MYSQL_ROWS *r=stmt->result.data;
		int rows_left = stmt->result.rows;
		int rows_read_inner = 0;

		if (r && rows_left) {
			row_count2a++;
			rows_read_inner++;
			while(rows_read_inner < stmt->result.rows && r->next) {
				rows_read_inner++;
				r = r->next;
				row_count2a++;
			}
		}
	}

	return row_count2a;
}

int NUM_ROWS = 100;

int test_ps_async(MYSQL* proxy, MYSQL* admin) {
	// we drastically reduce the receive buffer to make sure that
	// mysql_stmt_store_result_[start|continue] doesn't complete
	// in a single call
	int s = mysql_get_socket(proxy);
	int rcvbuf = 10240;

	diag("Setting mysql connection RCVBUF to %d bytes", rcvbuf);
	if(setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
		fprintf(stderr, "Failed to call setsockopt\n");
		return exit_status();
	}

	MYSQL_QUERY(admin, "delete from mysql_query_rules");
	MYSQL_QUERY(admin, "load mysql query rules to runtime");

	MYSQL_QUERY(admin, "delete from mysql_servers where hostgroup_id=1");
	MYSQL_QUERY(admin, "load mysql servers to runtime");

	MYSQL_QUERY(admin, "set mysql-threshold_resultset_size=5000");
	MYSQL_QUERY(admin, "load mysql variables to runtime");

	if (create_table_test_sbtest1(NUM_ROWS,proxy)) {
		fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
		return exit_status();
	}

	std::string query = "";

	int NUM_ROWS_READ = 0;
	MYSQL_STMT *stmt2a = nullptr;
	int rows_read = 0;
	int row_count2a = 0;

	// Initial query, checking that the order is correct
	// ************************************************************************

	NUM_ROWS_READ = 1000;

	stmt2a = mysql_stmt_init(proxy);
	if (!stmt2a) {
		ok(false, " mysql_stmt_init(), out of memory\n");
		return restore_admin(admin);
	}

	// NOTE: the first 2 columns we select are 3 ids, so we can later print and verify
	query = "SELECT t1.id id1, t2.id id2, t1.id+t2.id id3, t1.k k1, t1.c c1, t1.pad pad1, t2.k k2, t2.c c2, t2.pad pad2 FROM test.sbtest1 t1 JOIN test.sbtest1 t2 ORDER BY t1.id, t2.id LIMIT " + std::to_string(NUM_ROWS_READ);
	//query = "SELECT t1.id id1, t2.id id2, t1.id+t2.id id3 FROM test.sbtest1 t1 JOIN test.sbtest1 t2 LIMIT " + std::to_string(IT_NUM_ROWS_READ);
	//query = "SELECT t1.id id1, t2.id id2, t1.id+t2.id id3 FROM test.sbtest1 t1 JOIN test.sbtest1 t2 ORDER BY t1.id, t2.id LIMIT " + std::to_string(IT_NUM_ROWS_READ);

	rows_read = mysql_stmt_store_result_cont_poc(query, proxy, stmt2a, true);
	row_count2a = count_stmt_rows(stmt2a);

	ok(
		row_count2a + rows_read == NUM_ROWS_READ,
		"Fetched %d rows, expected %d. Details: %d rows processed while buffering, %d at the end",
		row_count2a + rows_read,
		NUM_ROWS_READ,
		rows_read,
		row_count2a
	);

	if (mysql_stmt_close(stmt2a)) {
		fprintf(stderr, " failed while closing the statement\n");
		ok(false, " %s\n", mysql_error(proxy));
		restore_admin(admin);

		return -1;
	}

	// Second query: This query was specifically thought to trigger a segfault
	// and invalid memory access found while testing and reported by valgrind.
	// The principle is to perform multiple big queries followed by small queries.
	// ************************************************************************
	NUM_ROWS_READ = 10;

	stmt2a = mysql_stmt_init(proxy);
	if (!stmt2a) {
		ok(false, " mysql_stmt_init(), out of memory\n");
		return restore_admin(admin);
	}

	// Original query: For testing purposes
	// ************************************************************************
	// query = "(SELECT id, k, REPEAT(c,100+20000) cc FROM test.sbtest1 LIMIT " + std::to_string(NUM_ROWS_READ) + ")";
	// query += "UNION (SELECT id, k, REPEAT(c,100) cc FROM test.sbtest1 LIMIT " + std::to_string(NUM_ROWS_READ) + ")";
	// ************************************************************************

	// Small version of 'memory issues' query triggering valgrind errors
	query = "(SELECT id, k, REPEAT(c,2000) cc FROM test.sbtest1 LIMIT " + std::to_string(NUM_ROWS_READ) + ")";
	query += "UNION (SELECT id, k, REPEAT(c,10) cc FROM test.sbtest1 LIMIT " + std::to_string(NUM_ROWS_READ) + ")";

	rows_read = mysql_stmt_store_result_cont_poc(query, proxy, stmt2a, false);
	row_count2a = count_stmt_rows(stmt2a);

	ok(
		row_count2a + rows_read == NUM_ROWS_READ * 2,
		"Fetched %d rows, expected %d. Details: %d rows processed while buffering, %d at the end",
		row_count2a + rows_read,
		NUM_ROWS_READ,
		rows_read,
		row_count2a
	);

	if (mysql_stmt_close(stmt2a)) {
		fprintf(stderr, " failed while closing the statement\n");
		ok(false, " %s\n", mysql_error(proxy));
		restore_admin(admin);

		return -1;
	}

	restore_admin(admin);


	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(4);
	diag("Testing PS async store result");

	MYSQL* admin = mysql_init(NULL);
	if (!admin)
		return EXIT_FAILURE;

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	MYSQL* proxy = mysql_init(NULL);
	if (!proxy) {
		return EXIT_FAILURE;
	}

	// First test without 'CLIENT_DEPRECATE_EOF' support
	{
		// configure the connection as not blocking
		diag("Setting mysql connection non blocking");
		mysql_options(proxy, MYSQL_OPT_NONBLOCK, 0);

		if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		    fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
			return EXIT_FAILURE;
		}

		test_ps_async(proxy, admin);
	}

	mysql_close(proxy);
	proxy = mysql_init(NULL);
	if (!proxy) {
		return EXIT_FAILURE;
	}

	// Enable 'CLIENT_DEPRECATE_EOF' support and retest
	{
		// configure the connection as not blocking
		diag("Setting mysql connection non blocking");
		mysql_options(proxy, MYSQL_OPT_NONBLOCK, 0);
		proxy->options.client_flag |= CLIENT_DEPRECATE_EOF;

		if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		    fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
			return EXIT_FAILURE;
		}

		test_ps_async(proxy, admin);
	}

	mysql_close(proxy);
	mysql_library_end();

	return exit_status();
}

