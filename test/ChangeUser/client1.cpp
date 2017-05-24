#include "cpp.h"
#include "proxysql.h"

static int wait_for_mysql(MYSQL *mysql, int status) {
  struct pollfd pfd;
  int timeout, res;

  pfd.fd = mysql_get_socket(mysql);
  pfd.events = (status & MYSQL_WAIT_READ ? POLLIN : 0) |
               (status & MYSQL_WAIT_WRITE ? POLLOUT : 0) |
               (status & MYSQL_WAIT_EXCEPT ? POLLPRI : 0);
  //  if (status & MYSQL_WAIT_TIMEOUT)
  //    timeout = 1000*mysql_get_timeout_value(mysql);
  //  else
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

int main() {
  // initialize mysql
  mysql_library_init(0, NULL, NULL);

  MYSQL *mysql = mysql_init(NULL);
  mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
  MYSQL *ret_mysql = NULL;
  int async_exit_status = 0;
  my_bool ret_bool;
  async_exit_status = mysql_real_connect_start(
      &ret_mysql, mysql, "127.0.0.1", "msandbox", "msandbox",
      "information_schema", 21891, NULL, 0);
  while (async_exit_status) {
    async_exit_status = wait_for_mysql(mysql, async_exit_status);
    async_exit_status =
        mysql_real_connect_cont(&ret_mysql, mysql, async_exit_status);
  }
  if (ret_mysql == NULL) {
    fprintf(stderr, "Failed to connect, error: %s\n", mysql_error(mysql));
    exit(EXIT_FAILURE);
  }
  async_exit_status = mysql_change_user_start(
      &ret_bool, mysql, "msandbox2", "msandbox2", "information_schema");
  while (async_exit_status) {
    async_exit_status = wait_for_mysql(mysql, async_exit_status);
    async_exit_status =
        mysql_change_user_cont(&ret_bool, mysql, async_exit_status);
  }
  if (ret_bool == TRUE) {
    fprintf(stderr, "Failed to change user, error: %s\n", mysql_error(mysql));
    exit(EXIT_FAILURE);
  }
  //	if
  //(!mysql_real_connect(mysql,"127.0.0.1","msandbox","msandbox","information_schema",21891,NULL,0))
  //{ 		fprintf(stderr, "Failed to connect, error: %s\n",
  //mysql_error(mysql)); 		exit(EXIT_FAILURE);
  //	}
  //	if
  //(mysql_change_user(mysql,"msandbox2","msandbox2","information_schema")) {
  //		fprintf(stderr, "Failed to change user, error: %s\n",
  //mysql_error(mysql)); 		exit(EXIT_FAILURE);
  //	}
  return 0;
}
