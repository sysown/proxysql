# TAP group dedicated to the PostgreSQL Unix-domain socket code path.
#
# `port=0` in pgsql_servers is documented to mean "hostname is a Unix socket
# path" (see https://www.proxysql.com/documentation/main-runtime/postgresql-tables
# #pgsql_servers). This group adds a new pgsql_servers row whose hostname is the
# socket directory shared between the pgdb1 container and the ProxySQL
# container, exercising the path that libpq would otherwise reject with
# "invalid port number: \"0\"".

# Mount the PostgreSQL Unix-socket directory into the ProxySQL container.
# start-proxysql-isolated.bash turns this into a `-v ...:/var/run/postgresql-shared`
# on the ProxySQL container, matching the path pgdb1 creates the socket at.
export PROXYSQL_NEEDS_PGSQL_SOCKET=1

export DEFAULT_PGSQL_INFRA="docker-pgsql16-single"
