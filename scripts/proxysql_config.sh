# Configure a local ProxySQL instance for enabling the example RESTAPI scripts in this folder

# Enable restapi
mysql -h127.0.0.1 -P6032 -uradmin -pradmin -e "SET admin-restapi_enabled='true'"
mysql -h127.0.0.1 -P6032 -uradmin -pradmin -e "SET admin-restapi_port=6070"
mysql -h127.0.0.1 -P6032 -uradmin -pradmin -e "LOAD ADMIN VARIABLES TO RUNTIME"

# Clenaup current routes
mysql -h127.0.0.1 -P6032 -uradmin -pradmin -e "DELETE FROM restapi_routes"

# Add new routes
mysql -h127.0.0.1 -P6032 -uradmin -pradmin -e \
    "INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) VALUES (1,3000,'GET','flush_query_cache','$(pwd)/flush_query_cache.sh','Flush the query cache')"
mysql -h127.0.0.1 -P6032 -uradmin -pradmin -e \
    "INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) VALUES (1,3000,'POST','change_host_status','$(pwd)/change_host_status.sh','Change the specified host status')"
mysql -h127.0.0.1 -P6032 -uradmin -pradmin -e \
    "INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) VALUES (1,3000,'POST','add_mysql_user','$(pwd)/add_mysql_user.sh','Adds a new MySQL user')"
mysql -h127.0.0.1 -P6032 -uradmin -pradmin -e \
    "INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) VALUES (1,20000,'POST','kill_idle_backend_conns','$(pwd)/kill_idle_backend_conns.py','Kills all idle backend connections')"
mysql -h127.0.0.1 -P6032 -uradmin -pradmin -e \
    "INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) VALUES (1,3000,'POST','scrap_stats','$(pwd)/stats_scrapper.py','Allow stats table scrapping')"

# Load the RESTAPI to runtime
mysql -h127.0.0.1 -P6032 -uradmin -pradmin -e "LOAD RESTAPI TO RUNTIME"
