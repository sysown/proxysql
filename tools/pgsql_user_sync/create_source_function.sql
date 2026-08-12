-- Run this file while connected to the database named in the synchronizer
-- configuration (normally "postgres") as a trusted PostgreSQL administrator.
-- Replace the reader password before running it.  This is an operator-managed
-- sample; keep this file out of source control after inserting a real secret.

-- The membership of this NOLOGIN role is the explicit import allow-list.
DO $role$
BEGIN
    CREATE ROLE proxysql_auth_managed NOLOGIN;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END
$role$;
ALTER ROLE proxysql_auth_managed NOLOGIN;

DO $role$
BEGIN
    CREATE ROLE proxysql_auth_reader
        LOGIN
        PASSWORD 'REPLACE_WITH_SOURCE_PASSWORD';
EXCEPTION
    WHEN duplicate_object THEN NULL;
END
$role$;

CREATE SCHEMA IF NOT EXISTS proxysql_auth;
ALTER SCHEMA proxysql_auth OWNER TO CURRENT_USER;

CREATE OR REPLACE FUNCTION proxysql_auth.export_login_roles()
RETURNS TABLE(username text, password text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT r.rolname::text AS username, r.rolpassword AS password
    FROM pg_catalog.pg_authid AS r
    WHERE r.rolcanlogin
      AND r.rolpassword IS NOT NULL
      AND (r.rolvaliduntil IS NULL OR r.rolvaliduntil > pg_catalog.now())
      AND pg_catalog.pg_has_role(r.oid, 'proxysql_auth_managed', 'member')
    ORDER BY r.rolname;
$function$;

-- Remove defaults first, then grant only the exact access needed by the
-- synchronizer.  CONNECT is shown for the sample database; change postgres
-- when installing into another database.
REVOKE ALL ON SCHEMA proxysql_auth FROM PUBLIC;
REVOKE ALL ON FUNCTION proxysql_auth.export_login_roles() FROM PUBLIC;
REVOKE ALL ON FUNCTION proxysql_auth.export_login_roles() FROM proxysql_auth_reader;
GRANT CONNECT ON DATABASE postgres TO proxysql_auth_reader;
GRANT USAGE ON SCHEMA proxysql_auth TO proxysql_auth_reader;
GRANT EXECUTE ON FUNCTION proxysql_auth.export_login_roles() TO proxysql_auth_reader;

-- Allow-list examples (run separately, one role at a time):
--   GRANT app_login TO proxysql_auth_managed;
--   REVOKE app_login FROM proxysql_auth_managed;
