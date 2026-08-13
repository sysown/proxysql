-- Run this file with psql while connected to the database named in the
-- synchronizer configuration (normally "postgres") as a trusted PostgreSQL
-- administrator. Supply a distinct reader password at runtime, for example:
--   psql --set=ON_ERROR_STOP=1 --set=proxysql_auth_reader_password='secret' \\
--     --file=create_source_function.sql postgres
-- The password variable is required so this sample cannot create a predictable
-- credential when run unchanged.

\if :{?proxysql_auth_reader_password}
\else
\echo 'Set proxysql_auth_reader_password with psql --set before running this script.'
\quit
\endif

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
        LOGIN;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END
$role$;
ALTER ROLE proxysql_auth_reader LOGIN PASSWORD :'proxysql_auth_reader_password';

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
      AND NOT r.rolsuper
      AND EXISTS (
          SELECT 1
          FROM pg_catalog.pg_auth_members AS membership
          WHERE membership.member = r.oid
            AND membership.roleid = 'proxysql_auth_managed'::regrole
      )
    ORDER BY r.rolname;
$function$;

-- Remove defaults first, then grant only the exact access needed by the
-- synchronizer.  CONNECT is granted on the database where this script runs.
REVOKE ALL ON SCHEMA proxysql_auth FROM PUBLIC;
REVOKE ALL ON FUNCTION proxysql_auth.export_login_roles() FROM PUBLIC;
REVOKE ALL ON FUNCTION proxysql_auth.export_login_roles() FROM proxysql_auth_reader;
DO $grant$
BEGIN
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO proxysql_auth_reader', current_database()
    );
END
$grant$;
GRANT USAGE ON SCHEMA proxysql_auth TO proxysql_auth_reader;
GRANT EXECUTE ON FUNCTION proxysql_auth.export_login_roles() TO proxysql_auth_reader;

-- Allow-list examples (run separately, one role at a time):
--   GRANT proxysql_auth_managed TO app_login;
--   REVOKE proxysql_auth_managed FROM app_login;
