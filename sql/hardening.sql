-- The database-side floor for a public SQL surface.
--
-- This layer holds if every software layer above it fails. Apply as a
-- superuser, once per database. Replace `query_ro`, `app_login`, and `corpus`
-- with your role and schema names.

-- 1. The serving role: NOLOGIN, minimally privileged. The application does not
--    connect as this role; it connects as its own login role and runs
--    `SET LOCAL ROLE query_ro` per query (see session::build_setup_statements).
CREATE ROLE query_ro NOLOGIN;

-- The application's login role must be a member of query_ro to assume it, and
-- it must NOT be a superuser: a superuser session ignores every grant, revoke,
-- timeout, and read-only flag below. Connect the public surface as an
-- unprivileged login role.
GRANT query_ro TO app_login;

-- The per-query timeouts, read-only flag, and search_path come from the session
-- battery (SET LOCAL, applied inside each query's transaction). That battery is
-- load-bearing and must run on every query. `ALTER ROLE query_ro SET ...` would
-- NOT back it up: role-level settings apply when a session logs in AS that role,
-- not when a session assumes it with SET ROLE. If you want a connection-time
-- backstop independent of the battery, set it on the login role instead:
-- ALTER ROLE app_login SET statement_timeout = '15s';

-- 2. PostgreSQL grants EXECUTE on routines to PUBLIC by default. Revoke it in
--    the served schema, both for existing objects and for objects created
--    later, so functions must be granted deliberately.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA public FROM PUBLIC;

-- This does NOT reach pg_catalog. Built-in functions like version(),
-- current_setting(), and has_table_privilege() keep their default EXECUTE grant
-- to PUBLIC, and revoking it there breaks the server. The AST and token gates
-- are the primary control for catalog-function calls; this floor backstops the
-- served schema, not pg_catalog.

-- 3. Grant the serving role exactly what it serves: usage on the served
--    schema and SELECT on the served relations. Grant table-by-table if the
--    schema mixes public and private relations.
GRANT USAGE ON SCHEMA corpus TO query_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA corpus TO query_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA corpus GRANT SELECT ON TABLES TO query_ro;

-- 4. If you expose any table-valued helper functions on the surface
--    (Policy::bounded_table_functions), grant them one by one:
-- GRANT EXECUTE ON FUNCTION corpus.search(text, int) TO query_ro;
