-- The database-side floor for a public SQL surface.
--
-- This layer holds if every software layer above it fails. Apply as a
-- superuser, once per database. Replace `query_ro` and `corpus` with your
-- role and schema names.

-- 1. The serving role: NOLOGIN, minimally privileged. The application
--    connects as its own user and runs `SET LOCAL ROLE query_ro` per query
--    (see session::build_setup_statements).
CREATE ROLE query_ro NOLOGIN;

-- Role-level backstops. The session battery sets these per query; the role
-- carries them too so a battery gap does not run unbounded.
ALTER ROLE query_ro SET statement_timeout = '15s';
ALTER ROLE query_ro SET lock_timeout = '5s';
ALTER ROLE query_ro SET default_transaction_read_only = on;

-- 2. PostgreSQL grants EXECUTE on routines to PUBLIC by default. Revoke it,
--    both for existing objects and for objects created later, so functions
--    must be granted deliberately.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA public FROM PUBLIC;

-- 3. Grant the serving role exactly what it serves: usage on the served
--    schema and SELECT on the served relations. Grant table-by-table if the
--    schema mixes public and private relations.
GRANT USAGE ON SCHEMA corpus TO query_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA corpus TO query_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA corpus GRANT SELECT ON TABLES TO query_ro;

-- 4. If you expose any table-valued helper functions on the surface
--    (Policy::bounded_table_functions), grant them one by one:
-- GRANT EXECUTE ON FUNCTION corpus.search(text, int) TO query_ro;
