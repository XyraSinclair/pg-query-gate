# pg-query-gate

Deny-by-default validation and session hardening for serving untrusted SQL on
PostgreSQL.

This code is extracted from a production public SQL surface that served tens
of thousands of near-arbitrary queries from anonymous and authenticated
callers against a live PostgreSQL database. We publish it because the
question it answers — *how do you let strangers, and their agents, run SQL
against your database?* — now confronts everyone building data products, and
most available answers are either "don't" or a regex.

## The model: four independent layers

No single layer is trusted. Each is small enough to audit on its own, and a
gap in any one leaves the others standing.

1. **AST gate** (`Policy::validate`). Parse with
   [sqlparser-rs](https://github.com/apache/datafusion-sqlparser-rs), then
   refuse everything that is not one bounded, read-only statement: an
   exhaustive statement-class match (every write, DDL, DCL, session,
   transaction, and cursor class refused by name), a read-only walk through
   CTEs, set operations, derived tables and lateral joins, SELECT INTO and
   FOR UPDATE/SHARE refusal, literal-only LIMIT/OFFSET with caps, a visitor
   spine that reaches every `Query` node an AST can carry (so a new nesting
   position cannot slip past), nested-ORDER-BY bounded-work enforcement,
   cartesian-product and tautological-join detection, and EXPLAIN ANALYZE
   refusal.
2. **Token gate** (also in `Policy::validate`). An independent screen at the
   token level: blocked schema qualifiers, blocked identifiers and prefixes
   (`pg_*`, `dblink*`, `lo_*`, advisory locks, sequence movers, XML
   exfiltration helpers, …), applied equally to double-quoted identifier
   forms so `"pg_catalog"."pg_class"` cannot bypass the bare-word list.
3. **Session battery** (`session::build_setup_statements`). The `SET LOCAL`
   preamble before every query: role switch, pinned `search_path`
   (`pg_catalog` first), statement and lock timeouts, `work_mem` cap,
   parallelism off, JIT off, `temp_file_limit`, the row-level-security
   context trio (all three vars or none), and
   `default_transaction_read_only = on` — so a validator gap still cannot
   turn an accidental write grant into a mutation.
4. **Role DDL** (`sql/hardening.sql`). The database-side floor: a NOLOGIN
   minimally-privileged serving role with role-level timeout backstops,
   `REVOKE CREATE ON SCHEMA public`, and function-execution revocations for
   existing and future objects.

## Usage

```rust
use pg_query_gate::{Policy, session};

let policy = Policy::default(); // strictest posture; grow allowlists deliberately

policy.validate(user_sql)?; // Err(reason) refuses the query

let role = session::SessionRole::Anonymous { role_name: "query_ro".into() };
let timeout = session::effective_statement_timeout_ms(&role, requested_ms);
for stmt in session::build_setup_statements(&role, &[], timeout, &Default::default())? {
    tx.execute(&stmt, &[]).await?; // inside the query's transaction
}
// then run the validated query in the same transaction
```

`Policy` fields let a deployment name its own bounded vocabulary: internally
row-capped table-valued functions, permitted lateral functions, extra
set-returning functions to refuse, and extended block lists. The default is
an empty allowlist — every entry you add is attack surface you own.

Also included: `query_shape_hash` (literal-scrubbed blake3 hashing for abuse
cohort analysis) and humanized parse errors.

## What this crate does not do

It does not connect to PostgreSQL, pool connections, stream results, rate
limit, or bill. Those belong to your service. The constants in `session`
document the caps the original surface ran with (row, response-byte, and
per-cell limits); enforce them in your executor.

## Acknowledgments

Built on [sqlparser-rs](https://github.com/apache/datafusion-sqlparser-rs)
(Apache DataFusion), whose visitor-derive machinery is what makes the
"every query node, by construction" gate possible, and
[BLAKE3](https://github.com/BLAKE3-team/BLAKE3).

## License

Released under the Harvest License (see `LICENSE.md`): use, modify, and sell
it freely. The one condition — the Harvest — is that at most once a year the
Steward may ask what the Work has been worth to you, and you answer honestly.
Your chosen return can be payment, a contribution, releasing work of your
own, or an honest zero. Only silence is a breach.
