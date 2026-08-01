//! # pg-query-gate
//!
//! Deny-by-default validation and session hardening for serving untrusted SQL
//! on PostgreSQL.
//!
//! Four defense layers for a public SQL surface. This crate is the three
//! software layers; the fourth ships as SQL you apply to the database:
//!
//! 1. **AST gate** ([`Policy::validate`]) — parse with sqlparser-rs, then
//!    refuse everything that is not one bounded, read-only SELECT (or plain
//!    EXPLAIN). Unknown constructs are denied by construction.
//! 2. **Token gate** (part of [`Policy::validate`]) — an independent screen at
//!    the token level that blocks catalog introspection and side-effect
//!    helpers, including their quoted and Unicode-escaped identifier forms.
//! 3. **Session battery** ([`session::build_setup_statements`]) — the
//!    `SET LOCAL` preamble that runs before every query: role switch, pinned
//!    `search_path`, timeouts, memory clamps, and `transaction_read_only = on`
//!    as an independent write-protection layer under the AST gate.
//! 4. **Role DDL** (`sql/hardening.sql`) — the database-side floor: a
//!    minimally-privileged role and function-execution revocations, so a gap
//!    in every software layer above still hits locked doors.
//!
//! No single layer is trusted. Each is small enough to audit on its own.

pub mod session;
mod validate;

pub use validate::{
    humanize_parse_error, query_shape_hash, validate_aggregate_aliases, Policy, AGGREGATE_ALIAS_ERROR,
    DEFAULT_MAX_LIMIT,
};
