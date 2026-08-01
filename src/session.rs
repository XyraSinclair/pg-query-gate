//! The session battery: per-query `SET LOCAL` hardening.
//!
//! Runs inside the query's transaction, in order: role first, then the
//! resource clamps that keep one query from owning the box, then row-level
//! security context, then `transaction_read_only = on` — the second,
//! independent write-protection layer under the AST gate. A single validator
//! gap can no longer turn an accidental write grant into a real mutation.

use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// § Constants: the numeric law
// ---------------------------------------------------------------------------

/// Default query timeout when neither the caller nor the histogram decides.
pub const DEFAULT_QUERY_TIMEOUT_SECS: u64 = 60;

/// Maximum statement timeout for public/anonymous SQL. Authenticated SQL uses
/// the caller's tier; public SQL keeps this short guardrail because it has no
/// durable account boundary to charge, throttle, or investigate.
pub const MAX_PUBLIC_STATEMENT_TIMEOUT_MS: u64 = 15_000;

/// Minimum adaptive timeout under heavy load.
pub const MIN_QUERY_TIMEOUT_SECS: u64 = 20;

/// Recommended maximum rows returned per query.
pub const MAX_QUERY_ROWS: usize = 10_000;

/// Recommended maximum response size (50 MB): OOM protection while streaming.
pub const MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;

/// Recommended maximum decoded size for a single returned cell — one
/// attacker-controlled scalar must not dominate the API process after
/// PostgreSQL produced it.
pub const MAX_RESPONSE_CELL_BYTES: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// § Roles and the identifier law
// ---------------------------------------------------------------------------

/// Role to execute SQL as.
#[derive(Debug, Clone)]
pub enum SessionRole {
    /// Anonymous read-only role, no user context.
    Anonymous { role_name: String },
    /// Per-user role with row-level-security context.
    User { role_name: String, user_id: Uuid },
}

impl SessionRole {
    pub fn role_name(&self) -> &str {
        match self {
            SessionRole::Anonymous { role_name } | SessionRole::User { role_name, .. } => role_name,
        }
    }

    pub fn user_id(&self) -> Option<Uuid> {
        match self {
            SessionRole::User { user_id, .. } => Some(*user_id),
            SessionRole::Anonymous { .. } => None,
        }
    }
}

/// The identifier law: anything interpolated into `SET LOCAL ROLE` or
/// `search_path` must be a plain SQL identifier. (The predicate needs no
/// regex engine.)
pub fn is_sql_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ---------------------------------------------------------------------------
// § RLS session variables (the user-context law)
// ---------------------------------------------------------------------------
// PostgreSQL RLS policies read three session vars. The law is the TRIO: a
// user query that sets one but not the others is a policy hole, so the trio
// renders from one type and cannot be split. Values are typed UUIDs and a
// closed literal — their rendering cannot carry an injection.

#[derive(Debug, Clone)]
pub struct RlsContext {
    pub user_id: Uuid,
    pub group_ids: Vec<Uuid>,
}

impl RlsContext {
    /// The three `SET LOCAL` statements, always all three.
    pub fn set_local_statements(&self) -> [String; 3] {
        let groups_csv = self.group_ids.iter().map(Uuid::to_string).collect::<Vec<_>>().join(",");
        [
            format!("SET LOCAL app.current_user_id = '{}'", self.user_id),
            format!("SET LOCAL app.user_groups = '{groups_csv}'"),
            "SET LOCAL app.access_mode = 'full'".to_string(),
        ]
    }
}

// ---------------------------------------------------------------------------
// § Timeouts: the clamp law and the adaptive histogram
// ---------------------------------------------------------------------------

/// The clamp law. Every query here is validated by construction before it
/// executes, so the axis is the role alone: a durable account boundary earns
/// its requested timeout; public/anonymous does not.
pub fn effective_statement_timeout_ms(role: &SessionRole, requested_timeout_ms: u64) -> u64 {
    let requested = requested_timeout_ms.max(1);
    match role {
        SessionRole::User { .. } => requested,
        SessionRole::Anonymous { .. } => requested.min(MAX_PUBLIC_STATEMENT_TIMEOUT_MS),
    }
}

/// Lock-free latency histogram feeding the adaptive timeout.
/// Buckets: [0-100ms, 100-500ms, 500ms-1s, 1-5s, 5-10s, 10-30s, 30-60s, 60s+]
pub struct AtomicLatencyHistogram {
    buckets: [AtomicU64; 8],
    total: AtomicU64,
}

const BUCKET_BOUNDS: [u64; 7] = [100, 500, 1000, 5000, 10000, 30000, 60000];

impl AtomicLatencyHistogram {
    pub const fn new() -> Self {
        Self {
            buckets: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            total: AtomicU64::new(0),
        }
    }

    pub fn record(&self, duration_ms: u64) {
        let bucket = BUCKET_BOUNDS.iter().position(|&bound| duration_ms < bound).unwrap_or(7);
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    /// P95-bucket → timeout seconds. Under load the ceiling tightens toward
    /// [`MIN_QUERY_TIMEOUT_SECS`] so slow queries shed before they pile up.
    pub fn compute_query_timeout_secs(&self) -> u64 {
        if self.count() < 10 {
            return DEFAULT_QUERY_TIMEOUT_SECS;
        }
        match self.p95_bucket() {
            0..=2 => DEFAULT_QUERY_TIMEOUT_SECS,
            3 => 50,
            4 => 40,
            5 => 30,
            _ => MIN_QUERY_TIMEOUT_SECS,
        }
    }

    fn p95_bucket(&self) -> usize {
        let total = self.total.load(Ordering::Relaxed);
        if total == 0 {
            return 0;
        }
        let target = ((total as f64) * 0.95).ceil() as u64;
        let mut cumulative = 0u64;
        for (i, bucket) in self.buckets.iter().enumerate() {
            cumulative += bucket.load(Ordering::Relaxed);
            if cumulative >= target {
                return i;
            }
        }
        7
    }

    fn count(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

impl Default for AtomicLatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// § The setup battery
// ---------------------------------------------------------------------------

/// Knobs for the battery. Defaults are the production values the battery
/// shipped with; every one of them exists to keep a single query from owning
/// the box.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// Schemas for `SET LOCAL search_path`, in order. `pg_catalog` first is
    /// deliberate: it pins system-name resolution so a malicious same-named
    /// object in a user schema cannot shadow it.
    pub search_path: Vec<String>,
    pub lock_timeout_ms: u64,
    pub work_mem_mb: u64,
    pub temp_file_limit_mb: u64,
    /// `max_parallel_workers_per_gather = 0`: one query gets one core.
    pub disable_parallelism: bool,
    /// `jit = off`: JIT compilation is a cost amplifier on adversarial plans.
    pub disable_jit: bool,
    /// `transaction_read_only = on`, the independent write-protection layer.
    /// Leave on unless the session must write.
    pub read_only: bool,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            search_path: vec!["pg_catalog".to_string(), "public".to_string()],
            lock_timeout_ms: 5_000,
            work_mem_mb: 16,
            temp_file_limit_mb: 256,
            disable_parallelism: true,
            disable_jit: true,
            read_only: true,
        }
    }
}

/// Build the `SET LOCAL` battery for one query, in order: role first, then
/// the resource clamps, then RLS context, then read-only.
///
/// Execute the returned statements inside the query's transaction before the
/// query itself. Fails if the role name or any search-path schema is not a
/// plain SQL identifier (the identifier law).
pub fn build_setup_statements(
    role: &SessionRole, rls_groups: &[Uuid], timeout_ms: u64, options: &SessionOptions,
) -> Result<Vec<String>, String> {
    if !is_sql_identifier(role.role_name()) {
        return Err(format!("Role name `{}` is not a plain SQL identifier.", role.role_name()));
    }
    for schema in &options.search_path {
        if !is_sql_identifier(schema) {
            return Err(format!("search_path schema `{schema}` is not a plain SQL identifier."));
        }
    }

    let mut setup = Vec::with_capacity(12);
    setup.push(format!("SET LOCAL ROLE {}", role.role_name()));
    setup.push(format!("SET LOCAL search_path = {}", options.search_path.join(", ")));
    setup.push(format!("SET LOCAL statement_timeout = '{timeout_ms}ms'"));
    setup.push(format!("SET LOCAL lock_timeout = '{}ms'", options.lock_timeout_ms));
    setup.push(format!("SET LOCAL work_mem = '{}MB'", options.work_mem_mb));
    if options.disable_parallelism {
        setup.push("SET LOCAL max_parallel_workers_per_gather = 0".to_string());
    }
    if options.disable_jit {
        setup.push("SET LOCAL jit = 'off'".to_string());
    }
    setup.push(format!("SET LOCAL temp_file_limit = '{}MB'", options.temp_file_limit_mb));
    if let Some(user_id) = role.user_id() {
        let rls = RlsContext { user_id, group_ids: rls_groups.to_vec() };
        setup.extend(rls.set_local_statements());
    }
    if options.read_only {
        // `transaction_read_only`, not `default_transaction_read_only`: the
        // `default_` GUC only seeds transactions that START after it is set, so
        // setting it mid-transaction (where this battery runs) is a no-op. The
        // plain form is the current transaction's own read-only flag — the same
        // thing `SET TRANSACTION READ ONLY` sets — and takes effect immediately.
        setup.push("SET LOCAL transaction_read_only = on".to_string());
    }
    Ok(setup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_statement_timeout_is_clamped_and_user_is_not() {
        let anon = SessionRole::Anonymous { role_name: "query_ro".into() };
        assert_eq!(effective_statement_timeout_ms(&anon, 60_000), MAX_PUBLIC_STATEMENT_TIMEOUT_MS);
        let user = SessionRole::User { role_name: "user_role_01".into(), user_id: Uuid::nil() };
        assert_eq!(effective_statement_timeout_ms(&user, 60_000), 60_000);
    }

    #[test]
    fn identifier_law_rejects_injection_shapes() {
        for bad in ["'; DROP TABLE users; --", "role name", "", "1role", "a-b"] {
            assert!(!is_sql_identifier(bad), "{bad:?} must not pass");
        }
        for good in ["query_ro", "user_role_12345678", "_internal"] {
            assert!(is_sql_identifier(good), "{good:?} must pass");
        }
    }

    #[test]
    fn setup_battery_carries_the_clamps_and_the_rls_trio() {
        let user = SessionRole::User { role_name: "user_role_test".into(), user_id: Uuid::from_u128(7) };
        let groups = [Uuid::from_u128(1), Uuid::from_u128(2)];
        let setup = build_setup_statements(&user, &groups, 30_000, &SessionOptions::default()).unwrap();

        assert_eq!(setup[0], "SET LOCAL ROLE user_role_test", "role is set first");
        for clamp in [
            "SET LOCAL search_path = pg_catalog, public",
            "SET LOCAL statement_timeout = '30000ms'",
            "SET LOCAL lock_timeout = '5000ms'",
            "SET LOCAL work_mem = '16MB'",
            "SET LOCAL max_parallel_workers_per_gather = 0",
            "SET LOCAL jit = 'off'",
            "SET LOCAL temp_file_limit = '256MB'",
        ] {
            assert!(setup.contains(&clamp.to_string()), "missing clamp: {clamp}");
        }
        // The trio, always all three, in one block.
        let uid = Uuid::from_u128(7);
        assert!(setup.contains(&format!("SET LOCAL app.current_user_id = '{uid}'")));
        assert!(setup.contains(&format!("SET LOCAL app.user_groups = '{},{}'", groups[0], groups[1])));
        assert!(setup.contains(&"SET LOCAL app.access_mode = 'full'".to_string()));
        // Second write-protection layer under the AST gate, last.
        assert_eq!(setup.last().unwrap(), "SET LOCAL transaction_read_only = on");
    }

    #[test]
    fn battery_refuses_non_identifier_role() {
        let evil = SessionRole::Anonymous { role_name: "r; DROP TABLE users".into() };
        assert!(build_setup_statements(&evil, &[], 15_000, &SessionOptions::default()).is_err());
    }
}
