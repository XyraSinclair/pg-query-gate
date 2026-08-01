//! The AST gate and the token gate.
//!
//! AST-based SQL validation using sqlparser-rs for read-only query execution
//! paths, plus an independent token-level screen. Ported from a production
//! public SQL surface that served tens of thousands of untrusted queries;
//! deployment-specific vocabulary is factored into [`Policy`].

use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArg, FunctionArgExpr, FunctionArgumentClause, FunctionArguments, Join,
    JoinConstraint, JoinOperator, ObjectName, Query, Select, SelectItem, SetExpr, Statement, TableFactor,
    TableFunctionArgs, Value, Visit, Visitor, visit_expressions, visit_expressions_mut,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::{Parser, ParserError};
use sqlparser::tokenizer::{Token, Tokenizer};
use std::ops::ControlFlow;

/// Default maximum allowed LIMIT value for queries.
pub const DEFAULT_MAX_LIMIT: u64 = 10_000;

const BLOCKED_SCHEMA_QUALIFIERS: &[&str] = &["information_schema", "pg_catalog"];
const BLOCKED_IDENTIFIER_PREFIXES: &[&str] = &["binary_upgrade_", "pg_"];
const BLOCKED_BARE_IDENTIFIERS: &[&str] = &["user"];
const BLOCKED_FUNCTION_IDENTIFIERS: &[&str] = &["version"];
const BLOCKED_IDENTIFIERS: &[&str] = &[
    "aclexplode",
    "col_description",
    "current_catalog",
    "current_database",
    "current_query",
    "current_role",
    "current_schema",
    "current_schemas",
    "current_setting",
    "current_user",
    "cursor_to_xml",
    "cursor_to_xmlschema",
    "database_to_xml",
    "database_to_xml_and_xmlschema",
    "database_to_xmlschema",
    "dblink",
    "dblink_build_sql_delete",
    "dblink_build_sql_insert",
    "dblink_build_sql_update",
    "dblink_cancel_query",
    "dblink_close",
    "dblink_connect",
    "dblink_connect_u",
    "dblink_current_query",
    "dblink_disconnect",
    "dblink_error_message",
    "dblink_exec",
    "dblink_fetch",
    "dblink_get_connections",
    "dblink_get_notify",
    "dblink_get_pkey",
    "dblink_get_result",
    "dblink_is_busy",
    "dblink_open",
    "dblink_send_query",
    "format_type",
    "getpgusername",
    "has_any_column_privilege",
    "has_column_privilege",
    "has_database_privilege",
    "has_foreign_data_wrapper_privilege",
    "has_function_privilege",
    "has_language_privilege",
    "has_largeobject_privilege",
    "has_parameter_privilege",
    "has_schema_privilege",
    "has_sequence_privilege",
    "has_server_privilege",
    "has_table_privilege",
    "has_tablespace_privilege",
    "has_type_privilege",
    "inet_server_addr",
    "inet_server_port",
    "lastval",
    "lo_close",
    "lo_creat",
    "lo_create",
    "lo_export",
    "lo_from_bytea",
    "lo_get",
    "lo_import",
    "lo_lseek",
    "lo_lseek64",
    "lo_open",
    "lo_put",
    "lo_tell",
    "lo_tell64",
    "lo_truncate",
    "lo_truncate64",
    "lo_unlink",
    "loread",
    "lowrite",
    "nextval",
    "obj_description",
    "pg_advisory_lock",
    "pg_advisory_lock_shared",
    "pg_advisory_unlock",
    "pg_advisory_unlock_all",
    "pg_advisory_unlock_shared",
    "pg_advisory_xact_lock",
    "pg_advisory_xact_lock_shared",
    "pg_backend_pid",
    "pg_extension",
    "pg_roles",
    "pg_shadow",
    "pg_stat_activity",
    "pg_stat_database",
    "pg_stat_user_indexes",
    "pg_stat_user_tables",
    "pg_try_advisory_lock",
    "pg_try_advisory_lock_shared",
    "pg_try_advisory_xact_lock",
    "pg_try_advisory_xact_lock_shared",
    "pg_user",
    "pg_views",
    "repeat",
    "query_to_xml",
    "query_to_xml_and_xmlschema",
    "query_to_xmlschema",
    "regclass",
    "regcollation",
    "regconfig",
    "regdictionary",
    "regnamespace",
    "regoper",
    "regoperator",
    "regproc",
    "regprocedure",
    "regrole",
    "regtype",
    "row_security_active",
    "schema_to_xml",
    "schema_to_xml_and_xmlschema",
    "schema_to_xmlschema",
    "session_user",
    "set_config",
    "setval",
    "shobj_description",
    "system_user",
    "table_to_xml",
    "table_to_xml_and_xmlschema",
    "table_to_xmlschema",
    "to_regclass",
    "ts_rewrite",
    "ts_stat",
    "to_regnamespace",
    "to_regoper",
    "to_regoperator",
    "to_regproc",
    "to_regprocedure",
];

/// The validation policy: hard limits, block lists, and the deployment's own
/// bounded vocabulary.
///
/// [`Policy::default`] is the strictest useful posture: generic PostgreSQL
/// block lists, no table-valued functions admitted, aggregate aliases
/// required. Grow the allowlists deliberately; every entry is attack surface.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Maximum allowed LIMIT and OFFSET value.
    pub max_limit: u64,
    /// Schema qualifiers refused when followed by `.` (e.g. `pg_catalog`).
    pub blocked_schema_qualifiers: Vec<String>,
    /// Identifiers refused anywhere they appear.
    pub blocked_identifiers: Vec<String>,
    /// Identifier prefixes refused anywhere they appear (e.g. `pg_`).
    pub blocked_identifier_prefixes: Vec<String>,
    /// Identifiers refused only as bare words (e.g. `user`).
    pub blocked_bare_identifiers: Vec<String>,
    /// Identifiers refused only when called as functions (e.g. `version`).
    pub blocked_function_identifiers: Vec<String>,
    /// Fully-qualified, lowercase, dotted names of table-valued functions that
    /// are internally row-capped and therefore admissible in FROM (e.g.
    /// `"myschema.search"`). Only exempt functions whose own SQL hard-caps
    /// their result cardinality: this is a security control, not a
    /// convenience feature.
    pub bounded_table_functions: Vec<String>,
    /// Qualified names additionally permitted as LATERAL function join
    /// factors (`regexp_split_to_table` is always permitted there).
    pub safe_lateral_functions: Vec<String>,
    /// Additional set-returning function names to refuse inside expressions,
    /// beyond the built-in PostgreSQL list.
    pub set_returning_functions: Vec<String>,
    /// Require aggregate-shaped output columns to carry an alias.
    pub require_aggregate_aliases: bool,
}

impl Default for Policy {
    fn default() -> Self {
        fn owned(list: &[&str]) -> Vec<String> {
            list.iter().map(|s| s.to_string()).collect()
        }
        Self {
            max_limit: DEFAULT_MAX_LIMIT,
            blocked_schema_qualifiers: owned(BLOCKED_SCHEMA_QUALIFIERS),
            blocked_identifiers: owned(BLOCKED_IDENTIFIERS),
            blocked_identifier_prefixes: owned(BLOCKED_IDENTIFIER_PREFIXES),
            blocked_bare_identifiers: owned(BLOCKED_BARE_IDENTIFIERS),
            blocked_function_identifiers: owned(BLOCKED_FUNCTION_IDENTIFIERS),
            bounded_table_functions: Vec::new(),
            safe_lateral_functions: Vec::new(),
            set_returning_functions: Vec::new(),
            require_aggregate_aliases: true,
        }
    }
}

impl Policy {
    /// Validate that a SQL string is one bounded, read-only statement.
    ///
    /// Requires a single SELECT / VALUES / TABLE or EXPLAIN-wrapped read-only
    /// statement; blocks writable CTEs, SELECT INTO, SELECT FOR UPDATE/SHARE,
    /// unbounded LIMIT/OFFSET shapes, cartesian products, and everything on
    /// the token block lists.
    pub fn validate(&self, sql: &str) -> Result<(), String> {
        let dialect = PostgreSqlDialect {};
        let statements = Parser::parse_sql(&dialect, sql).map_err(|e| humanize_parse_error(e, sql))?;

        if statements.is_empty() {
            return Err("Empty query".to_string());
        }

        self.token_screen(sql)?;

        // Single statement only.
        if statements.len() != 1 {
            return Err(
                "Only a single statement is supported. Use a single SELECT (or SELECT with CTEs/UNION) query."
                    .to_string(),
            );
        }

        for (i, stmt) in statements.iter().enumerate() {
            match stmt {
                Statement::Query(query) => {
                    self.validate_read_only_query(query).map_err(|e| format!("Statement {}: {}", i + 1, e))?;
                    if self.require_aggregate_aliases {
                        validate_aggregate_aliases(query)?;
                    }
                    self.check_query_limit(query)?;
                    self.check_query_offsets(query)?;
                    self.check_bounded_nested_work(query)?;
                    self.check_projection_set_returning(query)?;
                    self.detect_cartesian_products(query)?;
                }
                Statement::Explain { statement, analyze, options, .. } => {
                    // sqlparser sets `analyze=true` for `EXPLAIN ANALYZE ...`, but for Postgres-style
                    // `EXPLAIN (ANALYZE, ...) ...` the ANALYZE flag may appear in `options`.
                    let analyze_in_options = options.as_ref().is_some_and(|opts| {
                        opts.iter().any(|opt| {
                            if !opt.name.value.eq_ignore_ascii_case("analyze") {
                                return false;
                            }
                            match &opt.arg {
                                // `EXPLAIN (ANALYZE)` or `EXPLAIN (ANALYZE TRUE)` executes.
                                None => true,
                                Some(Expr::Value(Value::Boolean(true))) => true,
                                // Explicit `ANALYZE FALSE` does not execute.
                                Some(Expr::Value(Value::Boolean(false))) => false,
                                // Conservative: treat non-literal args as enabled.
                                Some(_) => true,
                            }
                        })
                    });

                    // EXPLAIN ANALYZE actually executes the query - block it.
                    if *analyze || analyze_in_options {
                        return Err(format!(
                            "Statement {}: EXPLAIN ANALYZE is not allowed (it executes the query). Use EXPLAIN without ANALYZE.",
                            i + 1
                        ));
                    }
                    let Statement::Query(query) = &**statement else {
                        return Err(format!(
                            "Statement {}: EXPLAIN can only be used with read-only queries. EXPLAIN {} is not allowed.",
                            i + 1,
                            statement_type_name(statement)
                        ));
                    };
                    self.validate_read_only_query(query).map_err(|e| format!("Statement {}: EXPLAIN {}", i + 1, e))?;
                    self.check_query_limit(query)?;
                    self.check_query_offsets(query)?;
                    self.check_bounded_nested_work(query)?;
                    self.check_projection_set_returning(query)?;
                    self.detect_cartesian_products(query)?;
                }
                Statement::Insert(_) => {
                    return Err(refused(i, "INSERT"));
                }
                Statement::Update { .. } => {
                    return Err(refused(i, "UPDATE"));
                }
                Statement::Delete(_) => {
                    return Err(refused(i, "DELETE"));
                }
                Statement::Drop { .. } => {
                    return Err(refused(i, "DROP"));
                }
                Statement::CreateTable { .. }
                | Statement::CreateIndex { .. }
                | Statement::CreateView { .. }
                | Statement::CreateSchema { .. }
                | Statement::CreateDatabase { .. }
                | Statement::CreateFunction { .. }
                | Statement::CreateProcedure { .. }
                | Statement::CreateType { .. }
                | Statement::CreateRole { .. }
                | Statement::CreateSequence { .. }
                | Statement::CreateExtension { .. } => {
                    return Err(refused(i, "CREATE"));
                }
                Statement::AlterTable { .. }
                | Statement::AlterIndex { .. }
                | Statement::AlterView { .. }
                | Statement::AlterRole { .. } => {
                    return Err(refused(i, "ALTER"));
                }
                Statement::Truncate { .. } => {
                    return Err(refused(i, "TRUNCATE"));
                }
                Statement::Grant { .. } => {
                    return Err(refused(i, "GRANT"));
                }
                Statement::Revoke { .. } => {
                    return Err(refused(i, "REVOKE"));
                }
                Statement::Copy { .. } => {
                    return Err(refused(i, "COPY"));
                }
                Statement::SetVariable { .. }
                | Statement::SetRole { .. }
                | Statement::SetNames { .. }
                | Statement::SetTimeZone { .. }
                | Statement::SetTransaction { .. } => {
                    return Err(refused(i, "SET"));
                }
                Statement::StartTransaction { .. }
                | Statement::Commit { .. }
                | Statement::Rollback { .. }
                | Statement::Savepoint { .. } => {
                    return Err(refused(i, "Transaction control"));
                }
                Statement::Execute { .. } | Statement::Call { .. } => {
                    return Err(refused(i, "EXECUTE/CALL"));
                }
                Statement::Prepare { .. } | Statement::Deallocate { .. } => {
                    return Err(refused(i, "PREPARE/DEALLOCATE"));
                }
                Statement::LISTEN { .. } | Statement::NOTIFY { .. } => {
                    return Err(refused(i, "LISTEN/NOTIFY"));
                }
                Statement::Analyze { .. } => {
                    return Err(refused(i, "ANALYZE"));
                }
                Statement::ExplainTable { .. } => {
                    return Err(refused(i, "EXPLAIN TABLE"));
                }
                Statement::Merge { .. } => {
                    return Err(refused(i, "MERGE"));
                }
                Statement::Declare { .. } | Statement::Fetch { .. } | Statement::Close { .. } => {
                    return Err(refused(i, "Cursor operations"));
                }
                other => {
                    return Err(refused(i, statement_type_name(other)));
                }
            }
        }

        Ok(())
    }

    // § token gate: an independent screen below the AST
    //
    // PostgreSQL double quotes are delimited identifiers, not string literals,
    // so `"pg_catalog"."pg_class"` and `"pg_sleep"()` are screened exactly
    // like their bare forms.
    fn token_screen(&self, sql: &str) -> Result<(), String> {
        let dialect = PostgreSqlDialect {};
        let tokens = Tokenizer::new(&dialect, sql)
            .tokenize()
            .map_err(|e| format!("Failed to tokenize SQL for contract checks: {e}"))?;

        // Unicode-escape identifiers (`U&"..."`) and strings (`U&'...'`) let the
        // escaped bytes name a function or catalog object that never matches a
        // blocklist entry: `U&"v\0065rsion"()` reaches the server as `version()`.
        // The introducer is a bare `u`/`U` word glued — no whitespace token
        // between — to `&` glued to a quoted string. Scan the UNFILTERED stream
        // so the adjacency is real; `u & "x"` (spaced) is ordinary bitwise-and
        // and must survive. Reject the form outright: it has no legitimate use
        // on this surface, and admitting it would mean decoding every escape.
        for window in tokens.windows(3) {
            let [Token::Word(intro), Token::Ampersand, third] = window else {
                continue;
            };
            let is_introducer = intro.quote_style.is_none() && intro.value.eq_ignore_ascii_case("u");
            let third_is_quoted = matches!(third, Token::Word(w) if w.quote_style.is_some())
                || matches!(third, Token::SingleQuotedString(_) | Token::DoubleQuotedString(_));
            if is_introducer && third_is_quoted {
                return Err("Unicode-escaped identifiers and strings (U&\"…\") are not allowed on this SQL surface.".to_string());
            }
        }

        let meaningful: Vec<&Token> = tokens.iter().filter(|token| !matches!(token, Token::Whitespace(_))).collect();

        for (idx, token) in meaningful.iter().enumerate() {
            let Some(identifier) = contract_identifier_token(token) else {
                continue;
            };

            let ident = identifier.to_ascii_lowercase();
            let is_bare_word = matches!(token, Token::Word(_));
            let next_is_period = meaningful.get(idx + 1).is_some_and(|next| matches!(next, Token::Period));

            if self.blocked_schema_qualifiers.iter().any(|q| q == &ident) && next_is_period {
                return Err(introspection_blocked(identifier));
            }

            let next_is_open_paren = meaningful.get(idx + 1).is_some_and(|next| matches!(next, Token::LParen));

            if self.blocked_identifiers.iter().any(|b| b == &ident)
                || (next_is_open_paren && self.blocked_function_identifiers.iter().any(|b| b == &ident))
                || (is_bare_word && self.blocked_bare_identifiers.iter().any(|b| b == &ident))
                || self.blocked_identifier_prefixes.iter().any(|prefix| ident.starts_with(prefix.as_str()))
            {
                return Err(introspection_blocked(identifier));
            }
        }

        Ok(())
    }

    fn validate_read_only_query(&self, query: &Query) -> Result<(), String> {
        if !query.locks.is_empty() {
            return Err("SELECT ... FOR UPDATE/SHARE is not allowed".to_string());
        }

        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                self.validate_read_only_query(&cte.query)?;
            }
        }

        self.validate_read_only_set_expr(&query.body)
    }

    fn validate_read_only_set_expr(&self, expr: &SetExpr) -> Result<(), String> {
        match expr {
            SetExpr::Select(select) => self.validate_read_only_select(select),
            SetExpr::Query(query) => self.validate_read_only_query(query),
            SetExpr::SetOperation { left, right, .. } => {
                self.validate_read_only_set_expr(left)?;
                self.validate_read_only_set_expr(right)
            }
            SetExpr::Values(_) | SetExpr::Table(_) => Ok(()),
            SetExpr::Insert(stmt) | SetExpr::Update(stmt) => Err(format!(
                "data-modifying queries are not allowed (found {} inside a query)",
                statement_type_name(stmt)
            )),
        }
    }

    fn validate_read_only_select(&self, select: &Select) -> Result<(), String> {
        if select.into.is_some() {
            return Err("SELECT ... INTO is not allowed".to_string());
        }

        for table_with_joins in &select.from {
            self.validate_table_factor_surface(&table_with_joins.relation, false)?;
            for join in &table_with_joins.joins {
                self.validate_table_factor_surface(&join.relation, self.is_safe_lateral_function_join(join))?;
            }
        }

        Ok(())
    }

    fn validate_table_factor_surface(
        &self, factor: &TableFactor, allow_safe_lateral_function: bool,
    ) -> Result<(), String> {
        match factor {
            TableFactor::Table { name, args: Some(args), .. } => {
                self.validate_table_valued_function_call(name, Some(args), allow_safe_lateral_function)
            }
            TableFactor::Function { name, args, .. } => {
                self.validate_table_valued_function_call(name, None, allow_safe_lateral_function)?;
                self.validate_table_function_args(name, args)
            }
            TableFactor::TableFunction { .. } => Err(table_function_error("TABLE(...)")),
            TableFactor::UNNEST { .. } => Err(table_function_error("UNNEST")),
            TableFactor::JsonTable { .. } => Err(table_function_error("JSON_TABLE")),
            TableFactor::Derived { subquery, .. } => self.validate_read_only_query(subquery),
            TableFactor::NestedJoin { table_with_joins, .. } => self.validate_table_with_joins_surface(table_with_joins),
            TableFactor::Pivot { table, .. } | TableFactor::Unpivot { table, .. } => {
                self.validate_table_factor_surface(table, false)
            }
            TableFactor::MatchRecognize { table, .. } => self.validate_table_factor_surface(table, false),
            // A plain table reference (no arguments) is the only admissible
            // remaining shape; relation-name allowlisting, if any, is the
            // caller's job via the block lists and DDL grants.
            //
            // This match is deliberately exhaustive with no `_` arm: deny by
            // construction. If a future sqlparser release adds a TableFactor
            // variant, this stops compiling until a human decides how to
            // treat it — a new query shape can never be silently admitted.
            TableFactor::Table { args: None, .. } => Ok(()),
        }
    }

    fn validate_table_with_joins_surface(
        &self, table_with_joins: &sqlparser::ast::TableWithJoins,
    ) -> Result<(), String> {
        self.validate_table_factor_surface(&table_with_joins.relation, false)?;
        for join in &table_with_joins.joins {
            self.validate_table_factor_surface(&join.relation, self.is_safe_lateral_function_join(join))?;
        }
        Ok(())
    }

    fn validate_table_valued_function_call(
        &self, name: &ObjectName, args: Option<&TableFunctionArgs>, allow_safe_lateral_function: bool,
    ) -> Result<(), String> {
        if self.is_bounded_table_function(name)
            || (allow_safe_lateral_function && is_regexp_split_to_table_name(name))
            || (allow_safe_lateral_function && self.is_listed_safe_lateral(name))
        {
            if let Some(args) = args {
                if args.settings.is_some() {
                    return Err(format!(
                        "Table-valued function `{}` settings are not allowed on this SQL surface.",
                        name
                    ));
                }
                self.validate_table_function_args(name, &args.args)?;
            }
            return Ok(());
        }

        Err(table_function_error(&name.to_string()))
    }

    fn validate_table_function_args(&self, name: &ObjectName, args: &[FunctionArg]) -> Result<(), String> {
        for arg in args {
            let arg_expr = match arg {
                FunctionArg::Named { arg, .. } => arg,
                FunctionArg::Unnamed(arg) => arg,
            };

            let FunctionArgExpr::Expr(expr) = arg_expr else {
                return Err(format!(
                    "Table-valued function `{}` arguments may not use wildcard arguments on this SQL surface.",
                    name
                ));
            };

            if expression_contains_subquery(expr) {
                return Err(format!(
                    "Table-valued function `{}` arguments may not contain subqueries on this SQL surface.",
                    name
                ));
            }

            if self.expression_contains_set_returning_function(expr) {
                return Err(format!(
                    "Table-valued function `{}` arguments may not contain set-returning functions on this SQL surface.",
                    name
                ));
            }
        }

        Ok(())
    }

    fn is_bounded_table_function(&self, name: &ObjectName) -> bool {
        let rendered = qualified_lowercase(name);
        self.bounded_table_functions.iter().any(|f| f == &rendered)
    }

    fn is_listed_safe_lateral(&self, name: &ObjectName) -> bool {
        let rendered = qualified_lowercase(name);
        self.safe_lateral_functions.iter().any(|f| f == &rendered)
    }

    fn check_query_limit(&self, query: &Query) -> Result<(), String> {
        if let Some(offset) = &query.offset {
            check_offset_value(&offset.value, self.max_limit)?;
        }

        match &query.limit {
            None => {
                // Internally row-capped helper functions do not need a redundant
                // outer LIMIT, and obvious single-row aggregates (e.g. SELECT
                // COUNT(*)) are already bounded.
                if self.is_bounded_function_query(query)
                    || is_obviously_single_row_aggregate_query(query)
                    || self.is_no_from_scalar_query(query)
                {
                    Ok(())
                } else {
                    Err(format!(
                        "Query must have a LIMIT clause. Add 'LIMIT {}' or less to prevent runaway queries.",
                        self.max_limit
                    ))
                }
            }
            Some(limit_expr) => {
                // Extract literal value from LIMIT expression.
                // Non-literal limits (ALL, NULL, subqueries) bypass the limit.
                let limit_val = match limit_expr {
                    Expr::Value(Value::Number(n, _)) => n
                        .parse::<u64>()
                        .map_err(|_| format!("Invalid LIMIT value '{}'. LIMIT must be a positive integer.", n))?,
                    Expr::Value(Value::Null) => {
                        // LIMIT NULL = return all rows (bypass).
                        return Err("LIMIT NULL is not allowed. Use a numeric LIMIT value.".to_string());
                    }
                    Expr::Identifier(ident) if ident.value.eq_ignore_ascii_case("ALL") => {
                        return Err("LIMIT ALL is not allowed. Use a numeric LIMIT value.".to_string());
                    }
                    // Block subqueries, function calls, etc.
                    _ => {
                        return Err(format!(
                            "LIMIT must be a numeric literal (e.g., LIMIT 100). Found: {}. \
                             Expressions, subqueries, and special values are not allowed.",
                            limit_expr
                        ));
                    }
                };

                if limit_val > self.max_limit {
                    return Err(format!("LIMIT {} is too large. Maximum allowed is {}.", limit_val, self.max_limit));
                }

                Ok(())
            }
        }
    }

    fn check_query_offsets(&self, query: &Query) -> Result<(), String> {
        check_each_query(query, |q| match &q.offset {
            Some(offset) => check_offset_value(&offset.value, self.max_limit),
            None => Ok(()),
        })
    }

    fn check_bounded_nested_work(&self, query: &Query) -> Result<(), String> {
        // "Nested" means: not on the root's parenthesized-body spine. The root
        // query — and a body that is merely the root wrapped in parentheses
        // (`(SELECT ... ORDER BY x) LIMIT 5`) — is bounded by the outer LIMIT
        // gate; every other Query node (CTEs, set-operation branches, derived
        // tables, subqueries) must bound its own ORDER BY sort work.
        let mut top_spine: Vec<*const Query> = Vec::new();
        let mut spine_query = query;
        loop {
            top_spine.push(spine_query as *const Query);
            match spine_query.body.as_ref() {
                SetExpr::Query(inner) => spine_query = inner,
                _ => break,
            }
        }

        check_each_query(query, |q| {
            let nested = !top_spine.contains(&(q as *const Query));
            if nested && !q.order_by.as_ref().is_none_or(|order_by| order_by.exprs.is_empty()) {
                self.check_query_limit(q).map_err(|_| {
                    "Nested queries with ORDER BY must include their own bounded LIMIT. An outer LIMIT does not bound inner sort work.".to_string()
                })?;
            }
            Ok(())
        })
    }

    fn is_bounded_function_query(&self, query: &Query) -> bool {
        // Keep this narrowly-scoped. This is a security control, not a convenience parser.
        if query.with.is_some() || query.offset.is_some() || query.fetch.is_some() {
            return false;
        }

        let SetExpr::Select(select) = &*query.body else {
            return false;
        };

        if select.from.len() != 1 {
            return false;
        }

        let table_with_joins = &select.from[0];
        if !table_with_joins.joins.is_empty() {
            return false;
        }

        match &table_with_joins.relation {
            // Postgres table-valued functions parse as `Table { name, args: Some(..) }`.
            TableFactor::Table { name, args, .. } => args.is_some() && self.is_bounded_table_function(name),
            // Some dialect paths parse this as a "Function" table factor.
            TableFactor::Function { name, .. } => self.is_bounded_table_function(name),
            _ => false,
        }
    }

    fn is_no_from_scalar_query(&self, query: &Query) -> bool {
        if query.with.is_some() || query.offset.is_some() || query.fetch.is_some() {
            return false;
        }

        let SetExpr::Select(select) = query.body.as_ref() else {
            return false;
        };

        if !select.from.is_empty() || select.projection.is_empty() {
            return false;
        }

        let rendered = query.to_string().to_ascii_lowercase();
        if rendered.contains(" group by ")
            || rendered.contains(" having ")
            || rendered.contains(" over(")
            || rendered.contains(" over (")
        {
            return false;
        }

        select.projection.iter().all(|item| self.is_scalar_projection_item(item))
    }

    fn is_scalar_projection_item(&self, item: &SelectItem) -> bool {
        match item {
            SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                !expression_contains_subquery(expr) && !self.expression_contains_set_returning_function(expr)
            }
            SelectItem::QualifiedWildcard(_, _) | SelectItem::Wildcard(_) => false,
        }
    }

    fn expression_contains_set_returning_function(&self, expr: &Expr) -> bool {
        matches!(
            visit_expressions(expr, |expr| {
                if let Expr::Function(function) = expr {
                    if is_set_returning_expression_function_name(&function.name)
                        || self.is_bounded_table_function(&function.name)
                        || self.is_listed_set_returning(&function.name)
                    {
                        return ControlFlow::Break(());
                    }
                }
                ControlFlow::Continue(())
            }),
            ControlFlow::Break(())
        )
    }

    fn is_listed_set_returning(&self, name: &ObjectName) -> bool {
        let rendered = qualified_lowercase(name);
        self.set_returning_functions.iter().any(|f| f == &rendered)
    }

    /// A set-returning function in a SELECT list expands one input row into many
    /// output rows before any outer LIMIT or aggregate applies. In a derived
    /// table — `SELECT count(*) FROM (SELECT generate_series(1, 1e9) AS g) t` —
    /// the inner explosion happens even though the outer query looks bounded.
    /// SRFs are already refused as FROM relations; refuse them in projections
    /// too, at every nesting level the visitor reaches.
    fn check_projection_set_returning(&self, query: &Query) -> Result<(), String> {
        check_each_query(query, |q| {
            let SetExpr::Select(select) = q.body.as_ref() else {
                return Ok(());
            };
            for item in &select.projection {
                let expr = match item {
                    SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => expr,
                    _ => continue,
                };
                if self.expression_contains_set_returning_function(expr) {
                    return Err(
                        "Set-returning functions are not allowed in the SELECT list on this SQL \
                         surface; they can expand result cardinality without bound."
                            .to_string(),
                    );
                }
            }
            Ok(())
        })
    }

    // § cartesian products and tautological joins

    fn detect_cartesian_products(&self, query: &Query) -> Result<(), String> {
        // `check_each_query` visits every Query node in the tree — CTEs, derived
        // tables, set-operation branches, AND expression subqueries such as
        // `WHERE id IN (SELECT a.id FROM a CROSS JOIN b)`, which a FROM-only
        // recursion never reaches. Each Query's own FROM/join shape is checked
        // once here; nesting is handled by the visitor, not by re-descending.
        check_each_query(query, |q| self.detect_cartesian_in_set_expr(&q.body))
    }

    fn detect_cartesian_in_set_expr(&self, expr: &SetExpr) -> Result<(), String> {
        match expr {
            SetExpr::Select(select) => self.detect_cartesian_in_select(select),
            // Nested queries are reached by the visitor as their own nodes.
            SetExpr::SetOperation { left, right, .. } => {
                self.detect_cartesian_in_set_expr(left)?;
                self.detect_cartesian_in_set_expr(right)
            }
            _ => Ok(()),
        }
    }

    fn detect_cartesian_in_select(&self, select: &Select) -> Result<(), String> {
        for table_with_joins in &select.from {
            // A NestedJoin hides its joins inside the relation rather than as a
            // separate Query node, so its shape is still walked here; ordinary
            // derived tables are reached by the visitor.
            self.detect_cartesian_in_table_factor(&table_with_joins.relation)?;
            for join in &table_with_joins.joins {
                self.detect_cartesian_in_table_factor(&join.relation)?;
                if self.is_cartesian_join(join) {
                    let join_type = match &join.join_operator {
                        JoinOperator::CrossJoin => "CROSS JOIN",
                        JoinOperator::Inner(JoinConstraint::None) => "JOIN without ON clause",
                        JoinOperator::LeftOuter(JoinConstraint::None) => "LEFT JOIN without ON clause",
                        JoinOperator::RightOuter(JoinConstraint::None) => "RIGHT JOIN without ON clause",
                        JoinOperator::FullOuter(JoinConstraint::None) => "FULL JOIN without ON clause",
                        JoinOperator::Inner(JoinConstraint::Natural)
                        | JoinOperator::LeftOuter(JoinConstraint::Natural)
                        | JoinOperator::RightOuter(JoinConstraint::Natural)
                        | JoinOperator::FullOuter(JoinConstraint::Natural)
                        | JoinOperator::LeftSemi(JoinConstraint::Natural)
                        | JoinOperator::RightSemi(JoinConstraint::Natural)
                        | JoinOperator::LeftAnti(JoinConstraint::Natural)
                        | JoinOperator::RightAnti(JoinConstraint::Natural) => "NATURAL JOIN",
                        JoinOperator::Inner(JoinConstraint::On(expr))
                        | JoinOperator::LeftOuter(JoinConstraint::On(expr))
                        | JoinOperator::RightOuter(JoinConstraint::On(expr))
                        | JoinOperator::FullOuter(JoinConstraint::On(expr))
                        | JoinOperator::LeftSemi(JoinConstraint::On(expr))
                        | JoinOperator::RightSemi(JoinConstraint::On(expr))
                        | JoinOperator::LeftAnti(JoinConstraint::On(expr))
                        | JoinOperator::RightAnti(JoinConstraint::On(expr))
                            if is_tautological_join_expr(expr) =>
                        {
                            "JOIN with tautological ON condition"
                        }
                        _ => "cartesian product",
                    };
                    return Err(format!(
                        "Potential cartesian product detected: {}. This join shape is not allowed on this SQL surface because it can explode result cardinality. Rewrite with an explicit ON clause or another bounded relational shape.",
                        join_type
                    ));
                }
            }
        }

        if select.from.len() > 1 {
            return Err("Multiple tables in FROM clause without explicit JOIN. \
             Use explicit JOIN syntax with ON clauses instead of comma-separated tables. \
             Example: 'FROM a JOIN b ON a.id = b.a_id' instead of 'FROM a, b WHERE a.id = b.a_id'"
                .to_string());
        }

        Ok(())
    }

    fn detect_cartesian_in_table_factor(&self, factor: &TableFactor) -> Result<(), String> {
        match factor {
            // A Derived subquery is its own Query node; the visitor reaches it.
            // Only NestedJoin hides join shapes that are not separate nodes.
            TableFactor::NestedJoin { table_with_joins, .. } => {
                self.detect_cartesian_in_table_factor(&table_with_joins.relation)?;
                for join in &table_with_joins.joins {
                    self.detect_cartesian_in_table_factor(&join.relation)?;
                    if self.is_cartesian_join(join) {
                        return Err("Potential cartesian product detected inside nested join.".to_string());
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn is_cartesian_join(&self, join: &Join) -> bool {
        if self.is_safe_lateral_function_join(join) {
            return false;
        }

        match &join.join_operator {
            JoinOperator::CrossJoin | JoinOperator::CrossApply | JoinOperator::OuterApply => true,
            JoinOperator::Inner(constraint)
            | JoinOperator::LeftOuter(constraint)
            | JoinOperator::RightOuter(constraint)
            | JoinOperator::FullOuter(constraint)
            | JoinOperator::LeftSemi(constraint)
            | JoinOperator::RightSemi(constraint)
            | JoinOperator::LeftAnti(constraint)
            | JoinOperator::RightAnti(constraint) => is_unbounded_join_constraint(constraint),
            JoinOperator::AsOf { constraint, .. } => is_unbounded_join_constraint(constraint),
        }
    }

    fn is_safe_lateral_function_join(&self, join: &Join) -> bool {
        if !matches!(&join.join_operator, JoinOperator::CrossJoin) {
            return false;
        }

        match &join.relation {
            TableFactor::Function { name, lateral, .. } => {
                *lateral && (is_regexp_split_to_table_name(name) || self.is_listed_safe_lateral(name))
            }
            TableFactor::Table { name, args, .. } => {
                args.is_some() && (is_regexp_split_to_table_name(name) || self.is_listed_safe_lateral(name))
            }
            _ => false,
        }
    }
}

fn refused(statement_index: usize, what: &str) -> String {
    format!("Statement {}: {} is not allowed. Only SELECT queries are permitted.", statement_index + 1, what)
}

fn introspection_blocked(identifier: &str) -> String {
    format!("Postgres introspection blocked. `{}` is not available on this SQL surface.", identifier)
}

fn table_function_error(name: &str) -> String {
    format!("Table-valued function `{}` is not allowed on this SQL surface.", name)
}

fn contract_identifier_token(token: &Token) -> Option<&str> {
    match token {
        Token::Word(word) => Some(word.value.as_str()),
        // PostgreSQL double quotes are delimited identifiers, not string literals.
        // Treat them exactly like bare words so `"pg_catalog"."pg_class"` and
        // `"pg_sleep"()` cannot bypass the surface contract.
        Token::DoubleQuotedString(value) => Some(value.as_str()),
        _ => None,
    }
}

fn qualified_lowercase(name: &ObjectName) -> String {
    name.0.iter().map(|part| part.value.to_ascii_lowercase()).collect::<Vec<_>>().join(".")
}

fn is_regexp_split_to_table_name(name: &ObjectName) -> bool {
    name.0.last().is_some_and(|last| last.value.eq_ignore_ascii_case("regexp_split_to_table"))
}

fn statement_type_name(stmt: &Statement) -> &'static str {
    match stmt {
        Statement::Query(_) => "SELECT",
        Statement::Insert(_) => "INSERT",
        Statement::Update { .. } => "UPDATE",
        Statement::Delete(_) => "DELETE",
        Statement::Drop { .. } => "DROP",
        Statement::Truncate { .. } => "TRUNCATE",
        Statement::Grant { .. } => "GRANT",
        Statement::Revoke { .. } => "REVOKE",
        Statement::Copy { .. } => "COPY",
        Statement::Explain { .. } => "EXPLAIN",
        _ => "Unknown statement type",
    }
}

// § aggregate alias law

pub const AGGREGATE_ALIAS_ERROR: &str = "Alias the aggregate: count() AS n.";

fn aggregate_combinator_suffix(mut suffix: &str) -> bool {
    const COMBINATORS: &[&str] = &[
        "simplestate", "mergestate", "ordefault", "distinct", "resample", "foreach", "ornull", "state", "merge",
        "array", "map", "if",
    ];
    if suffix.is_empty() {
        return true;
    }
    while !suffix.is_empty() {
        let Some(combinator) = COMBINATORS.iter().find(|combinator| suffix.starts_with(**combinator)) else {
            return false;
        };
        suffix = &suffix[combinator.len()..];
    }
    true
}

fn is_aggregate_function_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "any_value"
            | "anyheavy"
            | "anylast"
            | "array_agg"
            | "avgweighted"
            | "bit_and"
            | "bit_or"
            | "bool_and"
            | "bool_or"
            | "corr"
            | "every"
            | "json_agg"
            | "json_object_agg"
            | "jsonb_agg"
            | "jsonb_object_agg"
            | "mode"
            | "string_agg"
            | "variance"
            | "var_pop"
            | "var_samp"
            | "varpop"
            | "varsamp"
            | "xmlagg"
    ) {
        return true;
    }
    if ["grouparray", "groupbitmap", "groupuniqarray", "median", "percentile", "quantile", "stddev", "topk", "uniq"]
        .iter()
        .any(|family| name.starts_with(family))
        || ["covar", "regr"].iter().any(|family| name.starts_with(family))
    {
        return true;
    }
    ["any", "argmax", "argmin", "avg", "count", "max", "min", "sum"]
        .iter()
        .find_map(|base| name.strip_prefix(base))
        .is_some_and(aggregate_combinator_suffix)
}

/// Refuse aggregate-shaped public output names before execution. Aliases on
/// inner implementation queries are not required; only the result-defining
/// projection is public.
pub fn validate_aggregate_aliases(query: &Query) -> Result<(), String> {
    fn output_select(expr: &SetExpr) -> Option<&Select> {
        match expr {
            SetExpr::Select(select) => Some(select),
            SetExpr::Query(query) => output_select(&query.body),
            SetExpr::SetOperation { left, .. } => output_select(left),
            SetExpr::Values(_) | SetExpr::Table(_) | SetExpr::Insert(_) | SetExpr::Update(_) => None,
        }
    }

    let Some(select) = output_select(&query.body) else {
        return Ok(());
    };
    for item in &select.projection {
        if let SelectItem::UnnamedExpr(expr) = item {
            let aggregate = visit_expressions(expr, |expr| {
                let Expr::Function(function) = expr else {
                    return ControlFlow::Continue(());
                };
                let Some(name) = function.name.0.last() else {
                    return ControlFlow::Continue(());
                };
                if is_aggregate_function_name(&name.value) { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
            });
            if matches!(aggregate, ControlFlow::Break(())) {
                return Err(AGGREGATE_ALIAS_ERROR.to_string());
            }
        }
    }
    Ok(())
}

// § query shape hashing

/// Build a stable literal-scrubbed hash for grouping similar query shapes.
///
/// This is intentionally lighter-weight than PostgreSQL's `queryid`: it uses
/// the parsed AST when possible, replaces literal leaves with placeholders,
/// renders the statements back to canonical SQL, and hashes the result with
/// blake3. When parsing fails, it falls back to whitespace-normalized raw SQL
/// so the caller still gets a stable string for logging and offline cohort
/// analysis.
pub fn query_shape_hash(sql: &str) -> String {
    blake3::hash(normalize_query_shape(sql).as_bytes()).to_hex().to_string()
}

fn normalize_query_shape(sql: &str) -> String {
    let dialect = PostgreSqlDialect {};
    let mut statements = match Parser::parse_sql(&dialect, sql) {
        Ok(statements) => statements,
        Err(_) => return sql.split_whitespace().collect::<Vec<_>>().join(" "),
    };

    let _ = visit_expressions_mut(&mut statements, |expr| {
        scrub_literal_expression(expr);
        ControlFlow::<()>::Continue(())
    });

    statements.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
}

fn scrub_literal_expression(expr: &mut Expr) {
    match expr {
        Expr::Value(value) => *value = Value::Placeholder("?".to_string()),
        Expr::IntroducedString { value, .. } => *value = Value::Placeholder("?".to_string()),
        Expr::TypedString { value, .. } => *value = "?".to_string(),
        _ => {}
    }
}

// § shared literal-bound gates

/// The one OFFSET law: a literal, non-negative integer within the bound.
/// Shared by the LIMIT gate (root query) and the every-query offsets gate.
fn check_offset_value(value: &Expr, max_offset: u64) -> Result<(), String> {
    let offset_val = match value {
        Expr::Value(Value::Number(n, _)) => n
            .parse::<u64>()
            .map_err(|_| format!("Invalid OFFSET value '{}'. OFFSET must be a non-negative integer.", n))?,
        Expr::Value(Value::Null) => {
            return Err("OFFSET NULL is not allowed. Use a numeric OFFSET value.".to_string());
        }
        _ => {
            return Err(format!(
                "OFFSET must be a numeric literal (e.g., OFFSET 100). Found: {}. \
                 Expressions, subqueries, and special values are not allowed.",
                value
            ));
        }
    };

    if offset_val > max_offset {
        return Err(format!("OFFSET {} is too large. Maximum allowed is {}.", offset_val, max_offset));
    }

    Ok(())
}

// § every-query gates: one derived-Visitor spine, one per-Query action per gate.
//
// sqlparser's derived `Visit` fires `pre_visit_query` for EVERY `Query` node an
// AST can carry — CTEs, set-operation branches, derived tables, scalar/EXISTS/IN
// subqueries, ORDER BY expressions, join ON constraints, LIMIT BY, window specs —
// so a gate riding it is structurally incapable of missing a new AST variant.
// The per-Query actions stay distinct laws per gate; only the spine is shared.

struct QueryGate<F: FnMut(&Query) -> Result<(), String>> {
    action: F,
    err: Option<String>,
}

impl<F: FnMut(&Query) -> Result<(), String>> Visitor for QueryGate<F> {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        match (self.action)(query) {
            Ok(()) => ControlFlow::Continue(()),
            Err(e) => {
                self.err = Some(e);
                ControlFlow::Break(())
            }
        }
    }
}

/// Apply `action` to `query` and every `Query` node nested anywhere inside it
/// (depth-first pre-order), stopping at the first error.
fn check_each_query(query: &Query, action: impl FnMut(&Query) -> Result<(), String>) -> Result<(), String> {
    let mut gate = QueryGate { action, err: None };
    match query.visit(&mut gate) {
        ControlFlow::Break(()) => Err(gate.err.unwrap_or_else(|| "Query gate failed".to_string())),
        ControlFlow::Continue(()) => Ok(()),
    }
}

// § bounded-cardinality classifiers

fn is_obviously_single_row_aggregate_query(query: &Query) -> bool {
    if query.with.is_some() || query.offset.is_some() || query.fetch.is_some() {
        return false;
    }

    let SetExpr::Select(select) = query.body.as_ref() else {
        return false;
    };

    if select.projection.len() != 1 {
        return false;
    }

    let rendered = query.to_string().to_ascii_lowercase();
    if rendered.contains("group by")
        || rendered.contains("having")
        || rendered.contains(" over(")
        || rendered.contains(" over (")
    {
        return false;
    }

    match &select.projection[0] {
        SelectItem::UnnamedExpr(expr) => is_top_level_count_aggregate(expr),
        SelectItem::ExprWithAlias { expr, .. } => is_top_level_count_aggregate(expr),
        _ => false,
    }
}

fn is_top_level_count_aggregate(expr: &Expr) -> bool {
    match expr {
        Expr::Function(function) => function.name.to_string().eq_ignore_ascii_case("count"),
        _ => false,
    }
}

fn expression_contains_subquery(expr: &Expr) -> bool {
    matches!(
        visit_expressions(expr, |expr| {
            if matches!(
                expr,
                Expr::Subquery(_)
                    | Expr::Exists { .. }
                    | Expr::InSubquery { .. }
                    | Expr::AnyOp { .. }
                    | Expr::AllOp { .. }
            ) {
                ControlFlow::Break(())
            } else if let Expr::Function(function) = expr {
                if function_arguments_contains_subquery(&function.parameters)
                    || function_arguments_contains_subquery(&function.args)
                {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            } else {
                ControlFlow::Continue(())
            }
        }),
        ControlFlow::Break(())
    )
}

fn function_arguments_contains_subquery(args: &FunctionArguments) -> bool {
    match args {
        FunctionArguments::None => false,
        FunctionArguments::Subquery(_) => true,
        FunctionArguments::List(args) => {
            args.args.iter().any(function_arg_contains_subquery)
                || args.clauses.iter().any(function_clause_contains_subquery)
        }
    }
}

fn function_arg_contains_subquery(arg: &FunctionArg) -> bool {
    let arg = match arg {
        FunctionArg::Named { arg, .. } | FunctionArg::Unnamed(arg) => arg,
    };

    match arg {
        FunctionArgExpr::Expr(expr) => expression_contains_subquery(expr),
        FunctionArgExpr::QualifiedWildcard(_) | FunctionArgExpr::Wildcard => false,
    }
}

fn function_clause_contains_subquery(clause: &FunctionArgumentClause) -> bool {
    match clause {
        FunctionArgumentClause::OrderBy(order_by) => {
            order_by.iter().any(|order_by| expression_contains_subquery(&order_by.expr))
        }
        FunctionArgumentClause::Limit(expr) => expression_contains_subquery(expr),
        FunctionArgumentClause::Having(bound) => expression_contains_subquery(&bound.1),
        FunctionArgumentClause::OnOverflow(sqlparser::ast::ListAggOnOverflow::Truncate { filler: Some(filler), .. }) => {
            expression_contains_subquery(filler)
        }
        FunctionArgumentClause::IgnoreOrRespectNulls(_)
        | FunctionArgumentClause::OnOverflow(_)
        | FunctionArgumentClause::Separator(_) => false,
    }
}

fn is_set_returning_expression_function_name(name: &ObjectName) -> bool {
    let Some(last) = name.0.last() else {
        return false;
    };

    [
        "generate_series",
        "generate_subscripts",
        "unnest",
        "regexp_matches",
        "regexp_split_to_table",
        "json_each",
        "json_each_text",
        "json_object_keys",
        "json_array_elements",
        "json_array_elements_text",
        "jsonb_each",
        "jsonb_each_text",
        "jsonb_object_keys",
        "jsonb_array_elements",
        "jsonb_array_elements_text",
    ]
    .iter()
    .any(|function_name| last.value.eq_ignore_ascii_case(function_name))
}

// § join-constraint laws

fn is_unbounded_join_constraint(constraint: &JoinConstraint) -> bool {
    match constraint {
        JoinConstraint::None | JoinConstraint::Natural => true,
        JoinConstraint::On(expr) => is_tautological_join_expr(expr),
        JoinConstraint::Using(_) => false,
    }
}

fn is_tautological_join_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Nested(inner) => is_tautological_join_expr(inner),
        Expr::Value(Value::Boolean(true)) => true,
        Expr::BinaryOp { left, op, right } => match op {
            BinaryOperator::And => is_tautological_join_expr(left) && is_tautological_join_expr(right),
            BinaryOperator::Or => is_tautological_join_expr(left) || is_tautological_join_expr(right),
            // `a.id = a.id` (any expression equal to itself) constrains nothing:
            // every row pair satisfies it, so the join is still a cartesian
            // product. Also catch equal literals like `1 = 1`.
            BinaryOperator::Eq => {
                left == right
                    || matches!(
                        (literal_expr_fingerprint(left), literal_expr_fingerprint(right)),
                        (Some(lhs), Some(rhs)) if lhs == rhs
                    )
            }
            _ => false,
        },
        _ => false,
    }
}

fn literal_expr_fingerprint(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Nested(inner) => literal_expr_fingerprint(inner),
        Expr::Value(value) => Some(format!("value:{value}")),
        Expr::IntroducedString { introducer, value } => {
            Some(format!("introduced:{}:{value}", introducer.to_ascii_lowercase()))
        }
        Expr::TypedString { data_type, value } => {
            Some(format!("typed:{}:{}", data_type.to_string().to_ascii_lowercase(), value))
        }
        _ => None,
    }
}

// § parse-error humanization

/// Map sqlparser errors to messages a caller can act on.
pub fn humanize_parse_error(err: ParserError, sql: &str) -> String {
    let err_str = err.to_string();

    if err_str.contains("Expected end of statement") {
        return format!("Syntax error: {}. Check for missing semicolons or unexpected characters.", err_str);
    }

    if err_str.contains("Expected SELECT") || err_str.contains("Expected: SELECT") {
        return "Query must start with SELECT (or WITH for CTEs).".to_string();
    }

    if err_str.contains("Expected identifier") {
        return format!("{}. Check for missing table/column names or typos in keywords.", err_str);
    }

    if err_str.contains("Unterminated string") {
        return "Unterminated string literal. Check for missing closing quote (').".to_string();
    }

    if err_str.contains("Expected: )") || err_str.contains("Expected )") {
        return format!("{}. Check for unbalanced parentheses.", err_str);
    }

    let sql_lower = sql.to_lowercase();
    if sql_lower.contains("form ") && !sql_lower.contains("from ") {
        return format!("{}. Did you mean 'FROM' instead of 'FORM'?", err_str);
    }
    if sql_lower.contains("wher ") || sql_lower.contains("wehre ") {
        return format!("{}. Did you mean 'WHERE'?", err_str);
    }
    if sql_lower.contains("slect ") || sql_lower.contains("selct ") {
        return format!("{}. Did you mean 'SELECT'?", err_str);
    }

    format!("SQL parse error: {}", err_str)
}

#[cfg(test)]
mod tests {
    use super::{query_shape_hash, Policy};

    fn validate(sql: &str) -> Result<(), String> {
        Policy::default().validate(sql)
    }

    #[test]
    fn test_valid_select() {
        assert!(validate("SELECT * FROM users LIMIT 10").is_ok());
    }

    #[test]
    fn test_requires_limit() {
        assert!(validate("SELECT * FROM users").is_err());
    }

    #[test]
    fn test_blocks_multi_statement_injection() {
        // Semicolon injection: valid SELECT followed by DROP.
        let sql = "SELECT 1 LIMIT 1; DROP TABLE users";
        assert!(validate(sql).is_err());
    }

    #[test]
    fn test_blocks_catalog_introspection() {
        let err = validate("SELECT * FROM information_schema.columns LIMIT 10")
            .expect_err("information_schema should be blocked");
        assert!(err.contains("Postgres introspection blocked"));

        let err = validate("SELECT * FROM pg_views LIMIT 10").expect_err("pg_views blocked");
        assert!(err.contains("Postgres introspection blocked"));
    }

    #[test]
    fn test_blocks_select_callable_side_effect_helpers() {
        for sql in [
            "SELECT binary_upgrade_set_next_pg_authid_oid(1::oid) LIMIT 1",
            "SELECT lo_create(12345) LIMIT 1",
            "SELECT nextval('some_sequence') LIMIT 1",
            "SELECT dblink_connect('dbname=postgres') LIMIT 1",
            "SELECT * FROM ts_stat('SELECT to_tsvector(''simple'', content_text) FROM entities') LIMIT 1",
            "SELECT ts_rewrite(to_tsquery('a'), $$SELECT to_tsquery('a'), to_tsquery('b')$$) LIMIT 1",
        ] {
            let err = validate(sql).expect_err("side-effect helper should be blocked");
            assert!(err.contains("Postgres introspection blocked"), "unexpected error for {sql}: {err}");
        }
    }

    #[test]
    fn query_shape_hash_scrubs_literal_variance() {
        let a = query_shape_hash("SELECT * FROM entities WHERE id = 42 AND title = 'alpha' LIMIT 10");
        let b = query_shape_hash(" select  *  from entities where id = 99 and title = 'beta' limit 25 ");
        assert_eq!(a, b);
    }
}
