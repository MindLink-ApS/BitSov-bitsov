//! Catalog comparison for the tables that must match across SQLite and Postgres.
//!
//! Integer width is not part of [`TypeKind`]: SQLite `INTEGER` stores 64-bit
//! values, while Postgres `INTEGER` is signed 32-bit. `fits_u32` records whether
//! a column can hold `u32::MAX`.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TypeKind {
    Int,
    Float,
    Text,
    Bytes,
    Bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Column {
    name: String,
    not_null: bool,
    kind: TypeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TableCatalog {
    columns: BTreeSet<Column>,
    primary_key: Vec<String>,
    uniques: BTreeSet<Vec<String>>,
    checks: BTreeSet<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParityCatalog {
    tables: BTreeMap<String, TableCatalog>,
    fits_u32: BTreeMap<String, bool>,
}

#[derive(Clone, Copy)]
enum Backend {
    Sqlite,
    Postgres,
}

const TABLES: &[&str] = &[
    "calendar_events",
    "calendar_rsvps",
    "contacts",
    "fiat_rate_snapshots",
    "invites_issued",
    "onboarding_state",
    "recovery_schemes",
    "recovery_shards",
    "recovery_trustees",
];

pub(crate) fn assert_parity(actual: &ParityCatalog) {
    let expected = expected_catalog();
    assert_eq!(
        actual.tables, expected,
        "schema catalog mismatch\nactual={:#?}\nexpected={:#?}",
        actual.tables, expected
    );
    assert!(
        actual
            .fits_u32
            .get("onboarding_state.funding_amount_sats_received")
            .copied()
            .unwrap_or(false),
        "onboarding_state.funding_amount_sats_received must store the full u32 range"
    );
}

pub(crate) async fn load_sqlite(pool: &sqlx::SqlitePool) -> ParityCatalog {
    let mut tables = BTreeMap::new();
    let mut fits_u32 = BTreeMap::new();
    for table in TABLES {
        let (catalog, fits) = sqlite_table(pool, table).await;
        for (column, fits_value) in fits {
            fits_u32.insert(format!("{table}.{column}"), fits_value);
        }
        tables.insert((*table).to_string(), catalog);
    }
    ParityCatalog { tables, fits_u32 }
}

pub(crate) async fn load_postgres(pool: &sqlx::PgPool) -> ParityCatalog {
    let mut tables = BTreeMap::new();
    let mut fits_u32 = BTreeMap::new();
    for table in TABLES {
        let (catalog, fits) = postgres_table(pool, table).await;
        for (column, fits_value) in fits {
            fits_u32.insert(format!("{table}.{column}"), fits_value);
        }
        tables.insert((*table).to_string(), catalog);
    }
    ParityCatalog { tables, fits_u32 }
}

fn ident(name: &str) -> String {
    assert!(
        name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "unexpected identifier {name}"
    );
    name.to_string()
}

async fn sqlite_table(pool: &sqlx::SqlitePool, table: &str) -> (TableCatalog, Vec<(String, bool)>) {
    let table = ident(table);
    let info: Vec<(String, String, i64, i64)> = sqlx::query_as(&format!(
        "SELECT name, type, \"notnull\", pk FROM pragma_table_info('{table}')"
    ))
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| panic!("pragma_table_info {table}: {e}"));
    assert!(!info.is_empty(), "missing sqlite table {table}");

    let mut pk_cols: Vec<(i64, String)> = Vec::new();
    let mut columns = BTreeSet::new();
    let mut fits = Vec::new();
    for (name, decl, notnull, pk) in info {
        if pk > 0 {
            pk_cols.push((pk, name.clone()));
        }
        columns.insert(Column {
            name: name.clone(),
            not_null: notnull != 0 || pk > 0,
            kind: type_kind(&decl),
        });
        fits.push((name, fits_u32(Backend::Sqlite, &decl)));
    }
    pk_cols.sort_by_key(|(ord, _)| *ord);
    let primary_key: Vec<String> = pk_cols.into_iter().map(|(_, name)| name).collect();

    let indexes: Vec<(String, i64, String, i64)> = sqlx::query_as(&format!(
        "SELECT name, \"unique\", origin, partial FROM pragma_index_list('{table}')"
    ))
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| panic!("pragma_index_list {table}: {e}"));

    let mut uniques = BTreeSet::new();
    for (index, unique, origin, partial) in indexes {
        if unique == 0 || partial != 0 || origin == "pk" {
            continue;
        }
        let index = ident(&index);
        let mut cols: Vec<(i64, String)> = sqlx::query_as(&format!(
            "SELECT seqno, name FROM pragma_index_info('{index}')"
        ))
        .fetch_all(pool)
        .await
        .unwrap_or_else(|e| panic!("pragma_index_info {index}: {e}"));
        cols.sort_by_key(|(seq, _)| *seq);
        let mut names: Vec<String> = cols.into_iter().map(|(_, name)| name).collect();
        names.sort();
        if names == primary_key_sorted(&primary_key) {
            continue;
        }
        uniques.insert(names);
    }

    let create_sql: Option<String> =
        sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?")
            .bind(&table)
            .fetch_optional(pool)
            .await
            .unwrap_or_else(|e| panic!("sqlite_master {table}: {e}"));
    let checks = extract_checks(create_sql.as_deref().unwrap_or(""));
    (
        TableCatalog {
            columns,
            primary_key,
            uniques,
            checks,
        },
        fits,
    )
}

async fn postgres_table(pool: &sqlx::PgPool, table: &str) -> (TableCatalog, Vec<(String, bool)>) {
    let info: Vec<(String, bool, String, i32)> = sqlx::query_as(
        "SELECT a.attname, a.attnotnull, format_type(a.atttypid, a.atttypmod),
                COALESCE((
                    SELECT k.ord::int
                    FROM pg_index i
                    JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord)
                      ON k.attnum = a.attnum
                    WHERE i.indrelid = a.attrelid AND i.indisprimary
                ), 0)
         FROM pg_attribute a
         JOIN pg_class t ON t.oid = a.attrelid
         JOIN pg_namespace n ON n.oid = t.relnamespace
         WHERE n.nspname = current_schema()
           AND t.relname = $1
           AND a.attnum > 0
           AND NOT a.attisdropped
         ORDER BY a.attnum",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| panic!("postgres columns {table}: {e}"));
    assert!(!info.is_empty(), "missing postgres table {table}");

    let mut pk_cols: Vec<(i32, String)> = Vec::new();
    let mut columns = BTreeSet::new();
    let mut fits = Vec::new();
    for (name, notnull, decl, pk) in info {
        if pk > 0 {
            pk_cols.push((pk, name.clone()));
        }
        columns.insert(Column {
            name: name.clone(),
            not_null: notnull || pk > 0,
            kind: type_kind(&decl),
        });
        fits.push((name, fits_u32(Backend::Postgres, &decl)));
    }
    pk_cols.sort_by_key(|(ord, _)| *ord);
    let primary_key: Vec<String> = pk_cols.into_iter().map(|(_, name)| name).collect();

    let index_cols: Vec<(String, i32, String)> = sqlx::query_as(
        "SELECT ix.indexrelid::text, k.ord::int, a.attname
         FROM pg_index ix
         JOIN pg_class t ON t.oid = ix.indrelid
         JOIN pg_namespace n ON n.oid = t.relnamespace
         JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord) ON true
         JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
         WHERE n.nspname = current_schema()
           AND t.relname = $1
           AND ix.indisunique
           AND NOT ix.indisprimary
           AND ix.indpred IS NULL
           AND k.attnum > 0
         ORDER BY ix.indexrelid, k.ord",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| panic!("postgres uniques {table}: {e}"));

    let mut grouped: BTreeMap<String, Vec<(i32, String)>> = BTreeMap::new();
    for (index, ord, name) in index_cols {
        grouped.entry(index).or_default().push((ord, name));
    }
    let mut uniques = BTreeSet::new();
    for cols in grouped.into_values() {
        let mut names: Vec<String> = cols.into_iter().map(|(_, name)| name).collect();
        names.sort();
        if names == primary_key_sorted(&primary_key) {
            continue;
        }
        uniques.insert(names);
    }

    let defs: Vec<String> = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(c.oid)
         FROM pg_constraint c
         JOIN pg_class t ON t.oid = c.conrelid
         JOIN pg_namespace n ON n.oid = t.relnamespace
         WHERE n.nspname = current_schema()
           AND t.relname = $1
           AND c.contype = 'c'",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| panic!("postgres checks {table}: {e}"));
    let mut checks = BTreeSet::new();
    for def in defs {
        checks.extend(extract_checks(&def));
    }

    (
        TableCatalog {
            columns,
            primary_key,
            uniques,
            checks,
        },
        fits,
    )
}

fn primary_key_sorted(primary_key: &[String]) -> Vec<String> {
    let mut names = primary_key.to_vec();
    names.sort();
    names
}

fn type_kind(decl: &str) -> TypeKind {
    let d = decl.to_ascii_lowercase();
    if d.contains("bool") {
        TypeKind::Bool
    } else if d.contains("double") || d.contains("real") || d.contains("floa") {
        TypeKind::Float
    } else if d.contains("int") {
        TypeKind::Int
    } else if d.contains("blob") || d.contains("bytea") {
        TypeKind::Bytes
    } else if d.contains("char") || d.contains("clob") || d.contains("text") {
        TypeKind::Text
    } else {
        panic!("unrecognized sql type {decl}");
    }
}

fn fits_u32(backend: Backend, decl: &str) -> bool {
    if type_kind(decl) != TypeKind::Int {
        return false;
    }
    match backend {
        Backend::Sqlite => true,
        Backend::Postgres => {
            let d = decl.to_ascii_lowercase();
            d.contains("bigint") || d.contains("int8")
        }
    }
}

fn extract_checks(sql: &str) -> BTreeSet<String> {
    let lower = sql.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut checks = BTreeSet::new();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        if !lower.is_char_boundary(i) {
            i += 1;
            continue;
        }
        let boundary = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if boundary && &lower[i..i + 5] == "check" {
            let mut j = i + 5;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                if let Some(end) = matching_paren(&lower, j) {
                    checks.insert(normalize_check_body(&lower[j + 1..end]));
                    i = end + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    checks
}

fn matching_paren(sql: &str, open: usize) -> Option<usize> {
    let bytes = sql.as_bytes();
    let mut depth = 0i32;
    for (offset, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn normalize_check_body(body: &str) -> String {
    let mut stripped = String::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b':' && i + 1 < bytes.len() && bytes[i + 1] == b':' {
            i += 2;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            continue;
        }
        stripped.push(bytes[i] as char);
        i += 1;
    }
    let compact: String = stripped.chars().filter(|c| !c.is_whitespace()).collect();
    let compact = compact.replace("=any(array[", "in(");
    let compact = compact.replace(']', "");
    let compact = compact.replace(['\'', '"'], "");
    let compact = strip_wrapping_parens(&compact);
    let sorted = sort_in_lists(&compact);
    strip_wrapping_parens(&sorted)
}

fn strip_wrapping_parens(value: &str) -> String {
    let mut current = value.to_string();
    while current.starts_with('(') && current.ends_with(')') && wraps_entire(&current) {
        current = current[1..current.len() - 1].to_string();
    }
    current
}

fn wraps_entire(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'(') {
        return false;
    }
    let mut depth = 0i32;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return index + 1 == bytes.len();
                }
            }
            _ => {}
        }
    }
    false
}

fn sort_in_lists(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if !value.is_char_boundary(i) {
            i += 1;
            continue;
        }
        // `statein(...)` has no word boundary before `in(`.
        if i + 3 <= bytes.len() && &value[i..i + 3] == "in(" {
            if let Some(end) = matching_paren(value, i + 2) {
                let mut parts: Vec<&str> = value[i + 3..end]
                    .split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .collect();
                parts.sort_unstable();
                out.push_str("in(");
                out.push_str(&parts.join(","));
                out.push(')');
                i = end + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn expected_catalog() -> BTreeMap<String, TableCatalog> {
    let mut tables = BTreeMap::new();
    tables.insert("fiat_rate_snapshots".into(), fiat_table());
    tables.insert("recovery_schemes".into(), recovery_schemes_table());
    tables.insert("recovery_trustees".into(), recovery_trustees_table());
    tables.insert("recovery_shards".into(), recovery_shards_table());
    tables.insert("contacts".into(), contacts_table());
    tables.insert("calendar_events".into(), calendar_events_table());
    tables.insert("calendar_rsvps".into(), calendar_rsvps_table());
    tables.insert("invites_issued".into(), invites_table());
    tables.insert("onboarding_state".into(), onboarding_table());
    tables
}

fn table(
    columns: Vec<Column>,
    primary_key: &[&str],
    uniques: &[&[&str]],
    checks: &[&str],
) -> TableCatalog {
    TableCatalog {
        columns: columns.into_iter().collect(),
        primary_key: primary_key.iter().map(|name| (*name).to_string()).collect(),
        uniques: uniques
            .iter()
            .map(|cols| {
                let mut names: Vec<String> = cols.iter().map(|name| (*name).to_string()).collect();
                names.sort();
                names
            })
            .collect(),
        checks: checks
            .iter()
            .map(|expr| normalize_check_body(&expr.to_ascii_lowercase()))
            .collect(),
    }
}

fn col(name: &str, not_null: bool, kind: TypeKind) -> Column {
    Column {
        name: name.to_string(),
        not_null,
        kind,
    }
}

fn fiat_table() -> TableCatalog {
    table(
        vec![
            col("date", true, TypeKind::Text),
            col("currency", true, TypeKind::Text),
            col("rate", true, TypeKind::Float),
            col("source", true, TypeKind::Text),
            col("created_at", true, TypeKind::Text),
        ],
        &["date", "currency"],
        &[],
        &[],
    )
}

fn recovery_schemes_table() -> TableCatalog {
    table(
        vec![
            col("id", true, TypeKind::Text),
            col("scheme_type", true, TypeKind::Text),
            col("threshold", true, TypeKind::Int),
            col("total_shares", true, TypeKind::Int),
            col("metadata_json", true, TypeKind::Text),
            col("created_at", true, TypeKind::Text),
            col("updated_at", true, TypeKind::Text),
        ],
        &["id"],
        &[],
        &["threshold > 0", "total_shares >= threshold"],
    )
}

fn recovery_trustees_table() -> TableCatalog {
    table(
        vec![
            col("id", true, TypeKind::Text),
            col("scheme_id", true, TypeKind::Text),
            col("trustee_node_id", true, TypeKind::Text),
            col("share_index", true, TypeKind::Int),
            col("shard_commitment", false, TypeKind::Text),
            col("delivered_at", false, TypeKind::Text),
            col("created_at", true, TypeKind::Text),
        ],
        &["id"],
        &[
            &["scheme_id", "trustee_node_id"],
            &["scheme_id", "share_index"],
        ],
        &[],
    )
}

fn recovery_shards_table() -> TableCatalog {
    table(
        vec![
            col("id", true, TypeKind::Text),
            col("owner_node_id", true, TypeKind::Text),
            col("share_index", true, TypeKind::Int),
            col("shard_ciphertext", true, TypeKind::Bytes),
            col("scheme_metadata_json", true, TypeKind::Text),
            col("received_at", true, TypeKind::Text),
        ],
        &["id"],
        &[&["owner_node_id", "share_index"]],
        &[],
    )
}

fn contacts_table() -> TableCatalog {
    table(
        vec![
            col("node_id", true, TypeKind::Text),
            col("local_alias", false, TypeKind::Text),
            col("claimed_name", false, TypeKind::Text),
            col("profile_json", true, TypeKind::Text),
            col("avatar_blake3", false, TypeKind::Text),
            col("verified_identities_json", true, TypeKind::Text),
            col("muted", true, TypeKind::Int),
            col("blocked", true, TypeKind::Int),
            col("tags_json", true, TypeKind::Text),
            col("notes", false, TypeKind::Text),
            col("created_at", true, TypeKind::Text),
            col("updated_at", true, TypeKind::Text),
        ],
        &["node_id"],
        &[],
        &["muted IN (0, 1)", "blocked IN (0, 1)"],
    )
}

fn calendar_events_table() -> TableCatalog {
    table(
        vec![
            col("id", true, TypeKind::Text),
            col("message_id", false, TypeKind::Text),
            col("organizer", true, TypeKind::Text),
            col("title", true, TypeKind::Text),
            col("description", false, TypeKind::Text),
            col("start_ms", true, TypeKind::Int),
            col("end_ms", true, TypeKind::Int),
            col("tz", true, TypeKind::Text),
            col("location", false, TypeKind::Text),
            col("attendees_json", true, TypeKind::Text),
            col("recurrence_json", false, TypeKind::Text),
            col("color", false, TypeKind::Text),
            col("created_at", true, TypeKind::Text),
            col("parent_id", false, TypeKind::Text),
        ],
        &["id"],
        &[],
        &[],
    )
}

fn calendar_rsvps_table() -> TableCatalog {
    table(
        vec![
            col("id", true, TypeKind::Text),
            col("event_id", true, TypeKind::Text),
            col("responder", true, TypeKind::Text),
            col("response", true, TypeKind::Text),
            col("comment", false, TypeKind::Text),
            col("created_at", true, TypeKind::Text),
        ],
        &["id"],
        &[&["event_id", "responder"]],
        &[],
    )
}

fn invites_table() -> TableCatalog {
    table(
        vec![
            col("id", true, TypeKind::Bytes),
            col("invitee_pubkey", true, TypeKind::Bytes),
            col("expiry_unix", true, TypeKind::Int),
            col("channel_size_hint_sats", false, TypeKind::Int),
            col("addr", true, TypeKind::Text),
            col("max_fee_rate_sat_per_vb", false, TypeKind::Int),
            col("channel_open_intent_expiry_unix", false, TypeKind::Int),
            col("nonce", true, TypeKind::Bytes),
            col("state", true, TypeKind::Text),
            col("created_at", true, TypeKind::Int),
            col("accepted_at", false, TypeKind::Int),
            col("revoked_at", false, TypeKind::Int),
        ],
        &["id"],
        &[&["nonce"]],
        &["state IN ('pending', 'accepted', 'opening', 'revoked', 'expired')"],
    )
}

fn onboarding_table() -> TableCatalog {
    table(
        vec![
            col("id", true, TypeKind::Int),
            col("current_step", true, TypeKind::Text),
            col("funding_address", false, TypeKind::Text),
            col("funding_amount_sats_required", false, TypeKind::Int),
            col("funding_amount_sats_received", true, TypeKind::Int),
            col("last_poll_at", false, TypeKind::Int),
            col("tier", false, TypeKind::Text),
            col("funding_evidence", false, TypeKind::Text),
            col("invite_id", false, TypeKind::Text),
            col("inviter_pubkey", false, TypeKind::Bytes),
            col("inviter_ln_pubkey", false, TypeKind::Text),
            col("funding_amount_sats", false, TypeKind::Int),
            col("funding_txid", false, TypeKind::Text),
            col("confirmations", true, TypeKind::Int),
            col("updated_at", false, TypeKind::Int),
        ],
        &["id"],
        &[],
        &["id = 1"],
    )
}

#[cfg(test)]
mod tests {
    use super::normalize_check_body;

    #[test]
    fn postgres_and_sqlite_check_text_normalizes_to_the_same_predicate() {
        let sqlite =
            normalize_check_body("state in ('pending','accepted','opening','revoked','expired')");
        let postgres = normalize_check_body(
            "(state = any (array['pending'::text, 'accepted'::text, 'opening'::text, 'revoked'::text, 'expired'::text]))",
        );
        assert_eq!(sqlite, postgres);
        assert_eq!(
            normalize_check_body("(threshold > 0)"),
            normalize_check_body("threshold > 0")
        );
        assert_eq!(
            normalize_check_body("muted in (0, 1)"),
            normalize_check_body("(muted = any (array[0, 1]))")
        );
    }
}
