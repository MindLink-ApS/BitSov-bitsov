# Main schema at migration 032

Frozen from `origin/main` commit `a745318ecfaff7ddb55df6e0fa6472c14c7b2e47` for forward-only upgrade tests.

`sqlite.sql` concatenates main's migrations 001–032 in version order.
`postgres.sql` contains the SQL and version records returned by main's
`PostgresStorage::pg_migrations()` (including expanded `include_str!` files).
Main has no Postgres migrations 007–009; the test separately records these
versions to ensure migration 033 also works when they are already marked applied.
Trailing whitespace is stripped; SQL statements are unchanged.
Do not regenerate these fixtures from the current branch's migrations.
