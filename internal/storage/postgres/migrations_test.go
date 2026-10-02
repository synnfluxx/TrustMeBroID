package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/synnfluxx/TrustMeBroID/migrations"
)

// A database that already ran the earlier migrations is the case that keeps
// breaking: goose replays only versions it has not recorded, so correcting an
// applied file reaches a fresh database and never an existing one. Twice now
// the code has asked production for a column that was only ever renamed in a
// file nobody would replay — first verify_token, then last_token_generated_time.
//
// This brings a database up to the state production was in, then runs the rest,
// and checks it arrives where the queries expect.
func TestMigrationsReachTheSameSchemaFromAnOlderDatabase(t *testing.T) {
	db := createPostgresDB(t) // already fully migrated by the helper

	// Start again from nothing so the intermediate state can be recreated.
	goose.SetBaseFS(migrations.MigrationsFS)
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.DownTo(db, ".", 0))

	// 000004 is the last version that used the old column names.
	require.NoError(t, goose.UpTo(db, ".", 4))
	require.True(t, hasColumn(t, db, "verify_token"), "the old schema should have verify_token")
	require.True(t, hasColumn(t, db, "last_token_generated_time"), "the old schema should have last_token_generated_time")

	require.NoError(t, goose.Up(db, "."))

	require.True(t, hasColumn(t, db, "verification_code"), "verification_code is what every query selects")
	require.True(t, hasColumn(t, db, "last_code_generated_time"), "last_code_generated_time is what every query selects")
	require.False(t, hasColumn(t, db, "verify_token"), "the renamed column should be gone")
	require.False(t, hasColumn(t, db, "last_token_generated_time"), "the renamed column should be gone")

	// Six digits is a million values and the column is never reused, so a
	// unique constraint turns an ordinary collision into a failed signup.
	require.False(t, hasUniqueOn(t, db, "verification_code"), "verification_code must not be unique")
}

// The same files on an empty database have to produce that schema directly.
func TestMigrationsReachTheSameSchemaFromEmpty(t *testing.T) {
	db := createPostgresDB(t)

	require.True(t, hasColumn(t, db, "verification_code"))
	require.True(t, hasColumn(t, db, "last_code_generated_time"))
	require.False(t, hasUniqueOn(t, db, "verification_code"))
}

func hasColumn(t *testing.T, db *sql.DB, column string) bool {
	t.Helper()

	var exists bool
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		 WHERE table_name = 'users' AND column_name = $1)`, column).Scan(&exists))
	return exists
}

func hasUniqueOn(t *testing.T, db *sql.DB, column string) bool {
	t.Helper()

	var exists bool
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT EXISTS (
		    SELECT 1 FROM pg_constraint c
		    JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
		    WHERE c.conrelid = 'users'::regclass AND c.contype = 'u' AND a.attname = $1
		 )`, column).Scan(&exists))
	return exists
}
