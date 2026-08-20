package postgres

import (
	"context"
	"embed"

	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationsFS embeds every SQL migration under migrations/ into the binary,
// so the exact, checksummed migration bytes that the schema tests pin are the
// same bytes the runner applies at runtime and can never drift from the code.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// MigrateUp applies every pending migration embedded under migrations/ to the
// database reachable through pool. It delegates to the package's forward-only
// runner migrateUpFS with the embedded migration filesystem: pending
// migrations are applied in version order inside fresh transactions and each
// is recorded in aipt.schema_migrations, so a second call is a no-op. The
// error contract is migrateUpFS's (for example, a nil pool is rejected before
// any database access).
func MigrateUp(ctx context.Context, pool *pgxpool.Pool) error {
	return migrateUpFS(ctx, pool, migrationsFS)
}
