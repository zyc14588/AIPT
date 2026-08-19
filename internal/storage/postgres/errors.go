package postgres

import (
	"errors"
	"fmt"
)

// ErrMigrationChecksumDrift is the exported sentinel for migration checksum
// drift. Its error text is the stable code AIPT_MIGRATION_CHECKSUM_DRIFT so
// callers can match it without parsing messages; it is also matched via
// errors.Is by *MigrationChecksumDriftError.
var ErrMigrationChecksumDrift = errors.New("AIPT_MIGRATION_CHECKSUM_DRIFT")

// MigrationChecksumDriftError is the typed, errors.Is-compatible error that
// reports a SHA-256 checksum drift for one migration: the on-disk SQL bytes no
// longer hash to the checksum recorded when the migration was applied. Version
// is the numeric migration version, Expected is the recorded [32]byte SHA-256
// and Actual is the SHA-256 of the current file bytes.
type MigrationChecksumDriftError struct {
	Version  int64
	Expected [32]byte
	Actual   [32]byte
}

// Error implements error and always embeds the stable drift code.
func (e *MigrationChecksumDriftError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: migration version %d checksum drift: expected %x, actual %x",
		ErrMigrationChecksumDrift, e.Version, e.Expected, e.Actual)
}

// Is makes *MigrationChecksumDriftError match the exported sentinel through
// errors.Is, independent of the carried version and checksums.
func (e *MigrationChecksumDriftError) Is(target error) bool {
	return target == ErrMigrationChecksumDrift
}
