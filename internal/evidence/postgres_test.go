package evidence

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	storagepostgres "github.com/zyc14588/AIPT/internal/storage/postgres"
)

func scanCaptureValue(destination, value any) error {
	switch target := destination.(type) {
	case *int64:
		actual, ok := value.(int64)
		if !ok {
			return fmt.Errorf("value %T is not int64", value)
		}
		*target = actual
	case *string:
		actual, ok := value.(string)
		if !ok {
			return fmt.Errorf("value %T is not string", value)
		}
		*target = actual
	case *[]byte:
		actual, ok := value.([]byte)
		if !ok {
			return fmt.Errorf("value %T is not []byte", value)
		}
		*target = append((*target)[:0], actual...)
		if actual == nil {
			*target = nil
		}
	case *time.Time:
		actual, ok := value.(time.Time)
		if !ok {
			return fmt.Errorf("value %T is not time.Time", value)
		}
		*target = actual
	default:
		return fmt.Errorf("unsupported scan destination %T", destination)
	}
	return nil
}

type fakeCaptureRow struct {
	values []any
	err    error
}

func (row *fakeCaptureRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != len(row.values) {
		return fmt.Errorf("Scan destinations=%d values=%d", len(destinations), len(row.values))
	}
	for i := range destinations {
		if err := scanCaptureValue(destinations[i], row.values[i]); err != nil {
			return err
		}
	}
	return nil
}

type fakeCaptureRows struct {
	rows   [][]any
	index  int
	err    error
	closed bool
}

func (rows *fakeCaptureRows) Close()                                       { rows.closed = true }
func (rows *fakeCaptureRows) Err() error                                   { return rows.err }
func (rows *fakeCaptureRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (rows *fakeCaptureRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rows *fakeCaptureRows) Values() ([]any, error)                       { return nil, nil }
func (rows *fakeCaptureRows) RawValues() [][]byte                          { return nil }
func (rows *fakeCaptureRows) Conn() *pgx.Conn                              { return nil }
func (rows *fakeCaptureRows) Next() bool {
	if rows.index >= len(rows.rows) {
		return false
	}
	rows.index++
	return true
}
func (rows *fakeCaptureRows) Scan(destinations ...any) error {
	if rows.index == 0 || rows.index > len(rows.rows) {
		return errors.New("Scan called without a current row")
	}
	values := rows.rows[rows.index-1]
	if len(destinations) != len(values) {
		return fmt.Errorf("Scan destinations=%d values=%d", len(destinations), len(values))
	}
	for i := range destinations {
		if err := scanCaptureValue(destinations[i], values[i]); err != nil {
			return err
		}
	}
	return nil
}

type fakeCaptureTx struct {
	rows           *fakeCaptureRows
	cursorSequence int64
	cursorHash     []byte
	querySQL       []string
	queryRowSQL    []string
	commitCalled   bool
	rollbackCalled bool
}

func (tx *fakeCaptureTx) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	tx.querySQL = append(tx.querySQL, sql)
	return tx.rows, nil
}
func (tx *fakeCaptureTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	tx.queryRowSQL = append(tx.queryRowSQL, sql)
	return &fakeCaptureRow{values: []any{tx.cursorSequence, tx.cursorHash}}
}
func (tx *fakeCaptureTx) Commit(context.Context) error {
	tx.commitCalled = true
	return nil
}
func (tx *fakeCaptureTx) Rollback(context.Context) error {
	tx.rollbackCalled = true
	return nil
}

func captureRowsFromSnapshot(snapshot LedgerSnapshot) [][]any {
	rows := make([][]any, 0, len(snapshot.Events))
	for _, event := range snapshot.Events {
		var previous []byte
		if event.PrevEventHash != nil {
			previous = append([]byte(nil), event.PrevEventHash[:]...)
		}
		rows = append(rows, []any{
			event.Sequence, event.EventID, event.EventType, event.PayloadCanonical,
			append([]byte(nil), event.PayloadSHA256[:]...), previous,
			append([]byte(nil), event.EventHash[:]...), event.CommittedAt,
		})
	}
	return rows
}

func postgresSourceForTest(snapshot LedgerSnapshot, tx *fakeCaptureTx, options *pgx.TxOptions) *PostgresSource {
	return &PostgresSource{
		verify: func(context.Context, *pgxpool.Pool, storagepostgres.VerifyInput) (storagepostgres.VerifiedStream, error) {
			var tail *[32]byte
			if snapshot.TailHash != nil {
				value := *snapshot.TailHash
				tail = &value
			}
			return storagepostgres.VerifiedStream{
				StreamID: snapshot.StreamID, Sequence: snapshot.TailSequence,
				EventHash: tail, EventCount: snapshot.EventCount,
			}, nil
		},
		begin: func(_ context.Context, actual pgx.TxOptions) (captureTx, error) {
			*options = actual
			return tx, nil
		},
	}
}

func TestPostgresSourceCaptureSelectOnlyStableSnapshot(t *testing.T) {
	want := fixtureSnapshot()
	tx := &fakeCaptureTx{
		rows:           &fakeCaptureRows{rows: captureRowsFromSnapshot(want)},
		cursorSequence: want.TailSequence,
		cursorHash:     append([]byte(nil), want.TailHash[:]...),
	}
	var options pgx.TxOptions
	source := postgresSourceForTest(want, tx, &options)
	got, err := source.Capture(context.Background(), want.StreamID)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if options.AccessMode != pgx.ReadOnly || options.IsoLevel != pgx.ReadCommitted {
		t.Fatalf("transaction options = %+v, want ReadCommitted+ReadOnly", options)
	}
	if got.EventCount != want.EventCount || got.TailSequence != want.TailSequence ||
		got.TailHash == nil || *got.TailHash != *want.TailHash || len(got.Events) != len(want.Events) {
		t.Fatalf("Capture result = %+v, want stable complete snapshot", got)
	}
	if !tx.commitCalled || !tx.rollbackCalled || !tx.rows.closed {
		t.Fatalf("transaction lifecycle: commit=%t rollback=%t rows_closed=%t",
			tx.commitCalled, tx.rollbackCalled, tx.rows.closed)
	}
	for _, sql := range append(append([]string(nil), tx.querySQL...), tx.queryRowSQL...) {
		if !strings.HasPrefix(strings.TrimSpace(strings.ToUpper(sql)), "SELECT") {
			t.Fatalf("non-SELECT SQL issued: %q", sql)
		}
	}
}

func TestPostgresSourceCaptureFailsOnStreamChange(t *testing.T) {
	want := fixtureSnapshot()
	changedTail := filledHash(0xdd)
	tx := &fakeCaptureTx{
		rows:           &fakeCaptureRows{rows: captureRowsFromSnapshot(want)},
		cursorSequence: want.TailSequence + 1,
		cursorHash:     changedTail[:],
	}
	var options pgx.TxOptions
	_, err := postgresSourceForTest(want, tx, &options).Capture(context.Background(), want.StreamID)
	if !errors.Is(err, ErrStreamChanged) {
		t.Fatalf("error = %v, want ErrStreamChanged", err)
	}
	if tx.commitCalled || !tx.rollbackCalled {
		t.Fatalf("changed stream transaction commit=%t rollback=%t", tx.commitCalled, tx.rollbackCalled)
	}
}

func TestPostgresSourceCaptureNeverAcceptsShortPrefix(t *testing.T) {
	want := fixtureSnapshot()
	tx := &fakeCaptureTx{
		rows:           &fakeCaptureRows{rows: captureRowsFromSnapshot(want)[:2]},
		cursorSequence: want.TailSequence,
		cursorHash:     append([]byte(nil), want.TailHash[:]...),
	}
	var options pgx.TxOptions
	_, err := postgresSourceForTest(want, tx, &options).Capture(context.Background(), want.StreamID)
	if !errors.Is(err, ErrStreamChanged) {
		t.Fatalf("error = %v, want ErrStreamChanged", err)
	}
}

func TestPostgresSourceVerifyFailurePreventsRead(t *testing.T) {
	beginCalled := false
	verifyFailure := errors.New("synthetic verification failure containing SENSITIVE_PAYLOAD_MARKER")
	source := &PostgresSource{
		verify: func(context.Context, *pgxpool.Pool, storagepostgres.VerifyInput) (storagepostgres.VerifiedStream, error) {
			return storagepostgres.VerifiedStream{}, verifyFailure
		},
		begin: func(context.Context, pgx.TxOptions) (captureTx, error) {
			beginCalled = true
			return nil, errors.New("must not run")
		},
	}
	_, err := source.Capture(context.Background(), "synthetic-ledger")
	if !errors.Is(err, ErrLedgerVerify) || !errors.Is(err, verifyFailure) || beginCalled {
		t.Fatalf("verify failure error=%v beginCalled=%t", err, beginCalled)
	}
	if strings.Contains(err.Error(), "SENSITIVE_PAYLOAD_MARKER") {
		t.Fatalf("verify failure leaked payload-bearing cause text: %v", err)
	}
}
