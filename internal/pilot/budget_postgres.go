package pilot

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zyc14588/AIPT/internal/testplan"
)

// A single database claim binds the entire Owner-authorized pilot, including
// certification. Neither another run ID, private directory nor restart grants
// another budget. No existing migration or queue behavior is modified.
const pilotBudgetSchema = `
CREATE TABLE IF NOT EXISTS aipt.b007_budget_claims (
 authority_sha text PRIMARY KEY CHECK (authority_sha='605fd163c5c2245ae7088c849b82d35de6d04783b37639f48001a7b22de35d06'),
 run_id text NOT NULL UNIQUE REFERENCES aipt.playtest_runs(run_id),
 manifest_sha bytea NOT NULL CHECK (octet_length(manifest_sha)=32),
 root_device bigint NOT NULL,
 root_inode bigint NOT NULL,
 root_path_sha bytea NOT NULL CHECK (octet_length(root_path_sha)=32),
 pricing_bytes bytea NOT NULL,
 started_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 remote_attempts integer NOT NULL DEFAULT 0 CHECK (remote_attempts BETWEEN 0 AND 32),
 local_calls integer NOT NULL DEFAULT 0 CHECK (local_calls BETWEEN 0 AND 1),
 input_tokens bigint NOT NULL DEFAULT 0 CHECK (input_tokens BETWEEN 0 AND 262144),
 output_tokens bigint NOT NULL DEFAULT 0 CHECK (output_tokens BETWEEN 0 AND 32768),
 nanodollars bigint NOT NULL DEFAULT 0 CHECK (nanodollars BETWEEN 0 AND 5000000000)
);
CREATE TABLE IF NOT EXISTS aipt.b007_budget_reservations (
 authority_sha text NOT NULL REFERENCES aipt.b007_budget_claims(authority_sha),
 attempt_id text NOT NULL,
 kind text NOT NULL CHECK (kind IN ('REMOTE','LOCAL')),
 input_tokens integer NOT NULL CHECK (input_tokens BETWEEN 1 AND 8192),
 output_tokens integer NOT NULL CHECK (output_tokens=1024),
 nanodollars bigint NOT NULL CHECK (nanodollars>=0),
 proof_sha text NOT NULL,
 closure_sha text NOT NULL,
 reserved_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 PRIMARY KEY (authority_sha,attempt_id)
);
CREATE OR REPLACE FUNCTION aipt.b007_budget_history_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'AIPT_B007_BUDGET_HISTORY_IMMUTABLE' USING ERRCODE='55000';
END;$$;
CREATE OR REPLACE FUNCTION aipt.b007_budget_claim_monotone() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE rd bigint;ld bigint;it bigint;ot bigint;nd bigint;
BEGIN
 IF OLD.authority_sha IS DISTINCT FROM NEW.authority_sha OR OLD.run_id IS DISTINCT FROM NEW.run_id
 OR OLD.manifest_sha IS DISTINCT FROM NEW.manifest_sha OR OLD.root_device IS DISTINCT FROM NEW.root_device
 OR OLD.root_inode IS DISTINCT FROM NEW.root_inode OR OLD.root_path_sha IS DISTINCT FROM NEW.root_path_sha
 OR OLD.pricing_bytes IS DISTINCT FROM NEW.pricing_bytes OR OLD.started_at IS DISTINCT FROM NEW.started_at
 OR NEW.remote_attempts<OLD.remote_attempts OR NEW.local_calls<OLD.local_calls
 OR NEW.input_tokens<OLD.input_tokens OR NEW.output_tokens<OLD.output_tokens OR NEW.nanodollars<OLD.nanodollars THEN
  RAISE EXCEPTION 'AIPT_B007_BUDGET_CLAIM_IMMUTABLE' USING ERRCODE='55000';
 END IF;
 SELECT count(*) FILTER(WHERE kind='REMOTE'),count(*) FILTER(WHERE kind='LOCAL'),
 coalesce(sum(input_tokens),0),coalesce(sum(output_tokens),0),coalesce(sum(nanodollars),0)
 INTO rd,ld,it,ot,nd FROM aipt.b007_budget_reservations WHERE authority_sha=NEW.authority_sha;
 IF NEW.remote_attempts<>rd OR NEW.local_calls<>ld OR NEW.input_tokens<>it OR NEW.output_tokens<>ot OR NEW.nanodollars<>nd THEN
  RAISE EXCEPTION 'AIPT_B007_BUDGET_TOTALS_MISMATCH' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END;$$;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='aipt.b007_budget_claims'::regclass AND tgname='b007_budget_claim_monotone') THEN
  CREATE TRIGGER b007_budget_claim_monotone BEFORE UPDATE ON aipt.b007_budget_claims FOR EACH ROW EXECUTE FUNCTION aipt.b007_budget_claim_monotone();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='aipt.b007_budget_claims'::regclass AND tgname='b007_budget_claim_no_reset') THEN
  CREATE TRIGGER b007_budget_claim_no_reset BEFORE DELETE OR TRUNCATE ON aipt.b007_budget_claims FOR EACH STATEMENT EXECUTE FUNCTION aipt.b007_budget_history_immutable();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='aipt.b007_budget_reservations'::regclass AND tgname='b007_budget_reservations_immutable') THEN
  CREATE TRIGGER b007_budget_reservations_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON aipt.b007_budget_reservations FOR EACH STATEMENT EXECUTE FUNCTION aipt.b007_budget_history_immutable();
 END IF;
END;$$;`

type GlobalBudget struct {
	pool          *pgxpool.Pool
	root          *os.File
	rootPath      string
	device, inode uint64
	pathSHA       [32]byte
	manifest      testplan.FrozenManifest
	price         Pricing
}

// OpenGlobalBudget enrolls once or restores only that exact immutable manifest,
// price receipt and held root inode/path. All reservations commit in PostgreSQL
// before the model transport receives permission to send.
func OpenGlobalBudget(ctx context.Context, pool *pgxpool.Pool, rootPath string, manifest testplan.FrozenManifest, price Pricing) (*GlobalBudget, error) {
	if pool == nil || ctx == nil {
		return nil, ErrBudget
	}
	frozen, e := testplan.DecodeRunManifest(manifest.Canonical)
	if e != nil || frozen.Digest != manifest.Digest || frozen.Manifest.RunID != manifest.Manifest.RunID {
		return nil, ErrBudget
	}
	m := frozen.Manifest
	if m.Classification != "DIAGNOSTIC" || m.QualificationEligible || m.Budget.MaxInputTokens != MaxInputTokens || m.Budget.MaxOutputTokens != MaxOutputTokens || m.Budget.MaxDurationSeconds != 1800 {
		return nil, ErrBudget
	}
	if _, e = newBudget(rootPath, m.RunID, price); e != nil {
		return nil, e
	}
	abs, e := filepath.Abs(rootPath)
	if e != nil || !privateDirectory(abs) {
		return nil, ErrBudget
	}
	fd, e := syscall.Open(abs, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	root := os.NewFile(uintptr(fd), "held private pilot root")
	success := false
	defer func() {
		if !success {
			root.Close()
		}
	}()
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700 {
		return nil, ErrBudget
	}
	g := &GlobalBudget{pool: pool, root: root, rootPath: abs, device: st.Dev, inode: st.Ino, pathSHA: sha256.Sum256([]byte(abs)), manifest: frozen, price: price}
	p, _ := json.Marshal(price)
	tx, e := pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	// Enrollment and its additive schema are serialized independently of the
	// unchanged queue migrations. A concurrent opener cannot replace a claim.
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(470438005207)`); e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, pilotBudgetSchema); e != nil {
		return nil, e
	}
	// An arbitrary manifest object cannot create a claim: it must already be the
	// exact PostgreSQL-authoritative frozen diagnostic queue record.
	var canonical []byte
	var classification string
	var eligible bool
	e = tx.QueryRow(ctx, `SELECT m.manifest_bytes,r.classification,r.qualification_eligible FROM aipt.playtest_runs r JOIN aipt.run_manifests m ON m.run_id=r.run_id WHERE r.run_id=$1 AND m.canonical_sha256=$2`, m.RunID, frozen.Digest[:]).Scan(&canonical, &classification, &eligible)
	if e != nil || string(canonical) != string(frozen.Canonical) || classification != "DIAGNOSTIC" || eligible {
		return nil, ErrBudget
	}
	_, e = tx.Exec(ctx, `INSERT INTO aipt.b007_budget_claims(authority_sha,run_id,manifest_sha,root_device,root_inode,root_path_sha,pricing_bytes) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(authority_sha) DO NOTHING`, BudgetAuthority, m.RunID, frozen.Digest[:], int64(st.Dev), int64(st.Ino), g.pathSHA[:], p)
	if e != nil {
		return nil, e
	}
	if e = g.checkClaim(ctx, tx); e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	success = true
	return g, nil
}
func (g *GlobalBudget) Close() error {
	if g == nil || g.root == nil {
		return nil
	}
	return g.root.Close()
}
func (g *GlobalBudget) checkRoot() error {
	if g == nil || g.root == nil {
		return ErrBudget
	}
	var st syscall.Stat_t
	if syscall.Fstat(int(g.root.Fd()), &st) != nil || st.Dev != g.device || st.Ino != g.inode || st.Nlink == 0 || st.Mode&0777 != 0700 || st.Uid != uint32(os.Geteuid()) {
		return ErrBudget
	}
	if !privateDirectory(g.rootPath) {
		return ErrBudget
	}
	i, e := os.Lstat(g.rootPath)
	if e != nil {
		return ErrBudget
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || s.Dev != g.device || s.Ino != g.inode {
		return ErrBudget
	}
	return nil
}
func (g *GlobalBudget) checkClaim(ctx context.Context, tx pgx.Tx) error {
	var run string
	var manifest, path, price []byte
	var dev, inode int64
	e := tx.QueryRow(ctx, `SELECT run_id,manifest_sha,root_device,root_inode,root_path_sha,pricing_bytes FROM aipt.b007_budget_claims WHERE authority_sha=$1 FOR UPDATE`, BudgetAuthority).Scan(&run, &manifest, &dev, &inode, &path, &price)
	p, _ := json.Marshal(g.price)
	if e != nil || run != g.manifest.Manifest.RunID || string(manifest) != string(g.manifest.Digest[:]) || dev != int64(g.device) || inode != int64(g.inode) || string(path) != string(g.pathSHA[:]) || string(price) != string(p) {
		return ErrBudget
	}
	return g.checkRoot()
}
func (g *GlobalBudget) ReserveRemote(ctx context.Context, attempt string, proof WireProof) error {
	return g.reserve(ctx, attempt, "REMOTE", proof)
}
func (g *GlobalBudget) ReserveLocal(ctx context.Context, attempt string, proof WireProof) error {
	return g.reserve(ctx, attempt, "LOCAL", proof)
}
func (g *GlobalBudget) reserve(ctx context.Context, attempt, kind string, proof WireProof) error {
	if ctx == nil || !runPattern.MatchString(attempt) || !proof.valid() {
		return ErrBudget
	}
	if e := g.checkRoot(); e != nil {
		return e
	}
	tx, e := g.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = g.checkClaim(ctx, tx); e != nil {
		return e
	}
	var age, priceAge float64
	var remote, local int
	var input, output, dollars int64
	e = tx.QueryRow(ctx, `SELECT extract(epoch FROM statement_timestamp()-started_at),extract(epoch FROM statement_timestamp()-$2::timestamptz),remote_attempts,local_calls,input_tokens,output_tokens,nanodollars FROM aipt.b007_budget_claims WHERE authority_sha=$1`, BudgetAuthority, g.price.VerifiedAt).Scan(&age, &priceAge, &remote, &local, &input, &output, &dollars)
	if e != nil {
		return e
	}
	if age < 0 || age >= 1800 || priceAge < 0 || priceAge > 86400 {
		return ErrBudget
	}
	cost := int64(0)
	if kind == "REMOTE" {
		cost = int64(proof.CompleteInputCeiling)*g.price.InputNanodollars + int64(proof.UpstreamOutputCeiling)*g.price.OutputNanodollars
		if remote >= MaxRemoteAttempts {
			return ErrBudget
		}
	} else if kind == "LOCAL" {
		if local >= MaxLocalCalls {
			return ErrBudget
		}
	} else {
		return ErrBudget
	}
	if input+int64(proof.CompleteInputCeiling) > MaxInputTokens || output+int64(proof.UpstreamOutputCeiling) > MaxOutputTokens || cost > MaxNanodollars-dollars {
		return ErrBudget
	}
	_, e = tx.Exec(ctx, `INSERT INTO aipt.b007_budget_reservations(authority_sha,attempt_id,kind,input_tokens,output_tokens,nanodollars,proof_sha,closure_sha) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, BudgetAuthority, attempt, kind, proof.CompleteInputCeiling, proof.UpstreamOutputCeiling, cost, proof.ReportSHA, proof.ClosureSHA)
	if e != nil {
		return errors.Join(ErrBudget, e)
	}
	rd, ld := 0, 0
	if kind == "REMOTE" {
		rd = 1
	} else {
		ld = 1
	}
	_, e = tx.Exec(ctx, `UPDATE aipt.b007_budget_claims SET remote_attempts=remote_attempts+$2,local_calls=local_calls+$3,input_tokens=input_tokens+$4,output_tokens=output_tokens+$5,nanodollars=nanodollars+$6 WHERE authority_sha=$1`, BudgetAuthority, rd, ld, proof.CompleteInputCeiling, proof.UpstreamOutputCeiling, cost)
	if e != nil {
		return e
	}
	if e = g.checkRoot(); e != nil {
		return e
	}
	// Failed, cancelled or uncertain operations retain committed reservations.
	return tx.Commit(ctx)
}
func (g *GlobalBudget) Totals(ctx context.Context) (BudgetTotals, error) {
	var t BudgetTotals
	if e := g.checkRoot(); e != nil {
		return t, e
	}
	e := g.pool.QueryRow(ctx, `SELECT remote_attempts,local_calls,input_tokens,output_tokens,nanodollars FROM aipt.b007_budget_claims WHERE authority_sha=$1 AND run_id=$2 AND manifest_sha=$3 AND root_device=$4 AND root_inode=$5 AND root_path_sha=$6`, BudgetAuthority, g.manifest.Manifest.RunID, g.manifest.Digest[:], int64(g.device), int64(g.inode), g.pathSHA[:]).Scan(&t.RemoteAttempts, &t.LocalCalls, &t.InputTokens, &t.OutputTokens, &t.ReservedNanodollars)
	return t, e
}
