// Package pilot implements the additive, non-qualifying B007 diagnostic.
package pilot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

const (
	BudgetAuthority           = "605fd163c5c2245ae7088c849b82d35de6d04783b37639f48001a7b22de35d06"
	MaxRemoteAttempts         = 32
	MaxInputTokens            = 262144
	MaxOutputTokens           = 32768
	MaxOutputPerAttempt       = 1024
	MaxLocalCalls             = 1
	MaxNanodollars      int64 = 5000000000
	MaxElapsed                = 1800 * time.Second
)

var ErrBudget = errors.New("B007 diagnostic budget or proof rejected; no request authorized")
var runPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}$`)

// Pricing is a worst-case, cache-miss reservation in integer nanodollars.
// ReceiptSHA binds a fresh, independently retrieved official price snapshot.
// It is evidence metadata, not permission to increase any Owner-approved cap.
type Pricing struct {
	Model             string    `json:"model"`
	InputNanodollars  int64     `json:"input_nanodollars_per_token"`
	OutputNanodollars int64     `json:"output_nanodollars_per_token"`
	ReceiptSHA        string    `json:"official_price_receipt_sha256"`
	VerifiedAt        time.Time `json:"verified_at"`
}

// WireProof describes an independently audited actual HTTP dispatch boundary.
// An ACP limit, persona, retry setting or returned-text cap cannot supply it.
// The launcher must validate these facts against its held executable/closure
// before calling Reserve. This module neither constructs nor endorses proof.
type WireProof struct {
	SourceCommit                 string
	ClosureSHA                   string
	ReportSHA                    string
	CompleteInputCeiling         int
	UpstreamOutputCeiling        int
	MaxWireAttemptsPerInvocation int
	BeforeEveryWireSend          bool
}

func (p WireProof) valid() bool {
	return p.SourceCommit == "141eb6fef83422698aef7a981029e843e8161534" && digest(p.ClosureSHA) && digest(p.ReportSHA) && p.CompleteInputCeiling > 0 && p.CompleteInputCeiling <= 8192 && p.UpstreamOutputCeiling == MaxOutputPerAttempt && p.MaxWireAttemptsPerInvocation == 1 && p.BeforeEveryWireSend
}
func digest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == sha256.Size && s == hex.EncodeToString(b)
}

type budgetHeader struct {
	Schema         string    `json:"schema"`
	Authority      string    `json:"authority_sha256"`
	RunID          string    `json:"run_id"`
	Classification string    `json:"classification"`
	StartedAt      time.Time `json:"started_at"`
	Pricing        Pricing   `json:"pricing"`
}
type budgetEvent struct {
	Sequence int    `json:"sequence"`
	Previous string `json:"previous_sha256"`
	Kind     string `json:"kind"`
	Attempt  string `json:"attempt"`
	Input    int    `json:"input_reserved_tokens"`
	Output   int    `json:"output_reserved_tokens"`
	Cost     int64  `json:"reserved_nanodollars"`
	ProofSHA string `json:"wire_proof_sha256"`
}
type BudgetTotals struct {
	RemoteAttempts      int
	InputTokens         int
	OutputTokens        int
	ReservedNanodollars int64
	LocalCalls          int
}
type Budget struct {
	directory, runID string
	price            Pricing
	now              func() time.Time
	initializing     bool
}

// OpenBudget uses one fixed private ledger per approved pilot, not per role or
// retry. A different run ID cannot reset that ledger. Every uncertain request
// permanently retains its worst-case reservation, including after restart.
func newBudget(directory, runID string, price Pricing) (*Budget, error) {
	if !runPattern.MatchString(runID) || price.Model != "deepseek-v4-pro" || !digest(price.ReceiptSHA) || price.InputNanodollars <= 0 || price.OutputNanodollars <= 0 || price.InputNanodollars > MaxNanodollars || price.OutputNanodollars > MaxNanodollars {
		return nil, ErrBudget
	}
	absolute, e := filepath.Abs(directory)
	if e != nil {
		return nil, e
	}
	b := &Budget{directory: absolute, runID: runID, price: price, now: func() time.Time { return time.Now().UTC() }}
	return b, nil
}

// InitializeBudget explicitly enrolls one budget directory. The immutable
// sibling claim survives loss of either ledger file or the budget directory.
// Its private parent run root must itself be anchored by the launcher's unique
// PostgreSQL diagnostic claim; local files cannot detect rollback of that root
// and the authoritative database together.
func InitializeBudget(directory, runID string, price Pricing) (*Budget, error) {
	b, e := newBudget(directory, runID, price)
	if e != nil {
		return nil, e
	}
	if !privateDirectory(filepath.Dir(b.directory)) {
		return nil, ErrBudget
	}
	info, e := os.Lstat(b.directory)
	if e != nil {
		return nil, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !privateDirectory(b.directory) {
		return nil, ErrBudget
	}
	claim := budgetClaim{BudgetAuthority, runID, st.Dev, st.Ino, price}
	fd, e := syscall.Open(b.directory+".b007-budget-claim.json", syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "budget claim")
	defer f.Close()
	data, _ := json.Marshal(claim)
	data = append(data, '\n')
	n, e := f.Write(data)
	if e != nil {
		return nil, e
	}
	if n != len(data) {
		return nil, io.ErrShortWrite
	}
	if e = f.Sync(); e != nil {
		return nil, e
	}
	parent, e := os.Open(filepath.Dir(b.directory))
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	if e = parent.Sync(); e != nil {
		return nil, e
	}
	b.initializing = true
	e = b.locked(func(_ *os.File, _ budgetHeader, _ []budgetEvent, _ BudgetTotals, _ string) error { return nil })
	b.initializing = false
	if e != nil {
		return nil, e
	}
	return b, nil
}

// OpenBudget only restores an already-enrolled budget. Missing state never
// implies a first run, and reopening can never reset the start time/counters.
func OpenBudget(directory, runID string, price Pricing) (*Budget, error) {
	b, e := newBudget(directory, runID, price)
	if e != nil {
		return nil, e
	}
	if e = b.locked(func(_ *os.File, _ budgetHeader, _ []budgetEvent, _ BudgetTotals, _ string) error { return nil }); e != nil {
		return nil, e
	}
	return b, nil
}

type budgetClaim struct {
	Authority string  `json:"authority_sha256"`
	RunID     string  `json:"run_id"`
	Device    uint64  `json:"directory_device"`
	Inode     uint64  `json:"directory_inode"`
	Pricing   Pricing `json:"pricing"`
}

func privateDirectory(p string) bool {
	i, e := os.Lstat(p)
	if e != nil {
		return false
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	return ok && i.IsDir() && i.Mode().Perm() == 0700 && s.Uid == uint32(os.Geteuid())
}
func (b *Budget) validateClaim(st *syscall.Stat_t) error {
	if !privateDirectory(filepath.Dir(b.directory)) {
		return ErrBudget
	}
	fd, e := syscall.Open(b.directory+".b007-budget-claim.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "budget claim")
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return e
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || s.Uid != uint32(os.Geteuid()) || s.Nlink != 1 || i.Size() > 4096 {
		return ErrBudget
	}
	data, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil {
		return e
	}
	want, _ := json.Marshal(budgetClaim{BudgetAuthority, b.runID, st.Dev, st.Ino, b.price})
	want = append(want, '\n')
	if !bytes.Equal(data, want) {
		return ErrBudget
	}
	return nil
}
func (b *Budget) ReserveRemote(attempt string, proof WireProof) error {
	if !runPattern.MatchString(attempt) || !proof.valid() {
		return ErrBudget
	}
	return b.locked(func(f *os.File, h budgetHeader, events []budgetEvent, t BudgetTotals, previous string) error {
		if b.now().Before(h.StartedAt) || b.now().Sub(h.StartedAt) >= MaxElapsed || b.now().Sub(h.Pricing.VerifiedAt) > 24*time.Hour || b.now().Before(h.Pricing.VerifiedAt) {
			return ErrBudget
		}
		cost := int64(proof.CompleteInputCeiling)*h.Pricing.InputNanodollars + int64(proof.UpstreamOutputCeiling)*h.Pricing.OutputNanodollars
		if t.RemoteAttempts >= MaxRemoteAttempts || t.InputTokens+proof.CompleteInputCeiling > MaxInputTokens || t.OutputTokens+proof.UpstreamOutputCeiling > MaxOutputTokens || cost <= 0 || cost > MaxNanodollars-t.ReservedNanodollars {
			return ErrBudget
		}
		for _, e := range events {
			if e.Attempt == attempt {
				return ErrBudget
			}
		}
		return appendEvent(f, budgetEvent{len(events) + 1, previous, "REMOTE_RESERVED", attempt, proof.CompleteInputCeiling, proof.UpstreamOutputCeiling, cost, proof.ReportSHA})
	})
}
func (b *Budget) ReserveLocal(attempt string) error {
	if !runPattern.MatchString(attempt) {
		return ErrBudget
	}
	return b.locked(func(f *os.File, h budgetHeader, events []budgetEvent, t BudgetTotals, previous string) error {
		if b.now().Before(h.StartedAt) || b.now().Sub(h.StartedAt) >= MaxElapsed || t.LocalCalls >= MaxLocalCalls || t.InputTokens+8192 > MaxInputTokens || t.OutputTokens+MaxOutputPerAttempt > MaxOutputTokens {
			return ErrBudget
		}
		for _, e := range events {
			if e.Attempt == attempt {
				return ErrBudget
			}
		}
		return appendEvent(f, budgetEvent{Sequence: len(events) + 1, Previous: previous, Kind: "LOCAL_RESERVED", Attempt: attempt, Input: 8192, Output: MaxOutputPerAttempt})
	})
}
func (b *Budget) Totals() (BudgetTotals, error) {
	var total BudgetTotals
	e := b.locked(func(_ *os.File, _ budgetHeader, _ []budgetEvent, t BudgetTotals, _ string) error {
		total = t
		return nil
	})
	return total, e
}
func appendEvent(f *os.File, e budgetEvent) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err = f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	n, err := f.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	// Authorization is returned only after the reservation is durably stored.
	return f.Sync()
}
func (b *Budget) locked(fn func(*os.File, budgetHeader, []budgetEvent, BudgetTotals, string) error) error {
	// Never follow a directory symlink or accept a shared/private ledger path.
	info, e := os.Lstat(b.directory)
	if e != nil {
		return e
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return ErrBudget
	}
	fd, e := syscall.Open(b.directory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	if e = b.validateClaim(stat); e != nil {
		return e
	}
	var heldDir syscall.Stat_t
	if syscall.Fstat(fd, &heldDir) != nil || heldDir.Ino != stat.Ino || heldDir.Dev != stat.Dev {
		return ErrBudget
	}
	// An independent durable head detects a deleted, partially written or
	// truncated ledger. Crash between journal/head sync fails closed on restart.
	anchorCreated := b.initializing
	flagsAnchor := syscall.O_RDWR | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	if b.initializing {
		flagsAnchor |= syscall.O_CREAT | syscall.O_EXCL
	}
	anchorFD, e := syscall.Openat(fd, "b007-budget-head.json", flagsAnchor, 0600)
	if e != nil {
		return e
	}
	anchor := os.NewFile(uintptr(anchorFD), "b007-budget-head.json")
	defer anchor.Close()
	if e = syscall.Flock(anchorFD, syscall.LOCK_EX); e != nil {
		return e
	}
	defer syscall.Flock(anchorFD, syscall.LOCK_UN)
	ai, e := anchor.Stat()
	if e != nil {
		return e
	}
	ast, ok := ai.Sys().(*syscall.Stat_t)
	if !ok || !ai.Mode().IsRegular() || ai.Mode().Perm() != 0600 || ast.Uid != uint32(os.Geteuid()) || ast.Nlink != 1 || ai.Size() > 512 {
		return ErrBudget
	}
	// Hold the directory inode; pathname replacement cannot redirect this open.
	created := anchorCreated
	flags := syscall.O_RDWR | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	if created {
		flags |= syscall.O_CREAT | syscall.O_EXCL
	}
	ledger, e := syscall.Openat(fd, "b007-budget.jsonl", flags, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(ledger), "b007-budget.jsonl")
	defer f.Close()
	fi, e := f.Stat()
	if e != nil {
		return e
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || fi.Size() > 1<<20 {
		return ErrBudget
	}
	var h budgetHeader
	if created {
		if !b.price.VerifiedAt.IsZero() && b.now().Sub(b.price.VerifiedAt) >= 0 && b.now().Sub(b.price.VerifiedAt) <= 24*time.Hour {
			h = budgetHeader{"aipt.private.b007-budget/v1", BudgetAuthority, b.runID, "DIAGNOSTIC", b.now(), b.price}
			data, _ := json.Marshal(h)
			data = append(data, '\n')
			n, w := f.Write(data)
			if w != nil {
				return w
			}
			if n != len(data) {
				return io.ErrShortWrite
			}
			if w = f.Sync(); w != nil {
				return w
			}
			if w = syscall.Fsync(fd); w != nil {
				return w
			}
		} else {
			return ErrBudget
		}
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return e
	}
	data, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil {
		return e
	}
	if len(data) == 0 || data[len(data)-1] != '\n' || len(data) > 1<<20 {
		return ErrBudget
	}
	lines := bytes.Split(data[:len(data)-1], []byte{'\n'})
	if json.Unmarshal(lines[0], &h) != nil || !canonical(lines[0], h) || h.Schema != "aipt.private.b007-budget/v1" || h.Authority != BudgetAuthority || h.RunID != b.runID || h.Classification != "DIAGNOSTIC" || h.Pricing != b.price || h.StartedAt.IsZero() {
		return ErrBudget
	}
	head := struct {
		SHA     string `json:"ledger_sha256"`
		Entries int    `json:"entries"`
	}{sum(data), len(lines) - 1}
	if !created {
		stored, e := io.ReadAll(io.LimitReader(anchor, 513))
		if e != nil {
			return e
		}
		want, _ := json.Marshal(head)
		want = append(want, '\n')
		if !bytes.Equal(stored, want) {
			return ErrBudget
		}
	}
	previous := sum(lines[0])
	var events []budgetEvent
	var totals BudgetTotals
	seen := map[string]bool{}
	for i, line := range lines[1:] {
		var event budgetEvent
		if json.Unmarshal(line, &event) != nil || !canonical(line, event) || event.Sequence != i+1 || event.Previous != previous || !runPattern.MatchString(event.Attempt) || seen[event.Attempt] {
			return ErrBudget
		}
		seen[event.Attempt] = true
		switch event.Kind {
		case "REMOTE_RESERVED":
			if event.Input <= 0 || event.Input > 8192 || event.Output != MaxOutputPerAttempt || !digest(event.ProofSHA) || event.Cost != int64(event.Input)*h.Pricing.InputNanodollars+int64(event.Output)*h.Pricing.OutputNanodollars {
				return ErrBudget
			}
			totals.RemoteAttempts++
			totals.InputTokens += event.Input
			totals.OutputTokens += event.Output
			totals.ReservedNanodollars += event.Cost
		case "LOCAL_RESERVED":
			if event.Input != 8192 || event.Output != MaxOutputPerAttempt || event.Cost != 0 || event.ProofSHA != "" {
				return ErrBudget
			}
			totals.LocalCalls++
			totals.InputTokens += event.Input
			totals.OutputTokens += event.Output
		default:
			return ErrBudget
		}
		if totals.RemoteAttempts > MaxRemoteAttempts || totals.InputTokens > MaxInputTokens || totals.OutputTokens > MaxOutputTokens || totals.ReservedNanodollars > MaxNanodollars || totals.LocalCalls > MaxLocalCalls {
			return ErrBudget
		}
		previous = sum(line)
		events = append(events, event)
	}
	// Both names must still point at their held, private regular inodes.
	if !namedInode(fd, "b007-budget.jsonl", st) || !namedInode(fd, "b007-budget-head.json", ast) {
		return ErrBudget
	}
	if e = fn(f, h, events, totals, previous); e != nil {
		return e
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return e
	}
	after, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil {
		return e
	}
	if len(after) == 0 || len(after) > 1<<20 || after[len(after)-1] != '\n' {
		return ErrBudget
	}
	head.SHA = sum(after)
	head.Entries = bytes.Count(after, []byte{'\n'}) - 1
	value, _ := json.Marshal(head)
	value = append(value, '\n')
	if _, e = anchor.Seek(0, io.SeekStart); e != nil {
		return e
	}
	if e = anchor.Truncate(0); e != nil {
		return e
	}
	n, e := anchor.Write(value)
	if e != nil {
		return e
	}
	if n != len(value) {
		return io.ErrShortWrite
	}
	if e = anchor.Sync(); e != nil {
		return e
	}
	return syscall.Fsync(fd)
}
func canonical(data []byte, value any) bool {
	b, e := json.Marshal(value)
	return e == nil && bytes.Equal(data, b)
}
func sum(data []byte) string { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }

func namedInode(dir int, name string, want *syscall.Stat_t) bool {
	fd, e := syscall.Openat(dir, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return false
	}
	defer syscall.Close(fd)
	var s syscall.Stat_t
	return syscall.Fstat(fd, &s) == nil && s.Dev == want.Dev && s.Ino == want.Ino
}
