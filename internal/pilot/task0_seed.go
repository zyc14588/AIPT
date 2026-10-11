package pilot

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/zyc14588/AIPT/internal/runcore"
)

const task0SeedFile = "task0-root-seed.private.json"

type task0SeedRecord struct {
	Schema      string             `json:"schema"`
	Authority   string             `json:"authority_sha256"`
	ManifestSHA string             `json:"manifest_sha256"`
	Binding     runcore.RunBinding `json:"run_binding"`
	Seed        string             `json:"root_seed_hex"`
}

// Seed material stays in the held, database-enrolled private root. Creation
// completes and syncs before Core can commit genesis or perform a draw. An
// existing, failed or interrupted record never permits a fresh seed.
type task0SeedSource struct {
	mu      sync.Mutex
	budget  *GlobalBudget
	binding runcore.RunBinding
	held    *os.File
	raw     []byte
	seed    []byte
	used    bool
	closed  bool
}

func newTask0SeedSource(ctx context.Context, budget *GlobalBudget, binding runcore.RunBinding) (*task0SeedSource, error) {
	if ctx == nil || ctx.Err() != nil || budget == nil || budget.pool == nil || budget.checkRoot() != nil ||
		binding.SourcePackage != task0PrototypeSourceBinding || binding.RunID != budget.manifest.Manifest.RunID ||
		binding.Manifest.CanonicalSHA256 != hex.EncodeToString(budget.manifest.Digest[:]) {
		return nil, ErrTask0
	}
	// This also rechecks the persisted unique Run/manifest/root claim. Root
	// permissions alone are insufficient to enroll an actual diagnostic.
	if _, err := budget.Totals(ctx); err != nil {
		return nil, ErrTask0
	}
	return createTask0Seed(budget, binding)
}

func createTask0Seed(budget *GlobalBudget, binding runcore.RunBinding) (*task0SeedSource, error) {
	if budget == nil || budget.checkRoot() != nil {
		return nil, ErrTask0
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, ErrTask0
	}
	keep := false
	defer func() {
		if !keep {
			clear(seed)
		}
	}()
	raw, err := json.Marshal(task0SeedRecord{"aipt.private.b007-task0-root-seed/v1", BudgetAuthority,
		hex.EncodeToString(budget.manifest.Digest[:]), binding, hex.EncodeToString(seed)})
	if err != nil {
		return nil, ErrTask0
	}
	raw = append(raw, '\n')
	fd, err := syscall.Openat(int(budget.root.Fd()), task0SeedFile,
		syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrTask0
	}
	held := os.NewFile(uintptr(fd), "held private Task0 seed")
	defer func() {
		if !keep {
			held.Close()
		}
	}()
	// Never remove an incomplete record. Its existence records an attempted
	// genesis and requires explicit recovery rather than silent regeneration.
	if n, err := held.Write(raw); err != nil || n != len(raw) || held.Chmod(0400) != nil || held.Sync() != nil || budget.root.Sync() != nil || budget.checkRoot() != nil {
		return nil, ErrTask0
	}
	s := &task0SeedSource{budget: budget, binding: binding, held: held, raw: raw, seed: seed}
	if s.checkHeld() != nil {
		return nil, ErrTask0
	}
	keep = true
	return s, nil
}

func (s *task0SeedSource) checkHeld() error {
	if s == nil || s.closed || s.held == nil || s.budget == nil || s.budget.checkRoot() != nil {
		return ErrTask0
	}
	var held, named syscall.Stat_t
	if syscall.Fstat(int(s.held.Fd()), &held) != nil || held.Mode&syscall.S_IFMT != syscall.S_IFREG || held.Mode&0777 != 0400 ||
		held.Uid != uint32(os.Geteuid()) || held.Nlink != 1 || held.Size != int64(len(s.raw)) {
		return ErrTask0
	}
	fd, err := syscall.Openat(int(s.budget.root.Fd()), task0SeedFile, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return ErrTask0
	}
	defer syscall.Close(fd)
	if syscall.Fstat(fd, &named) != nil || held.Dev != named.Dev || held.Ino != named.Ino {
		return ErrTask0
	}
	raw, err := io.ReadAll(io.NewSectionReader(s.held, 0, int64(len(s.raw))+1))
	if err != nil || !bytes.Equal(raw, s.raw) {
		return ErrTask0
	}
	return nil
}

func (s *task0SeedSource) RootSeed(ctx context.Context, binding runcore.RunBinding) ([]byte, error) {
	if s == nil {
		return nil, ErrTask0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || binding != s.binding || s.used || s.checkHeld() != nil {
		return nil, ErrTask0
	}
	s.used = true
	return bytes.Clone(s.seed), nil
}

// Replay reads the same retained record; it neither reenrolls a budget nor
// supplies a second live genesis capability. Core verifies its commitment.
func (s *task0SeedSource) replaySeed() ([]byte, error) {
	if s == nil {
		return nil, ErrTask0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.used || s.checkHeld() != nil {
		return nil, ErrTask0
	}
	return bytes.Clone(s.seed), nil
}

func (s *task0SeedSource) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	clear(s.seed)
	clear(s.raw)
	return s.held.Close()
}
