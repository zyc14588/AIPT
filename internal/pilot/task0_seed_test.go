package pilot

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

// NON_CANON held-root fixtures exercise escrow persistence without creating
// the actual database claim or executing a game, model or diagnostic Run.
func task0SeedFixture(t *testing.T) (*GlobalBudget, *task0SeedSource) {
	t.Helper()
	rootPath := privateRoot(t)
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	var st syscall.Stat_t
	if syscall.Fstat(int(root.Fd()), &st) != nil {
		t.Fatal("fixture root unavailable")
	}
	f := task0ManifestFixture(t)
	binding, err := task0CoreBinding(f, f.Manifest.Source.AIPT)
	if err != nil {
		t.Fatal(err)
	}
	g := &GlobalBudget{root: root, rootPath: rootPath, device: st.Dev, inode: st.Ino, manifest: f}
	s, err := createTask0Seed(g, binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return g, s
}

func TestTask0SeedPersistsBeforeOneGenesisAndReplaysSameMaterial(t *testing.T) {
	g, s := task0SeedFixture(t)
	if _, err := s.replaySeed(); err == nil {
		t.Fatal("replay exposed a seed before genesis admission")
	}
	info, err := os.Stat(filepath.Join(g.rootPath, task0SeedFile))
	if err != nil || info.Mode().Perm() != 0400 || s.checkHeld() != nil {
		t.Fatal("seed was not durably retained with private permissions")
	}
	seed, err := s.RootSeed(context.Background(), s.binding)
	if err != nil || len(seed) != 32 {
		t.Fatal("one genesis seed unavailable")
	}
	seed[0] ^= 1
	replay, err := s.replaySeed()
	if err != nil || bytes.Equal(seed, replay) || !bytes.Equal(replay, s.seed) {
		t.Fatal("caller seed mutation affected retained replay material")
	}
	if _, err := s.RootSeed(context.Background(), s.binding); err == nil {
		t.Fatal("second live genesis received another seed")
	}
	if another, err := createTask0Seed(g, s.binding); err == nil {
		another.Close()
		t.Fatal("restart regenerated a seed over retained history")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.replaySeed(); err == nil {
		t.Fatal("retired seed capability remained usable")
	}
	if _, err := os.Stat(filepath.Join(g.rootPath, task0SeedFile)); err != nil {
		t.Fatal("retirement erased seed history")
	}
}

func TestTask0SeedRejectsRootReplacementRecordTamperingAndWrongBinding(t *testing.T) {
	for _, scenario := range []string{"wrong_binding", "cancelled", "modified_bytes", "hard_link", "record_replaced", "record_unlinked", "root_replaced", "closed"} {
		t.Run(scenario, func(t *testing.T) {
			g, s := task0SeedFixture(t)
			binding := s.binding
			ctx := context.Background()
			path := filepath.Join(g.rootPath, task0SeedFile)
			switch scenario {
			case "wrong_binding":
				binding.RunID += "-other"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "modified_bytes":
				if _, err := s.held.WriteAt([]byte("x"), 0); err != nil {
					t.Fatal(err)
				}
			case "hard_link":
				if err := os.Link(path, filepath.Join(g.rootPath, "another-seed-link")); err != nil {
					t.Fatal(err)
				}
			case "record_replaced", "record_unlinked":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if scenario == "record_replaced" {
					if err := os.WriteFile(path, s.raw, 0400); err != nil {
						t.Fatal(err)
					}
				}
			case "root_replaced":
				if err := os.Rename(g.rootPath, g.rootPath+"-old"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(g.rootPath + "-old") })
				if err := os.Mkdir(g.rootPath, 0700); err != nil {
					t.Fatal(err)
				}
			case "closed":
				s.Close()
			}
			if _, err := s.RootSeed(ctx, binding); err == nil {
				t.Fatal("invalid seed capability admitted genesis")
			}
		})
	}
}

func TestTask0SeedOnlyOneConcurrentGenesisReceivesMaterial(t *testing.T) {
	_, s := task0SeedFixture(t)
	var pass atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := s.RootSeed(context.Background(), s.binding); err == nil {
				pass.Add(1)
			}
		})
	}
	wg.Wait()
	if pass.Load() != 1 {
		t.Fatal("concurrent genesis admitted multiple seed readers")
	}
}

func TestTask0SeedProductionConstructorRequiresDatabaseEnrollment(t *testing.T) {
	g, s := task0SeedFixture(t)
	if _, err := newTask0SeedSource(context.Background(), g, s.binding); err == nil {
		t.Fatal("held-root fixture supplied production seed authority")
	}
}
