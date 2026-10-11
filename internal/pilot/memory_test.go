package pilot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMemoryGateHeldCacheReleasePreservesBytesAndLocatorPrivacy(t *testing.T) {
	name := filepath.Join(t.TempDir(), "private-synthetic-cache-asset")
	content := bytes.Repeat([]byte("non-canon model-cache fixture\n"), 1<<15)
	if err := os.WriteFile(name, content, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.ReadAt(make([]byte, len(content)), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(name, name+".renamed"); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"BEFORE_START", "AFTER_START", "AFTER_RETIRE"} {
		var log bytes.Buffer
		receipt, err := CheckAndReleaseModelCache(context.Background(), phase, 0, []CacheAsset{{AssetID: "SYNTHETIC_NON_CANON_CACHE", File: f}}, &log)
		if err != nil {
			t.Fatal(err)
		}
		if receipt.Before.TotalBytes == 0 || receipt.After.AvailableBytes == 0 || !receipt.Assets[0].HintAccepted || receipt.SystemGlobalCacheCleared {
			t.Fatal("invalid memory receipt")
		}
		if strings.Contains(log.String(), name) || strings.Contains(log.String(), "private-synthetic-cache-asset") {
			t.Fatal("private locator leaked into receipt")
		}
	}
	after, err := os.ReadFile(name + ".renamed")
	if err != nil || sha256.Sum256(after) != sha256.Sum256(content) {
		t.Fatal("cache release changed file bytes", err)
	}
}

func TestMemoryGateCancellationUnknownPhaseAndMissingPIDReject(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var log bytes.Buffer
	if _, err := CheckAndReleaseModelCache(ctx, "BEFORE_START", 0, nil, &log); !errors.Is(err, ErrMemory) || log.Len() != 0 {
		t.Fatal("canceled release admitted")
	}
	if _, err := CheckAndReleaseModelCache(context.Background(), "OTHER", 0, nil, &log); !errors.Is(err, ErrMemory) {
		t.Fatal("invalid phase accepted")
	}
	if _, err := ReadMemorySnapshot(1 << 30); !errors.Is(err, ErrMemory) {
		t.Fatal("missing model process accepted")
	}
	if _, err := parseMemoryValues(strings.NewReader("MemTotal: 10 kB\nMemTotal: 20 kB\n")); !errors.Is(err, ErrMemory) {
		t.Fatal("duplicate memory metric accepted")
	}
}

func TestMemoryGateRejectsCompositePhaseBeforeAnyCacheOperation(t *testing.T) {
	name := filepath.Join(t.TempDir(), "non-canon-cache-fixture")
	if err := os.WriteFile(name, []byte("non-canon"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, phase := range []string{"BEFORE_START AFTER_START", "AFTER_START AFTER_RETIRE", "BEFORE_START AFTER_START AFTER_RETIRE", "", " BEFORE_START", "BEFORE_START "} {
		var log bytes.Buffer
		if _, err := CheckAndReleaseModelCache(context.Background(), phase, 0, []CacheAsset{{AssetID: "NON_CANON", File: f}}, &log); !errors.Is(err, ErrMemory) || log.Len() != 0 {
			t.Fatalf("invalid phase wrote receipt %q err=%v", phase, err)
		}
	}
}
