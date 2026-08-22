package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type staticSource struct {
	snapshot LedgerSnapshot
	err      error
	calls    int
}

func (source *staticSource) Capture(context.Context, string) (LedgerSnapshot, error) {
	source.calls++
	return source.snapshot, source.err
}

func fixtureSourceIdentity() SourceIdentity {
	return SourceIdentity{
		Repository: "https://example.invalid/aipt-synthetic",
		Commit:     strings.Repeat("1", 40),
		Tree:       strings.Repeat("2", 40),
	}
}

func filledHash(value byte) [32]byte {
	var hash [32]byte
	for i := range hash {
		hash[i] = value
	}
	return hash
}

func fixtureSnapshot() LedgerSnapshot {
	payloads := []string{
		`{"kind":"start","value":1}`,
		`{"kind":"step","value":2}`,
		`{"kind":"finish","value":3}`,
	}
	eventTypes := []string{"fixture.started", "fixture.advanced", "fixture.finished"}
	hashes := [][32]byte{filledHash(0xaa), filledHash(0xbb), filledHash(0xcc)}
	events := make([]LedgerEvent, 0, len(payloads))
	for i, payload := range payloads {
		committedAt, err := time.Parse(time.RFC3339, "2026-01-01T00:00:0"+strconv.Itoa(i)+"Z")
		if err != nil {
			panic(err)
		}
		var previous *[32]byte
		if i > 0 {
			value := hashes[i-1]
			previous = &value
		}
		events = append(events, LedgerEvent{
			StreamID:         "synthetic-ledger",
			Sequence:         int64(i + 1),
			EventID:          "synthetic-event-000" + strconv.Itoa(i+1),
			EventType:        eventTypes[i],
			PayloadCanonical: payload,
			PayloadSHA256:    sha256.Sum256([]byte(payload)),
			PrevEventHash:    previous,
			EventHash:        hashes[i],
			CommittedAt:      committedAt,
		})
	}
	tail := hashes[len(hashes)-1]
	return LedgerSnapshot{
		StreamID: "synthetic-ledger", EventCount: 3, TailSequence: 3,
		TailHash: &tail, Events: events,
	}
}

func exportFixture(t *testing.T) string {
	t.Helper()
	destination := filepath.Join(t.TempDir(), "raw-capture")
	verification, err := ExportRawCapture(context.Background(), &staticSource{snapshot: fixtureSnapshot()}, ExportInput{
		Destination: destination,
		Source:      fixtureSourceIdentity(),
		StreamID:    "synthetic-ledger",
	})
	if err != nil {
		t.Fatalf("ExportRawCapture: %v", err)
	}
	if verification.Root != "106ba6686d0f47304921266824c5832916867931869c45424d894410eed241a2" {
		t.Fatalf("root = %s, want frozen synthetic root", verification.Root)
	}
	return destination
}

func TestExportRawCaptureDeterministicGoldenAndPrivate(t *testing.T) {
	first := exportFixture(t)
	second := exportFixture(t)
	golden := filepath.Join("..", "..", "testdata", "evidence", "v1", "minimal-raw-capture")
	for _, name := range []string{ManifestName, EventsName, RootName} {
		firstBytes, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		secondBytes, err := os.ReadFile(filepath.Join(second, name))
		if err != nil {
			t.Fatal(err)
		}
		goldenBytes, err := os.ReadFile(filepath.Join(golden, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(firstBytes) != string(secondBytes) || string(firstBytes) != string(goldenBytes) {
			t.Errorf("%s is not byte-deterministic or differs from golden", name)
		}
		info, err := os.Lstat(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
			t.Errorf("%s mode/type = %v, want regular 0600", name, info.Mode())
		}
	}
	directoryInfo, err := os.Lstat(first)
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 || !directoryInfo.IsDir() {
		t.Errorf("bundle mode/type = %v, want directory 0700", directoryInfo.Mode())
	}
	manifest, err := os.ReadFile(filepath.Join(first, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{first, "hostname", "exported_at", "process_id", "pid", "dsn", "password", "credential"} {
		if strings.Contains(strings.ToLower(string(manifest)), strings.ToLower(forbidden)) {
			t.Errorf("manifest contains forbidden operational metadata %q", forbidden)
		}
	}
	if _, err := VerifyRawCapture(first); err != nil {
		t.Fatalf("VerifyRawCapture(exported): %v", err)
	}
}

func TestExportRawCaptureEmptyStream(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "empty")
	snapshot := LedgerSnapshot{StreamID: "empty-ledger"}
	verification, err := ExportRawCapture(context.Background(), &staticSource{snapshot: snapshot}, ExportInput{
		Destination: destination, Source: fixtureSourceIdentity(), StreamID: "empty-ledger",
	})
	if err != nil {
		t.Fatalf("ExportRawCapture(empty): %v", err)
	}
	if verification.Manifest.EventCount != 0 || verification.Manifest.TailSequence != 0 ||
		verification.Manifest.TailEventHash != nil {
		t.Fatalf("empty manifest = %+v", verification.Manifest)
	}
	events, err := os.ReadFile(filepath.Join(destination, EventsName))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("empty events bytes = %d, want 0", len(events))
	}
}

func TestExportRawCaptureSemanticIdentityAndCanonicalMapOrdering(t *testing.T) {
	baseDirectory := exportFixture(t)
	baseVerification, err := VerifyRawCapture(baseDirectory)
	if err != nil {
		t.Fatal(err)
	}

	changedSourceDestination := filepath.Join(t.TempDir(), "changed-source")
	changedSource := fixtureSourceIdentity()
	changedSource.Commit = strings.Repeat("3", 40)
	changedSourceVerification, err := ExportRawCapture(context.Background(), &staticSource{snapshot: fixtureSnapshot()}, ExportInput{
		Destination: changedSourceDestination, Source: changedSource, StreamID: "synthetic-ledger",
	})
	if err != nil {
		t.Fatal(err)
	}
	if changedSourceVerification.Root == baseVerification.Root {
		t.Fatal("source commit semantic change did not change the root")
	}

	changedEventDestination := filepath.Join(t.TempDir(), "changed-event")
	changedSnapshot := fixtureSnapshot()
	changedSnapshot.Events[1].EventType = "fixture.changed"
	changedEventVerification, err := ExportRawCapture(context.Background(), &staticSource{snapshot: changedSnapshot}, ExportInput{
		Destination: changedEventDestination, Source: fixtureSourceIdentity(), StreamID: "synthetic-ledger",
	})
	if err != nil {
		t.Fatal(err)
	}
	if changedEventVerification.Root == baseVerification.Root {
		t.Fatal("event semantic change did not change the root")
	}

	left, err := canonicalLine(map[string]any{"z": 1, "a": map[string]any{"y": 2, "b": 3}})
	if err != nil {
		t.Fatal(err)
	}
	right, err := canonicalLine(map[string]any{"a": map[string]any{"b": 3, "y": 2}, "z": 1})
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatalf("map insertion order changed canonical bytes:\n%s\n%s", left, right)
	}
}

func TestExportRawCaptureAtomicFailureAndExistingTarget(t *testing.T) {
	t.Run("source failure leaves no final or temporary content", func(t *testing.T) {
		parent := t.TempDir()
		destination := filepath.Join(parent, "capture")
		sourceFailure := errors.New("synthetic source failure containing SENSITIVE_PAYLOAD_MARKER")
		_, err := ExportRawCapture(context.Background(), &staticSource{err: sourceFailure}, ExportInput{
			Destination: destination, Source: fixtureSourceIdentity(), StreamID: "synthetic-ledger",
		})
		if err == nil {
			t.Fatal("source failure unexpectedly succeeded")
		}
		if !errors.Is(err, ErrLedgerVerify) {
			t.Fatalf("source failure error = %v, want ErrLedgerVerify", err)
		}
		if !errors.Is(err, sourceFailure) {
			t.Fatalf("source failure cause is not preserved for errors.Is: %v", err)
		}
		if strings.Contains(err.Error(), "SENSITIVE_PAYLOAD_MARKER") {
			t.Fatalf("source failure leaked payload-bearing cause text: %v", err)
		}
		entries, readErr := os.ReadDir(parent)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if len(entries) != 0 {
			t.Fatalf("failure left content: %v", entries)
		}
	})
	t.Run("unsafe parent symlink is rejected before source access", func(t *testing.T) {
		parent := t.TempDir()
		realParent := filepath.Join(parent, "real")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedParent := filepath.Join(parent, "linked")
		if err := os.Symlink(realParent, linkedParent); err != nil {
			t.Fatal(err)
		}
		source := &staticSource{snapshot: fixtureSnapshot()}
		_, err := ExportRawCapture(context.Background(), source, ExportInput{
			Destination: filepath.Join(linkedParent, "capture"), Source: fixtureSourceIdentity(), StreamID: "synthetic-ledger",
		})
		if !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("error = %v, want ErrUnsafePath", err)
		}
		if source.calls != 0 {
			t.Fatalf("unsafe parent was checked after source access (%d calls)", source.calls)
		}
	})
	t.Run("write failures carry a stable category", func(t *testing.T) {
		err := writePrivateFile(filepath.Join(t.TempDir(), "missing"), EventsName, []byte("synthetic"))
		if !errors.Is(err, ErrWriteFailed) {
			t.Fatalf("error = %v, want ErrWriteFailed", err)
		}
	})
	t.Run("inconsistent source is never truncated", func(t *testing.T) {
		parent := t.TempDir()
		destination := filepath.Join(parent, "capture")
		snapshot := fixtureSnapshot()
		snapshot.EventCount = 2
		_, err := ExportRawCapture(context.Background(), &staticSource{snapshot: snapshot}, ExportInput{
			Destination: destination, Source: fixtureSourceIdentity(), StreamID: "synthetic-ledger",
		})
		if !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("error = %v, want ErrInvalidInput", err)
		}
		if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("partial final exists: %v", statErr)
		}
	})
	for _, kind := range []string{"file", "directory", "symlink"} {
		t.Run("reject existing "+kind, func(t *testing.T) {
			parent := t.TempDir()
			destination := filepath.Join(parent, "capture")
			switch kind {
			case "file":
				if err := os.WriteFile(destination, []byte("occupied"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(destination, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(parent, "missing"), destination); err != nil {
					t.Fatal(err)
				}
			}
			source := &staticSource{snapshot: fixtureSnapshot()}
			_, err := ExportRawCapture(context.Background(), source, ExportInput{
				Destination: destination, Source: fixtureSourceIdentity(), StreamID: "synthetic-ledger",
			})
			if !errors.Is(err, ErrTargetExists) {
				t.Fatalf("error = %v, want ErrTargetExists", err)
			}
			if source.calls != 0 {
				t.Fatalf("existing target was checked after source access (%d calls)", source.calls)
			}
		})
	}
}

func writeManifestAndRoot(t *testing.T, directory string, manifest any) {
	t.Helper()
	manifestBytes, err := canonicalLine(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ManifestName), manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(manifestBytes)
	if err := os.WriteFile(filepath.Join(directory, RootName), []byte(hex.EncodeToString(digest[:])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mutateManifest(t *testing.T, directory string, mutate func(*RawCaptureManifest)) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var manifest RawCaptureManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	mutate(&manifest)
	writeManifestAndRoot(t, directory, manifest)
}

func rewriteEvents(t *testing.T, directory string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, EventsName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	mutateManifest(t, directory, func(manifest *RawCaptureManifest) {
		manifest.Assets[0].Bytes = int64(len(data))
		manifest.Assets[0].SHA256 = hex.EncodeToString(digest[:])
	})
}

func mutateEvent(t *testing.T, directory string, index int, mutate func(*rawEventRecord)) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, EventsName))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	var event rawEventRecord
	if err := json.Unmarshal([]byte(lines[index]), &event); err != nil {
		t.Fatal(err)
	}
	mutate(&event)
	line, err := canonicalLine(event)
	if err != nil {
		t.Fatal(err)
	}
	lines[index] = strings.TrimSuffix(string(line), "\n")
	rewriteEvents(t, directory, []byte(strings.Join(lines, "\n")+"\n"))
}

func TestVerifyRawCaptureTamperTable(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"root mismatch", func(t *testing.T, dir string) {
			_ = os.WriteFile(filepath.Join(dir, RootName), []byte(strings.Repeat("0", 64)+"\n"), 0o600)
		}},
		{"root uppercase", func(t *testing.T, dir string) {
			data, _ := os.ReadFile(filepath.Join(dir, RootName))
			_ = os.WriteFile(filepath.Join(dir, RootName), []byte(strings.ToUpper(string(data))), 0o600)
		}},
		{"root short", func(t *testing.T, dir string) {
			_ = os.WriteFile(filepath.Join(dir, RootName), []byte("abcd\n"), 0o600)
		}},
		{"events content digest", func(t *testing.T, dir string) {
			file, _ := os.OpenFile(filepath.Join(dir, EventsName), os.O_APPEND|os.O_WRONLY, 0o600)
			_, _ = file.WriteString(" ")
			_ = file.Close()
		}},
		{"unknown manifest field", func(t *testing.T, dir string) {
			data, _ := os.ReadFile(filepath.Join(dir, ManifestName))
			var manifest map[string]any
			_ = json.Unmarshal(data, &manifest)
			manifest["hostname"] = "synthetic.invalid"
			writeManifestAndRoot(t, dir, manifest)
		}},
		{"unknown stage", func(t *testing.T, dir string) {
			mutateManifest(t, dir, func(manifest *RawCaptureManifest) { manifest.Stage = "RAW_CAPTURE_V2" })
		}},
		{"wrong version", func(t *testing.T, dir string) {
			mutateManifest(t, dir, func(manifest *RawCaptureManifest) { manifest.Version = "2.0.0" })
		}},
		{"wrong source SHA", func(t *testing.T, dir string) {
			mutateManifest(t, dir, func(manifest *RawCaptureManifest) { manifest.Source.Commit = "short" })
		}},
		{"absolute asset path", func(t *testing.T, dir string) {
			mutateManifest(t, dir, func(manifest *RawCaptureManifest) { manifest.Assets[0].Path = "/events.ndjson" })
		}},
		{"unsafe asset path", func(t *testing.T, dir string) {
			mutateManifest(t, dir, func(manifest *RawCaptureManifest) { manifest.Assets[0].Path = "../events.ndjson" })
		}},
		{"duplicate asset", func(t *testing.T, dir string) {
			mutateManifest(t, dir, func(manifest *RawCaptureManifest) { manifest.Assets = append(manifest.Assets, manifest.Assets[0]) })
		}},
		{"unsorted asset inventory", func(t *testing.T, dir string) {
			mutateManifest(t, dir, func(manifest *RawCaptureManifest) {
				other := manifest.Assets[0]
				other.Path = "aaa.ndjson"
				manifest.Assets = []Asset{manifest.Assets[0], other}
			})
		}},
		{"asset bytes", func(t *testing.T, dir string) {
			mutateManifest(t, dir, func(manifest *RawCaptureManifest) { manifest.Assets[0].Bytes++ })
		}},
		{"asset SHA", func(t *testing.T, dir string) {
			mutateManifest(t, dir, func(manifest *RawCaptureManifest) { manifest.Assets[0].SHA256 = strings.Repeat("d", 64) })
		}},
		{"event count", func(t *testing.T, dir string) {
			mutateManifest(t, dir, func(manifest *RawCaptureManifest) { manifest.EventCount = 2; manifest.TailSequence = 2 })
		}},
		{"tail hash", func(t *testing.T, dir string) {
			mutateManifest(t, dir, func(manifest *RawCaptureManifest) {
				value := strings.Repeat("d", 64)
				manifest.TailEventHash = &value
			})
		}},
		{"noncanonical manifest", func(t *testing.T, dir string) {
			data, _ := os.ReadFile(filepath.Join(dir, ManifestName))
			data = append([]byte(" "), data...)
			_ = os.WriteFile(filepath.Join(dir, ManifestName), data, 0o600)
			digest := sha256.Sum256(data)
			_ = os.WriteFile(filepath.Join(dir, RootName), []byte(hex.EncodeToString(digest[:])+"\n"), 0o600)
		}},
		{"sequence gap", func(t *testing.T, dir string) {
			mutateEvent(t, dir, 1, func(event *rawEventRecord) { event.Sequence = 4 })
		}},
		{"duplicate sequence", func(t *testing.T, dir string) {
			mutateEvent(t, dir, 1, func(event *rawEventRecord) { event.Sequence = 1 })
		}},
		{"wrong stream", func(t *testing.T, dir string) {
			mutateEvent(t, dir, 1, func(event *rawEventRecord) { event.StreamID = "other-ledger" })
		}},
		{"reordered events", func(t *testing.T, dir string) {
			data, _ := os.ReadFile(filepath.Join(dir, EventsName))
			lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
			lines[0], lines[1] = lines[1], lines[0]
			rewriteEvents(t, dir, []byte(strings.Join(lines, "\n")+"\n"))
		}},
		{"previous hash", func(t *testing.T, dir string) {
			mutateEvent(t, dir, 1, func(event *rawEventRecord) {
				value := strings.Repeat("d", 64)
				event.PrevEventHash = &value
			})
		}},
		{"payload hash", func(t *testing.T, dir string) {
			mutateEvent(t, dir, 0, func(event *rawEventRecord) { event.PayloadSHA256 = strings.Repeat("d", 64) })
		}},
		{"noncanonical payload", func(t *testing.T, dir string) {
			mutateEvent(t, dir, 0, func(event *rawEventRecord) { event.PayloadCanonical = `{ "value":1,"kind":"start"}` })
		}},
		{"non-UTC timestamp", func(t *testing.T, dir string) {
			mutateEvent(t, dir, 0, func(event *rawEventRecord) { event.CommittedAt = "2026-01-01T10:00:00+10:00" })
		}},
		{"events missing LF", func(t *testing.T, dir string) {
			data, _ := os.ReadFile(filepath.Join(dir, EventsName))
			rewriteEvents(t, dir, data[:len(data)-1])
		}},
		{"truncated events", func(t *testing.T, dir string) {
			data, _ := os.ReadFile(filepath.Join(dir, EventsName))
			rewriteEvents(t, dir, data[:len(data)/2])
		}},
		{"appended events bytes", func(t *testing.T, dir string) {
			data, _ := os.ReadFile(filepath.Join(dir, EventsName))
			rewriteEvents(t, dir, append(data, []byte("{}\n")...))
		}},
		{"blank line", func(t *testing.T, dir string) {
			data, _ := os.ReadFile(filepath.Join(dir, EventsName))
			rewriteEvents(t, dir, append([]byte("\n"), data...))
		}},
		{"invalid UTF-8", func(t *testing.T, dir string) {
			data, _ := os.ReadFile(filepath.Join(dir, EventsName))
			data[10] = 0xff
			rewriteEvents(t, dir, data)
		}},
		{"extra file", func(t *testing.T, dir string) {
			_ = os.WriteFile(filepath.Join(dir, "extra.txt"), []byte("synthetic"), 0o600)
		}},
		{"missing file", func(t *testing.T, dir string) {
			_ = os.Remove(filepath.Join(dir, EventsName))
		}},
		{"file mode", func(t *testing.T, dir string) {
			_ = os.Chmod(filepath.Join(dir, ManifestName), 0o644)
		}},
		{"directory mode", func(t *testing.T, dir string) {
			_ = os.Chmod(dir, 0o755)
		}},
		{"symlink member", func(t *testing.T, dir string) {
			_ = os.Remove(filepath.Join(dir, RootName))
			_ = os.Symlink(ManifestName, filepath.Join(dir, RootName))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := exportFixture(t)
			test.mutate(t, directory)
			if _, err := VerifyRawCapture(directory); !errors.Is(err, ErrBundleInvalid) {
				t.Fatalf("VerifyRawCapture error = %v, want ErrBundleInvalid", err)
			}
		})
	}
}
