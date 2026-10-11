package pilot

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/runcontrol"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/testplan"
)

// These are private NON_CANON control bytes, never actual credentials,
// registered inputs, static accepted helpers, model executions or DIAG runs.
func task0PreparationFileFixture(t *testing.T, body []byte, mode os.FileMode) task0PreparationFile {
	t.Helper()
	p := filepath.Join(privateRoot(t), "NON-CANON-private-input")
	if os.WriteFile(p, body, mode) != nil || os.Chmod(p, mode) != nil {
		t.Fatal("private fixture")
	}
	return task0PreparationFile{p, inputSHA(body), int64(len(body))}
}

func TestTask0PreparationOpensOnlyExactPrivateRegularSource(t *testing.T) {
	for _, scenario := range []string{"valid", "writable", "wrong_digest", "wrong_length", "modified_bytes", "hardlink", "symlink", "fifo", "directory", "unsafe_parent", "relative_path", "helper_not_executable", "non_elf_helper"} {
		t.Run(scenario, func(t *testing.T) {
			body := []byte("NON-CANON control input without a secret")
			s := task0PreparationFileFixture(t, body, 0400)
			switch scenario {
			case "writable":
				if os.Chmod(s.Path, 0600) != nil {
					t.Fatal("chmod")
				}
			case "wrong_digest":
				s.SHA256 = strings.Repeat("a", 64)
			case "wrong_length":
				s.Bytes++
			case "modified_bytes":
				if os.Chmod(s.Path, 0600) != nil || os.WriteFile(s.Path, []byte(strings.Repeat("x", len(body))), 0600) != nil || os.Chmod(s.Path, 0400) != nil {
					t.Fatal("fixture mutation")
				}
			case "hardlink":
				if os.Link(s.Path, s.Path+".alias") != nil {
					t.Fatal("hardlink")
				}
			case "symlink":
				target := s.Path + ".target"
				if os.Rename(s.Path, target) != nil || os.Symlink(target, s.Path) != nil {
					t.Fatal("symlink")
				}
			case "fifo":
				if os.Remove(s.Path) != nil || syscall.Mkfifo(s.Path, 0400) != nil {
					t.Fatal("fifo")
				}
			case "directory":
				if os.Remove(s.Path) != nil || os.Mkdir(s.Path, 0700) != nil {
					t.Fatal("directory")
				}
			case "unsafe_parent":
				if os.Chmod(filepath.Dir(s.Path), 0755) != nil {
					t.Fatal("parent")
				}
			case "relative_path":
				s.Path = filepath.Base(s.Path)
			case "non_elf_helper":
				if os.Chmod(s.Path, 0500) != nil {
					t.Fatal("helper")
				}
			}
			if scenario == "non_elf_helper" {
				if f, err := task0HoldPreparationHelper(s); err == nil {
					f.Close()
					t.Fatal("non-ELF helper accepted")
				}
				return
			}
			f, err := task0OpenPreparationFile(s, scenario == "helper_not_executable")
			if f != nil {
				defer f.Close()
			}
			if scenario == "valid" {
				if err != nil || f == nil {
					t.Fatal("exact private source rejected", err)
				}
			} else if err == nil {
				t.Fatal("unsafe private source accepted")
			}
		})
	}
}

func TestTask0PreparationConnectionHasNoSelectorOrAmbientCredential(t *testing.T) {
	for _, scenario := range []string{"valid", "empty_inline_password", "foreign_host", "wrong_port", "wrong_database", "tls", "keyword_dsn", "extra_query", "newline", "decoded_password_control", "ambient_password", "ambient_service", "ambient_passfile"} {
		t.Run(scenario, func(t *testing.T) {
			u := "postgresql://NON-CANON-user:NON-CANON-password@127.0.0.1:15432/aipt_b007_diag?sslmode=disable"
			switch scenario {
			case "empty_inline_password":
				u = "postgresql://NON-CANON-user@127.0.0.1:15432/aipt_b007_diag?sslmode=disable"
				home := privateRoot(t)
				if os.WriteFile(filepath.Join(home, ".pgpass"), []byte("127.0.0.1:15432:aipt_b007_diag:NON-CANON-user:forbidden-ambient-value\n"), 0600) != nil {
					t.Fatal("passfile")
				}
				t.Setenv("HOME", home)
			case "foreign_host":
				u = strings.Replace(u, "127.0.0.1", "203.0.113.8", 1)
			case "wrong_port":
				u = strings.Replace(u, "15432", "5432", 1)
			case "wrong_database":
				u = strings.Replace(u, "aipt_b007_diag", "another_database", 1)
			case "tls":
				u = strings.Replace(u, "sslmode=disable", "sslmode=require", 1)
			case "keyword_dsn":
				u = "host=127.0.0.1 port=15432 dbname=aipt_b007_diag sslmode=disable"
			case "extra_query":
				u += "&application_name=caller"
			case "newline":
				u += "\n"
			case "decoded_password_control":
				u = strings.Replace(u, "NON-CANON-password", "bad%0Apassword", 1)
			case "ambient_password":
				t.Setenv("PGPASSWORD", "NON-CANON-ambient")
			case "ambient_service":
				t.Setenv("PGSERVICE", "NON-CANON-ambient")
			case "ambient_passfile":
				t.Setenv("PGPASSFILE", filepath.Join(privateRoot(t), "NON-CANON-missing"))
			}
			cfg, err := task0PreparationDatabase(task0PreparationFileFixture(t, []byte(u), 0400))
			if scenario == "valid" || scenario == "empty_inline_password" {
				if err != nil || cfg == nil {
					t.Fatal("exact isolated connection rejected", err)
				}
				want := "NON-CANON-password"
				if scenario == "empty_inline_password" {
					want = ""
				}
				if cfg.ConnConfig.Password != want || cfg.ConnConfig.Host != "127.0.0.1" || cfg.ConnConfig.Port != 15432 || cfg.ConnConfig.Database != "aipt_b007_diag" || cfg.ConnConfig.TLSConfig != nil || len(cfg.ConnConfig.Fallbacks) != 0 {
					t.Fatal("connection selected an ambient route or credential")
				}
			} else if err == nil {
				t.Fatal("connection selector accepted")
			}
		})
	}
}

func TestTask0PreparationRootPinsRejectAliasingAndRename(t *testing.T) {
	b := task0PreparationBinding{SourceRoot: privateRoot(t), BudgetRoot: privateRoot(t), EvidenceRoot: privateRoot(t), KeyRoot: privateRoot(t)}
	r, err := openTask0PreparationRoots(b)
	if err != nil || !r.stable() {
		t.Fatal("separate private roots rejected")
	}
	defer r.Close()
	old := b.KeyRoot + ".original"
	if os.Rename(b.KeyRoot, old) != nil || os.Mkdir(b.KeyRoot, 0700) != nil {
		t.Fatal("rename fixture")
	}
	defer os.RemoveAll(old)
	if r.stable() {
		t.Fatal("replacement named key root accepted")
	}
	b.KeyRoot = b.EvidenceRoot
	if alias, err := openTask0PreparationRoots(b); err == nil {
		alias.Close()
		t.Fatal("same private evidence/key root accepted")
	}
}

func TestTask0ParentControlNeverAcceptsQualificationOrLocators(t *testing.T) {
	r := task0PreparationResult{Schema: "aipt.private.b007-task0-preparation-result/v2", BindingSHA: strings.Repeat("a", 64), RunID: task0DiagnosticRunID, Status: "COMPLETED_NON_QUAL", EvidenceRootSHA: strings.Repeat("b", 64), Generation: strings.Repeat("d", 64), CAAdmissionNonce: strings.Repeat("e", 64), SetupCreated: 2, SetupJoined: 2, SetupWaited: true}
	if !task0ParentResultValid(r, r.BindingSHA) {
		t.Fatal("exact typed control rejected")
	}
	for _, scenario := range []string{"qualification", "foreign_run", "foreign_binding", "locator_root", "missing_root"} {
		t.Run(scenario, func(t *testing.T) {
			changed := r
			switch scenario {
			case "qualification":
				changed.Status = "QUALIFIED"
			case "foreign_run":
				changed.RunID = "another-run"
			case "foreign_binding":
				changed.BindingSHA = strings.Repeat("c", 64)
			case "locator_root":
				changed.EvidenceRootSHA = "/private/run"
			case "missing_root":
				changed.EvidenceRootSHA = ""
			}
			if task0ParentResultValid(changed, r.BindingSHA) {
				t.Fatal("foreign control accepted")
			}
		})
	}
	for _, raw := range []string{"{}", "{\"schema\":\"caller\"}", "{\"schema\":\"a\",\"Schema\":\"a\"}"} {
		if _, err := decodeTask0ParentBinding([]byte(raw), inputSHA([]byte(raw))); err == nil {
			t.Fatal("unaccepted Parent binding accepted")
		}
		if _, err := decodeTask0Preparation([]byte(raw), inputSHA([]byte(raw))); err == nil {
			t.Fatal("unaccepted PREP binding accepted")
		}
	}
	if RunAcceptedTask0Parent("") == nil || RunAcceptedTask0Preparation("") == nil {
		t.Fatal("unbound build started a preparation path")
	}
	for _, value := range []string{"", " ", "credential\n", "credential\x00", strings.Repeat("x", 4097)} {
		if task0PreparationCredentialValid(value) {
			t.Fatal("invalid credential control accepted")
		}
	}
	if !task0PreparationCredentialValid("NON-CANON-no-real-credential") {
		t.Fatal("plain credential control rejected")
	}
}

func TestPostgresTask0PreparationEnrollsOriginalQueueOnceWithoutExecution(t *testing.T) {
	pool := pilotPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := task0ManifestFixture(t)
	m := f.Manifest
	m.RunID = task0DiagnosticRunID
	m.CanonicalSHA256 = ""
	var err error
	f, err = testplan.BindRunManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := postgres.NewQueueStore(pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := runcontrol.NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	options := task0DiagnosticServiceOptions(ctx, queue, reader, f)
	if task0EnrollDiagnostic(ctx, options) != nil {
		t.Fatal("original B006 enrollment rejected")
	}
	if task0EnrollDiagnostic(ctx, options) == nil {
		t.Fatal("second enrollment accepted")
	}
	record, err := queue.GetRun(ctx, task0DiagnosticRunID)
	if err != nil || record.Status != postgres.RunQueued || record.QualificationEligible || record.ManifestSHA256 != f.Digest || record.RequiredResourceID != options.Definitions[0].Input.RequiredResourceID {
		t.Fatal("enrollment changed original non-QUAL queue record")
	}
	attempts, err := queue.ReadAttempts(ctx, task0DiagnosticRunID)
	if err != nil || len(attempts) != 0 {
		t.Fatal("enrollment started an attempt")
	}
	service, err := runcontrol.New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Stop(context.Background())
	if _, err := service.RunNext(ctx); err == nil {
		t.Fatal("missing concrete executor/reports authorized execution")
	}
	if _, err := task0WaitDiagnostic(ctx, service); err == nil {
		t.Fatal("queued record accepted as completed")
	}
}
