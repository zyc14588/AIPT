package evidence

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestPrivateAuditDescriptorGenerationUsesExactObjectsAcrossParentReplacement(t *testing.T) {
	input, key, verifier := fixturePrivateAudit(t, fixtureExportProfile())
	parentPath := filepath.Dir(input.Destination)
	parent, err := os.Open(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	raw, err := os.Open(input.RawCapture)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// The old path form must keep refusing proc FD/symlink ancestors. A failed
	// path acquisition does not contact the verifier or consume the fresh key.
	bad := input
	bad.Destination = fmt.Sprintf("/proc/self/fd/%d/%s", parent.Fd(), filepath.Base(input.Destination))
	if _, err := generatePrivateAuditReady(context.Background(), bad, key, verifier); err == nil || verifier.proofRequests != 0 {
		t.Fatal("path entry accepted a proc ancestor", err)
	}
	if os.Rename(parentPath, parentPath+"-held") != nil || os.Mkdir(parentPath, 0700) != nil || os.Rename(input.RawCapture, input.RawCapture+"-held") != nil || os.Mkdir(input.RawCapture, 0700) != nil {
		t.Fatal("fixture ancestor replacement")
	}
	t.Cleanup(func() { os.RemoveAll(parentPath + "-held") })
	// Advancing caller cursors cannot empty an independent verification stream.
	if _, err := parent.ReadDir(-1); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ReadDir(-1); err != nil {
		t.Fatal(err)
	}
	at := input
	at.Destination, at.RawCapture = "", ""
	generated, err := generatePrivateAuditReadyAt(context.Background(), parent, filepath.Base(input.Destination), raw, at, key, verifier)
	if err != nil || verifier.proofRequests != 1 {
		t.Fatal("held generation reopened a replaced ancestor", err)
	}
	if _, err := os.Stat(input.Destination); !os.IsNotExist(err) {
		t.Fatal("publication used replacement parent")
	}
	bundle, _, err := openPrivateDirectoryAt(parent, filepath.Base(input.Destination))
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()
	independent := &staticSourceVerifier{expected: input.Closure.Source}
	verified, err := verifyPrivateAuditReadyAt(context.Background(), bundle, key, independent)
	if err != nil || verified.Root != generated.Root || independent.proofRequests != 1 || !canonicalEqual(verified.Closure, generated.Closure) {
		t.Fatal("independent held bundle lost the original closure", err)
	}
}

func TestPrivateAuditDescriptorGenerationRejectsSameBytesRawMemberReplacementAtEveryProofBoundary(t *testing.T) {
	for _, boundary := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("boundary_%d", boundary), func(t *testing.T) {
			input, key, verifier := fixturePrivateAudit(t, fixtureExportProfile())
			parent, err := os.Open(filepath.Dir(input.Destination))
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			raw, err := os.Open(input.RawCapture)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			member := filepath.Join(input.RawCapture, EventsName)
			body, err := os.ReadFile(member)
			if err != nil {
				t.Fatal(err)
			}
			changed := false
			verifier.hook = func(call int) {
				if call != boundary {
					return
				}
				if os.Rename(member, member+"-retained") != nil || os.WriteFile(member, body, 0400) != nil {
					t.Fatal("fixture RAW inode replacement")
				}
				changed = true
			}
			at := input
			at.Destination, at.RawCapture = "", ""
			if _, err := generatePrivateAuditReadyAt(context.Background(), parent, filepath.Base(input.Destination), raw, at, key, verifier); err == nil || !changed || verifier.proofRequests != 1 {
				t.Fatal("RAW replacement escaped a held proof boundary", boundary, err)
			}
			if _, err := os.Lstat(input.Destination); !os.IsNotExist(err) {
				t.Fatal("changed RAW published a final bundle", err)
			}
			entries, err := parent.ReadDir(-1)
			if err != nil || len(entries) != 0 {
				t.Fatal("failed RAW retained staging or publication", err)
			}
		})
	}
}

func TestPrivateAuditDescriptorGenerationRejectsSelectorsKeyOverlapAndExistingTargets(t *testing.T) {
	for _, attack := range []string{"nil_parent", "nil_raw", "path_selector", "raw_selector", "bad_name", "existing_target", "target_symlink", "key_parent", "key_raw", "key_ancestor", "key_child"} {
		t.Run(attack, func(t *testing.T) {
			input, key, verifier := fixturePrivateAudit(t, fixtureExportProfile())
			parent, err := os.Open(filepath.Dir(input.Destination))
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			raw, err := os.Open(input.RawCapture)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			at := input
			at.Destination, at.RawCapture = "", ""
			name := filepath.Base(input.Destination)
			selectedParent, selectedRaw := parent, raw
			open := func(path string) *os.File {
				f, e := os.Open(path)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { f.Close() })
				return f
			}
			switch attack {
			case "nil_parent":
				selectedParent = nil
			case "nil_raw":
				selectedRaw = nil
			case "path_selector":
				at.Destination = input.Destination
			case "raw_selector":
				at.RawCapture = input.RawCapture
			case "bad_name":
				name = "../outside"
			case "existing_target":
				if os.Mkdir(input.Destination, 0700) != nil {
					t.Fatal("fixture target")
				}
			case "target_symlink":
				if os.Symlink(input.RawCapture, input.Destination) != nil {
					t.Fatal("fixture symlink")
				}
			case "key_parent":
				selectedParent = open(key.directoryPath)
			case "key_raw":
				selectedRaw = open(key.directoryPath)
			case "key_ancestor":
				selectedParent = open(filepath.Dir(key.directoryPath))
			case "key_child":
				path := filepath.Join(key.directoryPath, "child")
				if os.Mkdir(path, 0700) != nil {
					t.Fatal("fixture key child")
				}
				selectedParent = open(path)
			}
			if _, err := generatePrivateAuditReadyAt(context.Background(), selectedParent, name, selectedRaw, at, key, verifier); err == nil || verifier.proofRequests != 0 {
				t.Fatal("descriptor boundary accepted selector/overlap/target", attack, err)
			}
		})
	}
}

func TestPrivateAuditHeldDirectoriesSurvivePathReplacementWithoutReopen(t *testing.T) {
	input, key, v := fixturePrivateAudit(t, fixtureExportProfile())
	generated, err := generatePrivateAuditReady(context.Background(), input, key, v)
	if err != nil {
		t.Fatal(err)
	}
	keyDir, err := os.Open(key.directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer keyDir.Close()
	heldKey, err := LoadPrivateAuditKeyAt(keyDir, key.Reference())
	if err != nil {
		t.Fatal(err)
	}
	defer heldKey.Close()
	bundle, err := os.Open(input.Destination)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()
	oldKeyPath := key.directoryPath
	if os.Rename(oldKeyPath, oldKeyPath+"-retained") != nil || os.Mkdir(oldKeyPath, 0700) != nil ||
		os.Rename(input.Destination, input.Destination+"-retained") != nil || os.Mkdir(input.Destination, 0700) != nil {
		t.Fatal("fixture directory replacement failed")
	}
	independent := &staticSourceVerifier{expected: input.Closure.Source}
	verified, err := verifyPrivateAuditReadyAt(context.Background(), bundle, heldKey, independent)
	if err != nil || verified.Root != generated.Root || independent.proofRequests != 1 {
		t.Fatal("held verification reopened a substituted pathname", err)
	}
	if _, err := verifyPrivateAuditReady(context.Background(), input.Destination, key, independent); err == nil {
		t.Fatal("path-based verification accepted substituted directories")
	}
	if _, err := verifyPrivateAuditReadyAt(context.Background(), keyDir, heldKey, independent); err == nil {
		t.Fatal("key and bundle directory identity were allowed to coincide")
	}
}

func TestPrivateAuditConcurrentHeldVerificationHasIndependentDirectoryStreams(t *testing.T) {
	input, key, v := fixturePrivateAudit(t, fixtureExportProfile())
	generated, err := generatePrivateAuditReady(context.Background(), input, key, v)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.Open(input.Destination)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			independent := &staticSourceVerifier{expected: input.Closure.Source}
			verified, err := verifyPrivateAuditReadyAt(context.Background(), bundle, key, independent)
			if err != nil || verified.Root != generated.Root || independent.proofRequests != 1 {
				t.Error("concurrent verifier lost its independent directory or source proof", err)
			}
		})
	}
	group.Wait()
}

// A private local schema check may retain this synthetic manifest. The optional
// output is test-only; production never accepts a source verifier or locator.
func TestPrivateAuditCanonicalManifestSchemaProbe(t *testing.T) {
	input, key, verifier := fixturePrivateAudit(t, fixtureExportProfile())
	held, err := generatePrivateAuditReady(context.Background(), input, key, verifier)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := canonicalLine(held.Manifest)
	if err != nil || digestText(encoded) != held.Root || bytes.Contains(encoded, []byte("NON_CANON_HIDDEN_BODY_CANARY")) {
		t.Fatal("manifest is not the exact canonical private root without body plaintext")
	}
	if target := os.Getenv("AIPT_Q011_TEST_SCHEMA_OUTPUT"); target != "" {
		dir, _, err := openPrivateDirectoryPath(target)
		if err != nil {
			t.Fatal("private schema fixture output rejected")
		}
		defer dir.Close()
		if err := writePrivateAuditFile(dir, "manifest-schema.fixture.json", encoded); err != nil {
			t.Fatal("private schema fixture could not be exclusively retained")
		}
	}
}

// All fixtures are NON_CANON and use the existing unexported offline source
// seam. Exported production entry points never accept this verifier.
func fixturePrivateAudit(t *testing.T, p ExportProfile) (GenerateAuditReadyInput, *PrivateAuditKey, *staticSourceVerifier) {
	t.Helper()
	rawPath := filepath.Join(privateTempDir(t), "private-synthetic-raw")
	source := fixtureSourceIdentity()
	source.Repository = "https://github.com/zyc14588/AIPT"
	if _, err := ExportRawCapture(context.Background(), &staticSource{snapshot: fixtureSnapshot()}, ExportInput{Destination: rawPath, Source: source, StreamID: "synthetic-ledger"}); err != nil {
		t.Fatal(err)
	}
	input, verifier := fixtureAuditInputForRaw(t, rawPath, p)
	key, err := CreatePrivateAuditKey(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { key.Close() })
	input.Destination = filepath.Join(privateTempDir(t), "private-audit")
	input.Disclosure = Disclosure{Profile: DisclosurePrivateFull, ContainsUnpublishedContent: true, Encryption: Encryption{Status: EncryptionEncrypted, Scheme: PrivateAuditEncryption, KeyReference: key.Reference()}}
	input.CoreClassifications.RawCapture = ContentTableHiddenRemote
	input.CoreClassifications.RunEvidenceClosure = ContentTableHiddenRemote
	input.CoreClassifications.ReplayEvidence = ContentTableHiddenRemote
	input.CoreClassifications.RunReport = ContentTableHiddenRemote
	input.CoreClassifications.ReportDerivatives = ContentTableHiddenRemote
	input.Supplemental = append(input.Supplemental, LogicalAssetInput{Path: "private/model-response.txt", MediaType: "text/plain", Classification: ContentTableHiddenRemote, ContentKind: ContentKindGameBody, Data: []byte("NON_CANON_HIDDEN_BODY_CANARY")})
	return input, key, verifier
}

func TestPrivateAuditEncryptionRoundTripAndFreshIndependentProof(t *testing.T) {
	input, key, v := fixturePrivateAudit(t, fixtureExportProfile())
	generated, err := generatePrivateAuditReady(context.Background(), input, key, v)
	if err != nil {
		t.Fatal(err, "fresh_source_requests", v.proofRequests, "source_boundaries", v.calls)
	}
	if v.proofRequests != 1 {
		t.Fatal("generation did not use exactly one fresh source request", v.proofRequests)
	}
	for _, name := range []string{RawEventsAssetName, RawManifestAssetName, RawRootAssetName, RunClosureName, ReplayEvidenceName, RunReportName, "private/model-response.txt"} {
		if len(generated.LogicalAssets[name]) == 0 {
			t.Fatal("required private evidence lost", name)
		}
	}
	if !bytes.Equal(generated.LogicalAssets["private/model-response.txt"], []byte("NON_CANON_HIDDEN_BODY_CANARY")) {
		t.Fatal("private body changed")
	}
	for _, name := range mustPrivateFiles(t, input.Destination) {
		body, err := os.ReadFile(filepath.Join(input.Destination, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte("NON_CANON_HIDDEN_BODY_CANARY")) || bytes.Contains(body, []byte("synthetic action receipt evidence")) {
			t.Fatal("plaintext private evidence published")
		}
		if strings.HasSuffix(name, ".key") {
			t.Fatal("key in bundle")
		}
	}
	loaded, err := LoadPrivateAuditKey(key.directoryPath, key.Reference())
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	independent := &staticSourceVerifier{expected: input.Closure.Source}
	verified, err := verifyPrivateAuditReady(context.Background(), input.Destination, loaded, independent)
	if err != nil || verified.Root != generated.Root || independent.proofRequests != 1 || !canonicalEqual(verified.Closure, generated.Closure) || !canonicalEqual(verified.Report, generated.Report) {
		t.Fatal("independent private verification failed", err)
	}
	if _, err := generatePrivateAuditReady(context.Background(), input, loaded, independent); err == nil {
		t.Fatal("loaded verification handle generated a bundle")
	}
	input.Destination = filepath.Join(privateTempDir(t), "reuse-key")
	if _, err := generatePrivateAuditReady(context.Background(), input, key, v); err == nil {
		t.Fatal("consumed key generated another bundle")
	}
}

func mustPrivateFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names
}

func TestPrivateAuditDeterministicPlaintextAndDistinctCiphertextIdentity(t *testing.T) {
	input, k, v := fixturePrivateAudit(t, fixtureExportProfile())
	first, err := generatePrivateAuditReady(context.Background(), input, k, v)
	if err != nil {
		t.Fatal(err)
	}
	other, err := CreatePrivateAuditKey(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	input.Destination = filepath.Join(privateTempDir(t), "second-private-audit")
	input.Disclosure.Encryption.KeyReference = other.Reference()
	second, err := generatePrivateAuditReady(context.Background(), input, other, v)
	if err != nil {
		t.Fatal(err)
	}
	if first.Manifest.PlaintextRoot != second.Manifest.PlaintextRoot || first.Root == second.Root || first.Manifest.Disclosure.Encryption.KeyReference == second.Manifest.Disclosure.Encryption.KeyReference {
		t.Fatal("plaintext/ciphertext identities confused")
	}
	for i, a := range first.Manifest.Members {
		if a.Nonce == second.Manifest.Members[i].Nonce || !canonicalEqual(a.Plaintext, second.Manifest.Members[i].Plaintext) {
			t.Fatal("per-bundle encryption did not preserve plaintext member identity")
		}
	}
}

func TestPrivateAuditChunkReassemblyIsExact(t *testing.T) {
	p := fixtureExportProfile()
	p.InlineThreshold = 8
	p.ChunkSize = 4096
	input, key, v := fixturePrivateAudit(t, p)
	canary := bytes.Repeat([]byte("NON_CANON_HIDDEN_LARGE_BODY\n"), 1000)
	input.Supplemental[len(input.Supplemental)-1].Data = canary
	generated, err := generatePrivateAuditReady(context.Background(), input, key, v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated.LogicalAssets["private/model-response.txt"], canary) {
		t.Fatal("chunked private body changed")
	}
	found := false
	for _, a := range generated.BundleIndex.LogicalAssets {
		if a.Path == "private/model-response.txt" {
			found = a.Storage.Kind == "CONTENT_ADDRESSED_CHUNKS" && len(a.Storage.Chunks) > 1
		}
	}
	if !found {
		t.Fatal("fixture did not use real chunk route")
	}
}

func rewritePrivateFixture(path string, body []byte) error {
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0400)
}

func resealPrivateManifest(t *testing.T, dir string, m PrivateAuditManifest) {
	t.Helper()
	body, err := canonicalLine(m)
	if err != nil {
		t.Fatal(err)
	}
	if err = rewritePrivateFixture(filepath.Join(dir, ManifestName), body); err != nil {
		t.Fatal(err)
	}
	if err = rewritePrivateFixture(filepath.Join(dir, RootName), []byte(digestText(body)+"\n")); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateAuditTamperAndCrossRunSubstitutionRefused(t *testing.T) {
	for _, attack := range []string{"ciphertext", "truncated_ciphertext", "wrong_key", "nonce", "reused_nonce", "source", "run_id", "run_manifest", "ledger_tail", "ordinal", "plaintext_sha", "plaintext_size", "path_escape", "case_alias", "unknown_field", "extra_member", "missing_member", "cross_bundle_ciphertext", "classification_public", "plaintext_fallback"} {
		t.Run(attack, func(t *testing.T) {
			input, key, v := fixturePrivateAudit(t, fixtureExportProfile())
			generated, err := generatePrivateAuditReady(context.Background(), input, key, v)
			if err != nil {
				t.Fatal(err)
			}
			var m PrivateAuditManifest
			manifestBytes, err := os.ReadFile(filepath.Join(input.Destination, ManifestName))
			if err != nil || json.Unmarshal(manifestBytes, &m) != nil {
				t.Fatal("fixture manifest missing")
			}
			checkKey := key
			switch attack {
			case "ciphertext", "truncated_ciphertext":
				path := filepath.Join(input.Destination, m.Members[0].Path)
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if attack == "ciphertext" {
					body[0] ^= 1
				} else {
					body = body[:len(body)-1]
				}
				m.Members[0].Bytes = int64(len(body))
				m.Members[0].SHA256 = digestText(body)
				if rewritePrivateFixture(path, body) != nil {
					t.Fatal("fixture write failed")
				}
				resealPrivateManifest(t, input.Destination, m)
			case "wrong_key":
				checkKey, err = CreatePrivateAuditKey(privateTempDir(t))
				if err != nil {
					t.Fatal(err)
				}
				defer checkKey.Close()
				m.Disclosure.Encryption.KeyReference = checkKey.Reference()
				resealPrivateManifest(t, input.Destination, m)
			case "nonce":
				body, _ := hex.DecodeString(m.Members[0].Nonce)
				body[0] ^= 1
				m.Members[0].Nonce = hex.EncodeToString(body)
				resealPrivateManifest(t, input.Destination, m)
			case "reused_nonce":
				m.Members[1].Nonce = m.Members[0].Nonce
				resealPrivateManifest(t, input.Destination, m)
			case "source":
				m.Source.Commit = repeatSHA("a")[:40]
				m.RemoteVerification.Commit = m.Source.Commit
				m.PlaintextRoot, _ = privatePlainRoot(m)
				resealPrivateManifest(t, input.Destination, m)
			case "run_id":
				m.RunID += "-foreign"
				m.PlaintextRoot, _ = privatePlainRoot(m)
				resealPrivateManifest(t, input.Destination, m)
			case "run_manifest":
				m.RunManifest.CanonicalSHA256 = repeatSHA("b")
				m.PlaintextRoot, _ = privatePlainRoot(m)
				resealPrivateManifest(t, input.Destination, m)
			case "ledger_tail":
				tail := repeatSHA("e")
				if m.Ledger.TailEventHash != nil && *m.Ledger.TailEventHash == tail {
					t.Fatal("tamper fixture must change the ledger tail")
				}
				m.Ledger.TailEventHash = &tail
				m.PlaintextRoot, _ = privatePlainRoot(m)
				resealPrivateManifest(t, input.Destination, m)
			case "ordinal":
				m.Members[0].Ordinal = 1
				resealPrivateManifest(t, input.Destination, m)
			case "plaintext_sha":
				m.Members[0].Plaintext.SHA256 = repeatSHA("d")
				m.PlaintextRoot, _ = privatePlainRoot(m)
				resealPrivateManifest(t, input.Destination, m)
			case "plaintext_size":
				m.Members[0].Plaintext.Bytes++
				m.Members[0].Bytes++
				m.PlaintextRoot, _ = privatePlainRoot(m)
				resealPrivateManifest(t, input.Destination, m)
			case "path_escape":
				m.Members[0].Path = "../foreign.bin"
				resealPrivateManifest(t, input.Destination, m)
			case "case_alias", "unknown_field":
				var object map[string]any
				if json.Unmarshal(manifestBytes, &object) != nil {
					t.Fatal("fixture decode failed")
				}
				if attack == "case_alias" {
					object["Schema"] = object["schema"]
					delete(object, "schema")
				} else {
					object["foreign_selector"] = true
				}
				body, _ := canonicalLine(object)
				if rewritePrivateFixture(filepath.Join(input.Destination, ManifestName), body) != nil || rewritePrivateFixture(filepath.Join(input.Destination, RootName), []byte(digestText(body)+"\n")) != nil {
					t.Fatal("fixture reseal failed")
				}
			case "extra_member":
				if os.WriteFile(filepath.Join(input.Destination, "extra.bin"), []byte("NON_CANON"), 0600) != nil {
					t.Fatal("fixture write failed")
				}
			case "missing_member":
				if os.Remove(filepath.Join(input.Destination, m.Members[0].Path)) != nil {
					t.Fatal("fixture remove failed")
				}
			case "cross_bundle_ciphertext":
				other, key2, v2 := fixturePrivateAudit(t, fixtureExportProfile())
				foreign, err := generatePrivateAuditReady(context.Background(), other, key2, v2)
				if err != nil {
					t.Fatal(err)
				}
				body, err := os.ReadFile(filepath.Join(other.Destination, foreign.Manifest.Members[0].Path))
				if err != nil {
					t.Fatal(err)
				}
				m.Members[0].SHA256 = digestText(body)
				m.Members[0].Nonce = foreign.Manifest.Members[0].Nonce
				if rewritePrivateFixture(filepath.Join(input.Destination, m.Members[0].Path), body) != nil {
					t.Fatal("fixture swap failed")
				}
				resealPrivateManifest(t, input.Destination, m)
			case "classification_public":
				m.Disclosure.Profile = DisclosurePublic
				resealPrivateManifest(t, input.Destination, m)
			case "plaintext_fallback":
				m.Disclosure.Encryption.Status = EncryptionUnencrypted
				resealPrivateManifest(t, input.Destination, m)
			}
			if _, err = verifyPrivateAuditReady(context.Background(), input.Destination, checkKey, v); err == nil {
				t.Fatal("resealed attack accepted", attack, generated.Root)
			}
		})
	}
}

func TestPrivateAuditForbiddenContentAndOriginalPublicRefusal(t *testing.T) {
	for _, bad := range []string{"credential_class", "human_private", "local_secret", "credential_kind", "locator_kind", "credential_body", "public_game_body", "raw_public", "wrong_key_reference", "qualifying", "mirror", "shared_key_directory"} {
		t.Run(bad, func(t *testing.T) {
			input, key, v := fixturePrivateAudit(t, fixtureExportProfile())
			i := len(input.Supplemental) - 1
			switch bad {
			case "credential_class":
				input.Supplemental[i].Classification = ContentCredentialSecret
			case "human_private":
				input.Supplemental[i].Classification = ContentHumanPrivateData
			case "local_secret":
				input.Supplemental[i].Classification = ContentLocalOnlySecret
			case "credential_kind":
				input.Supplemental[i].ContentKind = ContentKindCredential
			case "locator_kind":
				input.Supplemental[i].ContentKind = ContentKindPrivateAssetLocator
			case "credential_body":
				input.Supplemental[i].Data = []byte(strings.Join([]string{"Bearer", "SYNTHETIC_NON_SECRET_CANARY"}, " "))
			case "public_game_body":
				input.Supplemental[i].Classification = ContentPublic
			case "raw_public":
				input.CoreClassifications.RawCapture = ContentPublic
			case "wrong_key_reference":
				input.Disclosure.Encryption.KeyReference = "key-" + strings.Repeat("a", 32)
			case "qualifying":
				input.Report.QualificationEligible = true
			case "mirror":
				input.MirrorPath = privateTempDir(t)
			case "shared_key_directory":
				input.Destination = filepath.Join(key.directoryPath, "bundle")
			}
			if _, err := generatePrivateAuditReady(context.Background(), input, key, v); err == nil {
				t.Fatal("forbidden private input accepted")
			}
			if _, err := os.Lstat(input.Destination); !os.IsNotExist(err) {
				t.Fatal("failed private input published output")
			}
			if _, err := GenerateAuditReady(context.Background(), input); !errors.Is(err, ErrEncryptionRequired) {
				t.Fatal("original public entry changed its private refusal", err)
			}
		})
	}
}

func TestPrivateAuditKeyAliasingMutationPermissionsAndFailedSource(t *testing.T) {
	for _, scenario := range []string{"key_changed", "key_symlink", "key_hardlink", "key_mode", "directory_mode", "directory_symlink", "source_failure", "raw_changed_during_proof", "input_changed_during_proof"} {
		t.Run(scenario, func(t *testing.T) {
			input, key, v := fixturePrivateAudit(t, fixtureExportProfile())
			path := filepath.Join(key.directoryPath, key.Reference()+".key")
			switch scenario {
			case "key_changed":
				if os.Chmod(path, 0600) != nil || os.WriteFile(path, bytes.Repeat([]byte{7}, 32), 0400) != nil || os.Chmod(path, 0400) != nil {
					t.Fatal("fixture mutation failed")
				}
			case "key_symlink":
				other := filepath.Join(privateTempDir(t), "foreign.key")
				if os.Rename(path, other) != nil || os.Symlink(other, path) != nil {
					t.Fatal("fixture alias failed")
				}
			case "key_hardlink":
				if os.Link(path, filepath.Join(privateTempDir(t), "alias.key")) != nil {
					t.Fatal("fixture hardlink failed")
				}
			case "key_mode":
				if os.Chmod(path, 0600) != nil {
					t.Fatal("fixture mode failed")
				}
			case "directory_mode":
				if os.Chmod(key.directoryPath, 0755) != nil {
					t.Fatal("fixture mode failed")
				}
			case "directory_symlink":
				other := key.directoryPath + "-moved"
				if os.Rename(key.directoryPath, other) != nil || os.Symlink(other, key.directoryPath) != nil {
					t.Fatal("fixture directory alias failed")
				}
				t.Cleanup(func() { os.Remove(key.directoryPath); os.Rename(other, key.directoryPath) })
			case "source_failure":
				v.err = ErrSourceUnverified
			case "raw_changed_during_proof":
				v.hook = func(int) {
					file := filepath.Join(input.RawCapture, EventsName)
					if os.WriteFile(file, []byte("NON_CANON_CHANGED_RAW\n"), 0600) != nil {
						t.Fatal("fixture raw mutation failed")
					}
				}
			case "input_changed_during_proof":
				v.hook = func(int) { input.Supplemental[0].Data[0] ^= 1 }
			}
			if _, err := generatePrivateAuditReady(context.Background(), input, key, v); err == nil {
				t.Fatal("changed key/source/input accepted")
			}
			if _, err := os.Lstat(input.Destination); !os.IsNotExist(err) {
				t.Fatal("failed generation published output")
			}
		})
	}
}
