package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fixtureGitHubRoundTripper func(*http.Request) (*http.Response, error)

func (transport fixtureGitHubRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

type fixtureOnlineVerifier struct{ client *http.Client }

func (verifier fixtureOnlineVerifier) Verify(ctx context.Context, source SourceIdentity) (RemoteProvenanceReceipt, error) {
	return verifyGitHubSource(ctx, source, verifier.client)
}

func fixtureRemoteSource() SourceIdentity {
	return SourceIdentity{Repository: "https://github.com/AIPT-Synthetic/fixture", Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40)}
}
func fixtureCommitBody(source SourceIdentity) string {
	return `{"sha":"` + source.Commit + `","tree":{"sha":"` + source.Tree + `","url":"https://api.github.com/omitted"},"message":"ignored metadata"}`
}
func fixtureGitHubClient(t *testing.T, source SourceIdentity, status int, body string, calls *int) *http.Client {
	t.Helper()
	return &http.Client{Transport: fixtureGitHubRoundTripper(func(request *http.Request) (*http.Response, error) {
		*calls++
		_, owner, name, err := canonicalGitHubRepository(source.Repository)
		if err != nil || request.Method != http.MethodGet || request.URL.Scheme != "https" || request.URL.Host != "api.github.com" ||
			request.URL.Path != "/repos/"+owner+"/"+name+"/git/commits/"+source.Commit || request.URL.RawQuery != "" || request.URL.User != nil ||
			request.Header.Get("Authorization") != "" || request.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("request escaped fixed anonymous exact-object policy")
		}
		if deadline, ok := request.Context().Deadline(); !ok || time.Until(deadline) > remoteRequestTimeout {
			t.Error("request lacks bounded deadline")
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1}, nil
	}), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestRemoteProvenanceP01ExactCommitTreeAndBoundDeterministicReceipt(t *testing.T) {
	source := fixtureRemoteSource()
	calls := 0
	client := fixtureGitHubClient(t, source, 200, fixtureCommitBody(source), &calls)
	first, err := verifyGitHubSource(context.Background(), source, client)
	if err != nil || validateRemoteProvenanceReceipt(first, source) != nil {
		t.Fatalf("exact proof failed: %v", err)
	}
	second, err := verifyGitHubSource(context.Background(), source, client)
	a, _ := canonicalLine(first)
	b, _ := canonicalLine(second)
	var fields map[string]any
	if err != nil || !bytes.Equal(a, b) || json.Unmarshal(a, &fields) != nil || len(fields) != 8 || a[len(a)-1] != '\n' {
		t.Fatal("receipt is not exactly eight deterministic canonical fields")
	}
	input, _ := fixtureAuditInput(t, fixtureExportProfile())
	input.Destination = filepath.Join(privateTempDir(t), "audit")
	verifier := fixtureOnlineVerifier{client: client}
	before := calls
	generated, err := generateAuditReady(context.Background(), input, verifier)
	if err != nil {
		t.Fatal(err)
	}
	receipt, exists := generated.LogicalAssets[RemoteProvenanceName]
	if !exists || !bytes.Equal(receipt, a) || calls-before != 1 {
		t.Fatal("generation did not bind a fresh proof into its root")
	}
	before = calls
	verified, err := verifyAuditReady(context.Background(), input.Destination, verifier)
	if err != nil || verified.Root != generated.Root || calls != before+1 {
		t.Fatal("independent verification did not perform its own fresh request")
	}
	before = calls
	if _, err := verifyAuditReady(context.Background(), input.Destination, verifier); err != nil || calls != before+1 {
		t.Fatal("a separate verification reused a previous operation's receipt")
	}
	input.Destination = filepath.Join(privateTempDir(t), "second-audit")
	before = calls
	if next, err := generateAuditReady(context.Background(), input, verifier); err != nil || next.Root != generated.Root || calls != before+1 {
		t.Fatal("a separate generation did not obtain exactly one new proof")
	}
	bad := first
	bad.Tree = strings.Repeat("3", 40)
	if validateRemoteProvenanceReceipt(bad, source) == nil {
		t.Fatal("tree-confused receipt accepted")
	}
}

func TestRemoteProvenanceP02Remote404Fails(t *testing.T) {
	source := fixtureRemoteSource()
	calls := 0
	receipt, err := verifyGitHubSource(context.Background(), source, fixtureGitHubClient(t, source, 404, `{"message":"not found"}`, &calls))
	if !errors.Is(err, ErrSourceUnverified) || receipt != (RemoteProvenanceReceipt{}) || calls != 1 {
		t.Fatal("404 minted a proof")
	}
}
func TestRemoteProvenanceP03CommitMismatchFails(t *testing.T) {
	source := fixtureRemoteSource()
	other := source
	other.Commit = strings.Repeat("3", 40)
	calls := 0
	if _, err := verifyGitHubSource(context.Background(), source, fixtureGitHubClient(t, source, 200, fixtureCommitBody(other), &calls)); !errors.Is(err, ErrSourceUnverified) {
		t.Fatal("commit mismatch accepted")
	}
}
func TestRemoteProvenanceP04TreeMismatchFails(t *testing.T) {
	source := fixtureRemoteSource()
	other := source
	other.Tree = strings.Repeat("3", 40)
	calls := 0
	if _, err := verifyGitHubSource(context.Background(), source, fixtureGitHubClient(t, source, 200, fixtureCommitBody(other), &calls)); !errors.Is(err, ErrSourceUnverified) {
		t.Fatal("tree mismatch accepted")
	}
}
func TestRemoteProvenanceP05RedirectNeverFollowed(t *testing.T) {
	source := fixtureRemoteSource()
	calls := 0
	client, err := newGitHubHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	client.Transport = fixtureGitHubRoundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: 302, Header: http.Header{"Location": []string{"https://attacker.invalid/"}}, Body: io.NopCloser(strings.NewReader("")), ContentLength: 0,
		}, nil
	})
	receipt, err := verifyGitHubSource(context.Background(), source, client)
	if !errors.Is(err, ErrSourceUnverified) || calls != 1 || receipt != (RemoteProvenanceReceipt{}) {
		t.Fatal("redirect reached another endpoint or minted a proof")
	}
}

type unlimitedFixtureBody struct {
	read   int64
	closed bool
}

func (body *unlimitedFixtureBody) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 'x'
	}
	body.read += int64(len(buffer))
	return len(buffer), nil
}
func (body *unlimitedFixtureBody) Close() error { body.closed = true; return nil }
func TestRemoteProvenanceP06OversizedResponseStopsBeforeUnboundedBuffering(t *testing.T) {
	body := &unlimitedFixtureBody{}
	client := &http.Client{Transport: fixtureGitHubRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: body, ContentLength: -1}, nil
	})}
	receipt, err := verifyGitHubSource(context.Background(), fixtureRemoteSource(), client)
	if !errors.Is(err, ErrSourceUnverified) || receipt != (RemoteProvenanceReceipt{}) || body.read != maxRemoteResponseBytes+1 || !body.closed {
		t.Fatalf("unbounded capture: bytes=%d closed=%v", body.read, body.closed)
	}
}
func TestRemoteProvenanceP07RateLimitFailsClosed(t *testing.T) {
	source := fixtureRemoteSource()
	calls := 0
	receipt, err := verifyGitHubSource(context.Background(), source, fixtureGitHubClient(t, source, 429, `{"message":"rate limit"}`, &calls))
	if !errors.Is(err, ErrRemoteProvenanceUnavailable) || !errors.Is(err, ErrSourceUnverified) || receipt != (RemoteProvenanceReceipt{}) {
		t.Fatal("rate limit became success or fallback")
	}
}
func TestRemoteProvenanceP08FakeMirrorAndUnpushedCommitCannotMintRemoteProof(t *testing.T) {
	source, cache := syntheticGitMirror(t)
	source.Repository = fixtureRemoteSource().Repository
	cache.ExpectedRepository = source.Repository
	runGitTest(t, "--git-dir", cache.MirrorPath, "remote", "set-url", "origin", source.Repository)
	local, err := cache.Verify(context.Background(), source)
	if err != nil || local.Status != localObjectMatchStatus || local.Status == remoteVerificationStatus {
		t.Fatal("local object minted remote authority")
	}
	calls := 0
	receipt, err := verifyGitHubSource(context.Background(), source, fixtureGitHubClient(t, source, 404, `{}`, &calls))
	if !errors.Is(err, ErrSourceUnverified) || receipt != (RemoteProvenanceReceipt{}) {
		t.Fatal("unpublished local object became remote proof")
	}
}
func TestRemoteProvenanceP09PublicCallerCannotInjectFakeVerifier(t *testing.T) {
	if _, exists := reflect.TypeOf(GenerateAuditReadyInput{}).FieldByName("SourceVerifier"); exists {
		t.Fatal("production input still exposes a verifier")
	}
	if reflect.TypeOf(VerifyAuditReady).NumIn() != 2 {
		t.Fatal("public independent verifier accepts a caller verifier")
	}
	// A caller-supplied cancellation cannot turn a rejected request into a claim.
	input, _ := fixtureAuditInput(t, fixtureExportProfile())
	input.Destination = filepath.Join(privateTempDir(t), "audit")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := GenerateAuditReady(ctx, input)
	if err == nil || result.Root != "" {
		t.Fatal("cancelled public operation minted proof")
	}
	if _, err := os.Lstat(input.Destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected public operation left a bundle")
	}
}
func TestRemoteProvenanceP10CredentialQueryFragmentURLsRejectedBeforeRequest(t *testing.T) {
	for _, repository := range []string{"https://injected-user:injected-value@github.com/AIPT-Synthetic/fixture", "https://github.com/AIPT-Synthetic/fixture?injected-value=1", "https://github.com/AIPT-Synthetic/fixture#injected-value"} {
		source := fixtureRemoteSource()
		source.Repository = repository
		calls := 0
		receipt, err := verifyGitHubSource(context.Background(), source, fixtureGitHubClient(t, fixtureRemoteSource(), 200, fixtureCommitBody(source), &calls))
		if !errors.Is(err, ErrSourceUnverified) || calls != 0 || receipt != (RemoteProvenanceReceipt{}) || strings.Contains(err.Error(), "injected-value") {
			t.Fatal("credential-bearing source reached transport or output")
		}
	}
}
func TestRemoteProvenanceP11NonGitHubProviderIsUnsupported(t *testing.T) {
	source := fixtureRemoteSource()
	source.Repository = "https://example.invalid/fixture"
	calls := 0
	_, err := verifyGitHubSource(context.Background(), source, fixtureGitHubClient(t, fixtureRemoteSource(), 200, fixtureCommitBody(source), &calls))
	if !errors.Is(err, ErrRemoteProviderUnsupported) || calls != 0 {
		t.Fatal("non-GitHub source accepted or requested")
	}
}
func TestRemoteProvenanceP12NetworkUnavailableBlocksWithoutMirrorFallback(t *testing.T) {
	source := fixtureRemoteSource()
	calls := 0
	client := &http.Client{Transport: fixtureGitHubRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls++
		<-request.Context().Done()
		return nil, errors.New("untrusted network detail")
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	receipt, err := verifyGitHubSource(ctx, source, client)
	if !errors.Is(err, ErrRemoteProvenanceUnavailable) || receipt != (RemoteProvenanceReceipt{}) || calls != 1 || strings.Contains(err.Error(), "untrusted") {
		t.Fatal("unavailable endpoint minted proof or leaked cause")
	}
	input, verifier := fixtureAuditInput(t, fixtureExportProfile())
	input.Destination = filepath.Join(privateTempDir(t), "audit")
	generated, err := generateAuditReady(context.Background(), input, verifier)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	verified, err := verifyAuditReady(ctx, input.Destination, fixtureOnlineVerifier{client: client})
	if !errors.Is(err, ErrRemoteProvenanceUnavailable) || verified.Root != "" || generated.Root == "" {
		t.Fatal("old bound receipt was used as a fresh proof cache")
	}
}

func TestRemoteProvenanceTransportIgnoresProxyCAAndHTTPGlobals(t *testing.T) {
	invalidCA := filepath.Join(t.TempDir(), "untrusted-ca.pem")
	if err := os.WriteFile(invalidCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("SSL_CERT_FILE", invalidCA)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	original := http.DefaultTransport
	defer func() { http.DefaultTransport = original }()
	http.DefaultTransport = fixtureGitHubRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("production used global transport")
		return nil, ErrSourceUnverified
	})
	client, err := newGitHubHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.RootCAs == nil || len(transport.TLSClientConfig.RootCAs.Subjects()) == 0 ||
		transport.TLSClientConfig.ServerName != "api.github.com" || client.Timeout != remoteRequestTimeout || transport.TLSHandshakeTimeout <= 0 || transport.ResponseHeaderTimeout <= 0 || transport.MaxResponseHeaderBytes <= 0 || !transport.DisableCompression {
		t.Fatal("production transport trusts ambient proxy/CA/global state or lacks bounds")
	}
}
func TestRemoteProvenanceMalformedDuplicateDeepAndUnknownReceiptFieldsFail(t *testing.T) {
	source := fixtureRemoteSource()
	bodies := []string{`{`, fixtureCommitBody(source) + `{}`, `{"sha":"` + source.Commit + `","sha":"` + source.Commit + `","tree":{"sha":"` + source.Tree + `"}}`, strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40), "{\"sha\":\"\xff\"}"}
	for _, body := range bodies {
		calls := 0
		if _, err := verifyGitHubSource(context.Background(), source, fixtureGitHubClient(t, source, 200, body, &calls)); !errors.Is(err, ErrSourceUnverified) {
			t.Fatal("malformed/ambiguous response accepted")
		}
	}
	receipt, _ := receiptForSource(source)
	raw, _ := canonicalLine(receipt)
	var unknown RemoteProvenanceReceipt
	body := bytes.TrimSuffix(raw, []byte("\n"))
	body = append(body[:len(body)-1], []byte(`,"verification_timestamp":"forbidden"}`)...)
	if strictDecode(body, &unknown) == nil {
		t.Fatal("receipt accepted network metadata")
	}
}
func TestGitMirrorSignatureHelperCannotExecute(t *testing.T) {
	source, cache := syntheticGitMirror(t)
	marker := filepath.Join(t.TempDir(), "signature-helper-ran")
	helper := filepath.Join(t.TempDir(), "untrusted-signature-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n: > \""+marker+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	runGitTest(t, "--git-dir", cache.MirrorPath, "config", "log.showSignature", "true")
	runGitTest(t, "--git-dir", cache.MirrorPath, "config", "gpg.program", helper)
	// A commit with a signature header makes the original git-show path run
	// the configured helper. Prove the exploit fixture before testing the fix.
	commitFile := filepath.Join(privateTempDir(t), "signed-commit")
	commitBytes := "tree " + source.Tree + "\nauthor AIPT Synthetic <synthetic@example.invalid> 1767225600 +0000\ncommitter AIPT Synthetic <synthetic@example.invalid> 1767225600 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n fixture-signature\n -----END PGP SIGNATURE-----\n\nsynthetic signed fixture\n"
	if err := os.WriteFile(commitFile, []byte(commitBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	source.Commit = strings.TrimSpace(runGitTest(t, "--git-dir", cache.MirrorPath, "hash-object", "-t", "commit", "-w", commitFile))
	_ = exec.Command(trustedGitExecutable, "--git-dir", cache.MirrorPath, "show", "--no-patch", "--format=%T", source.Commit).Run()
	if _, err := os.Lstat(marker); err != nil {
		t.Fatal("original vulnerable path did not execute fixture helper")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	result, err := cache.Verify(context.Background(), source)
	if err != nil || result.Status != localObjectMatchStatus {
		t.Fatal("local consistency check failed")
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("signature helper ran")
	}
}
func TestGitMirrorOversizedOutputIsBoundedBeforeCapture(t *testing.T) {
	source, cache := syntheticGitMirror(t)
	// A syntactically valid large config produces a stdout stream well beyond
	// the bound. The real child must fail promptly and never mint any claim.
	config, err := os.OpenFile(filepath.Join(cache.MirrorPath, "config"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = config.WriteString("\n[remote \"origin\"]\nurl = https://example.invalid/" + strings.Repeat("x", 1<<20) + "\n")
	config.Close()
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	result, err := cache.Verify(context.Background(), source)
	if !errors.Is(err, ErrSourceUnverified) || result != (RemoteVerification{}) || time.Since(started) > 6*time.Second {
		t.Fatal("oversized Git output escaped byte/time bounds")
	}
	ctx, cancel := context.WithCancel(context.Background())
	output := &boundedGitOutput{maximum: 4, cancel: cancel}
	if _, err := output.Write([]byte("12345")); err == nil || output.buffer.Len() != 0 || ctx.Err() == nil {
		t.Fatal("Git writer buffered an oversized chunk before rejecting")
	}
}

func TestRemoteReceiptTamperingCannotBeResealedIntoValidBundle(t *testing.T) {
	for _, attack := range []string{"missing", "non-public", "wrong-kind", "tree", "metadata"} {
		t.Run(attack, func(t *testing.T) {
			input, verifier := fixtureAuditInput(t, fixtureExportProfile())
			input.Destination = filepath.Join(privateTempDir(t), "audit")
			if _, err := generateAuditReady(context.Background(), input, verifier); err != nil {
				t.Fatal(err)
			}
			if attack == "tree" || attack == "metadata" {
				physicalName := ""
				index := readJSONMap(t, filepath.Join(input.Destination, BundleIndexName))
				for _, raw := range index["logical_assets"].([]any) {
					asset := raw.(map[string]any)
					if asset["path"] == RemoteProvenanceName {
						physicalName = asset["storage"].(map[string]any)["path"].(string)
					}
				}
				if physicalName == "" {
					t.Fatal("fixture lacks physical receipt")
				}
				body := readJSONMap(t, filepath.Join(input.Destination, physicalName))
				if attack == "tree" {
					body["tree"] = strings.Repeat("3", 40)
				} else {
					body["verification_timestamp"] = "forbidden"
				}
				data, err := canonicalLine(body)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(input.Destination, physicalName), data, 0o600); err != nil {
					t.Fatal(err)
				}
				manifest := readJSONMap(t, filepath.Join(input.Destination, ManifestName))
				for _, raw := range manifest["normalized_assets"].([]any) {
					asset := raw.(map[string]any)
					if asset["path"] == physicalName {
						asset["bytes"], asset["sha256"] = len(data), digestText(data)
					}
				}
				writeCanonicalManifestAndRoot(t, input.Destination, manifest)
				rewriteBundleIndexAndRoot(t, input.Destination, func(index map[string]any) {
					for _, raw := range index["logical_assets"].([]any) {
						asset := raw.(map[string]any)
						if asset["path"] == RemoteProvenanceName {
							asset["bytes"], asset["sha256"] = len(data), digestText(data)
						}
					}
				})
			} else {
				rewriteBundleIndexAndRoot(t, input.Destination, func(index map[string]any) {
					assets := index["logical_assets"].([]any)
					for position, raw := range assets {
						asset := raw.(map[string]any)
						if asset["path"] != RemoteProvenanceName {
							continue
						}
						switch attack {
						case "missing":
							index["logical_assets"] = append(assets[:position], assets[position+1:]...)
						case "non-public":
							asset["classification"] = string(ContentUnreleasedRemote)
						case "wrong-kind":
							asset["content_kind"] = string(ContentKindSupplemental)
						}
						return
					}
					t.Fatal("fixture lacks receipt descriptor")
				})
			}
			if _, err := verifyAuditReady(context.Background(), input.Destination, verifier); err == nil {
				t.Fatal("resealed remote receipt attack accepted")
			}
		})
	}
}

func TestRemoteRepositoryIdentityHasOneCanonicalForm(t *testing.T) {
	for _, repository := range []string{"https://github.com/AIPT-Synthetic/fixture", "https://github.com/AIPT-Synthetic/fixture.git"} {
		canonical, owner, name, err := canonicalGitHubRepository(repository)
		if err != nil || canonical != fixtureRemoteSource().Repository || owner != "AIPT-Synthetic" || name != "fixture" {
			t.Fatal("accepted repository form is not canonical")
		}
	}
	for _, repository := range []string{"https://github.com/AIPT-Synthetic/fixture.git.git", "https://github.com:443/AIPT-Synthetic/fixture", "https://github.com/AIPT-Synthetic/fixture/", "https://github.com/AIPT-Synthetic/%66ixture", "https://github.com/AIPT-Synthetic/..", "https://github.com/AIPT-Synthetic/.git"} {
		if _, _, _, err := canonicalGitHubRepository(repository); err == nil {
			t.Fatal("ambiguous repository form accepted")
		}
	}
}

func TestExpectedGitHubRepositorySuffixFormsMatchBeforeFreshProof(t *testing.T) {
	canonical := fixtureRemoteSource().Repository
	for _, sourceRepository := range []string{canonical, canonical + ".git"} {
		for _, expectedRepository := range []string{canonical, canonical + ".git"} {
			t.Run(sourceRepository+"="+expectedRepository, func(t *testing.T) {
				source := fixtureRemoteSource()
				source.Repository = sourceRepository
				rawPath := filepath.Join(privateTempDir(t), "raw")
				if _, err := ExportRawCapture(context.Background(), &staticSource{snapshot: fixtureSnapshot()}, ExportInput{Destination: rawPath, Source: source, StreamID: "synthetic-ledger"}); err != nil {
					t.Fatal(err)
				}
				input, _ := fixtureAuditInputForRaw(t, rawPath, fixtureExportProfile())
				input.ExpectedRepository = expectedRepository
				input.Destination = filepath.Join(privateTempDir(t), "audit")
				calls := 0
				verifier := fixtureOnlineVerifier{client: fixtureGitHubClient(t, source, 200, fixtureCommitBody(source), &calls)}
				generated, err := generateAuditReady(context.Background(), input, verifier)
				if err != nil || calls != 1 || generated.Manifest.Source != source {
					t.Fatalf("equivalent form generation failed: %v, requests=%d", err, calls)
				}
				var receipt RemoteProvenanceReceipt
				if strictDecode(generated.LogicalAssets[RemoteProvenanceName], &receipt) != nil || receipt.Repository != canonical {
					t.Fatal("equivalent source form changed canonical receipt identity")
				}
			})
		}
	}
	input, verifier := fixtureAuditInput(t, fixtureExportProfile())
	input.ExpectedRepository = "https://github.com/AIPT-Synthetic/different"
	input.Destination = filepath.Join(privateTempDir(t), "rejected")
	if _, err := generateAuditReady(context.Background(), input, verifier); !errors.Is(err, ErrSourceUnverified) || verifier.proofRequests != 0 {
		t.Fatal("different repository passed or reached source transport")
	}
	if _, err := os.Lstat(input.Destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("repository mismatch left a bundle")
	}
}

func TestLocalMirrorUsesGitHubSuffixIdentityWithoutRemoteAuthority(t *testing.T) {
	source, cache := syntheticGitMirror(t)
	source.Repository = fixtureRemoteSource().Repository + ".git"
	cache.ExpectedRepository = fixtureRemoteSource().Repository
	runGitTest(t, "--git-dir", cache.MirrorPath, "remote", "set-url", "origin", cache.ExpectedRepository)
	result, err := cache.Verify(context.Background(), source)
	if err != nil || result.Status != localObjectMatchStatus {
		t.Fatalf("equivalent local mirror form failed: %v", err)
	}
	cache.ExpectedRepository = "https://github.com/AIPT-Synthetic/different"
	if _, err := cache.Verify(context.Background(), source); !errors.Is(err, ErrSourceUnverified) {
		t.Fatal("different local repository accepted")
	}
}

func TestExpectedRepositoryVerificationRejectsBeforeFreshRequest(t *testing.T) {
	input, _ := fixtureAuditInput(t, fixtureExportProfile())
	input.Destination = filepath.Join(privateTempDir(t), "audit")
	source := fixtureRemoteSource()
	calls := 0
	verifier := fixtureOnlineVerifier{client: fixtureGitHubClient(t, source, 200, fixtureCommitBody(source), &calls)}
	generated, err := generateAuditReady(context.Background(), input, verifier)
	if err != nil || calls != 1 {
		t.Fatalf("generation fixture: %v, requests=%d", err, calls)
	}
	for _, expected := range []string{"https://github.com/AIPT-Synthetic/different", source.Repository + ".git.git", source.Repository + "?injected-value=1", "https://injected-user:injected-value@github.com/AIPT-Synthetic/fixture"} {
		before := calls
		verified, err := verifyAuditReadyForRepository(context.Background(), input.Destination, expected, verifier)
		if !errors.Is(err, ErrSourceUnverified) || calls != before || verified.Root != "" || strings.Contains(err.Error(), "injected-value") {
			t.Fatal("unexpected repository reached the source transport or succeeded")
		}
	}
	for _, expected := range []string{source.Repository, source.Repository + ".git"} {
		before := calls
		verified, err := verifyAuditReadyForRepository(context.Background(), input.Destination, expected, verifier)
		if err != nil || calls != before+1 || verified.Root != generated.Root {
			t.Fatalf("expected repository verification: %v, requests=%d", err, calls-before)
		}
	}
	if reflect.TypeOf(VerifyAuditReadyForRepository).NumIn() != 3 {
		t.Fatal("expected-repository verification exposes a source-verifier injection argument")
	}
}

func TestPublicExpectedRepositoryRejectsInvalidIdentityBeforeOpeningBundle(t *testing.T) {
	for _, expected := range []string{"", "https://injected-user:injected-value@github.com/AIPT-Synthetic/fixture", "https://github.com/AIPT-Synthetic/fixture?injected-value=1"} {
		result, err := VerifyAuditReadyForRepository(context.Background(), filepath.Join(privateTempDir(t), "absent"), expected)
		if !errors.Is(err, ErrSourceUnverified) || result.Root != "" || strings.Contains(err.Error(), "injected-value") {
			t.Fatal("invalid expected identity did not fail before filesystem/network work")
		}
	}
}

func fixtureMirrorAuditInput(t *testing.T) (GenerateAuditReadyInput, *staticSourceVerifier, GitMirrorVerifier) {
	t.Helper()
	source, mirror := syntheticGitMirror(t)
	source.Repository = fixtureRemoteSource().Repository
	mirror.ExpectedRepository = source.Repository
	runGitTest(t, "--git-dir", mirror.MirrorPath, "remote", "set-url", "origin", source.Repository)
	rawPath := filepath.Join(privateTempDir(t), "raw")
	if _, err := ExportRawCapture(context.Background(), &staticSource{snapshot: fixtureSnapshot()}, ExportInput{Destination: rawPath, Source: source, StreamID: "synthetic-ledger"}); err != nil {
		t.Fatal(err)
	}
	input, verifier := fixtureAuditInputForRaw(t, rawPath, fixtureExportProfile())
	input.Destination = filepath.Join(privateTempDir(t), "audit")
	input.MirrorPath = mirror.MirrorPath
	return input, verifier, mirror
}

func TestGenerationMirrorChecksHeldSourceAndRequiresFreshRemoteProof(t *testing.T) {
	input, _, mirror := fixtureMirrorAuditInput(t)
	input.MirrorRemoteName = "alternate"
	runGitTest(t, "--git-dir", mirror.MirrorPath, "remote", "add", "alternate", input.ExpectedRepository+".git")
	source := input.Closure.Source
	calls := 0
	verifier := fixtureOnlineVerifier{client: fixtureGitHubClient(t, source, 200, fixtureCommitBody(source), &calls)}
	generated, err := generateAuditReady(context.Background(), input, verifier)
	if err != nil || generated.Manifest.Source != source || calls != 1 {
		t.Fatalf("held mirror generation: %v, requests=%d", err, calls)
	}
	for _, data := range generated.LogicalAssets {
		if bytes.Contains(data, []byte(input.MirrorPath)) {
			t.Fatal("local mirror path leaked into evidence")
		}
	}
	input.Destination = filepath.Join(privateTempDir(t), "unavailable")
	before := calls
	verifier = fixtureOnlineVerifier{client: fixtureGitHubClient(t, source, 503, "{}", &calls)}
	if result, err := generateAuditReady(context.Background(), input, verifier); !errors.Is(err, ErrRemoteProvenanceUnavailable) || result.Root != "" || calls != before+1 {
		t.Fatal("matching mirror bypassed fresh remote proof or masked unavailability")
	}
}

func TestGenerationMirrorCannotValidateEarlierRawPathSnapshot(t *testing.T) {
	inputA, _, mirror := fixtureMirrorAuditInput(t)
	// Reproduce the rejected CLI boundary: A passed a separate mirror preflight.
	if _, err := mirror.Verify(context.Background(), inputA.Closure.Source); err != nil {
		t.Fatal(err)
	}
	// Commit B exists in the source repository, but was never copied to mirror A.
	sourceDirectory := filepath.Join(filepath.Dir(mirror.MirrorPath), "source")
	if err := os.WriteFile(filepath.Join(sourceDirectory, "fixture.txt"), []byte("synthetic replacement source B\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGitTest(t, "-C", sourceDirectory, "add", "fixture.txt")
	runGitTest(t, "-C", sourceDirectory, "-c", "user.name=AIPT Synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "--quiet", "-m", "synthetic B")
	sourceB := inputA.Closure.Source
	sourceB.Commit = strings.TrimSpace(runGitTest(t, "-C", sourceDirectory, "rev-parse", "HEAD"))
	sourceB.Tree = strings.TrimSpace(runGitTest(t, "-C", sourceDirectory, "rev-parse", "HEAD^{tree}"))
	rawBPath := filepath.Join(privateTempDir(t), "raw-b")
	if _, err := ExportRawCapture(context.Background(), &staticSource{snapshot: fixtureSnapshot()}, ExportInput{Destination: rawBPath, Source: sourceB, StreamID: "synthetic-ledger"}); err != nil {
		t.Fatal(err)
	}
	inputB, _ := fixtureAuditInputForRaw(t, rawBPath, fixtureExportProfile())
	inputB.Destination = filepath.Join(privateTempDir(t), "rejected")
	inputB.MirrorPath = mirror.MirrorPath
	if err := os.Rename(inputA.RawCapture, inputA.RawCapture+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(rawBPath, inputA.RawCapture); err != nil {
		t.Fatal(err)
	}
	inputB.RawCapture = inputA.RawCapture
	calls := 0
	verifier := fixtureOnlineVerifier{client: fixtureGitHubClient(t, sourceB, 200, fixtureCommitBody(sourceB), &calls)}
	result, err := generateAuditReady(context.Background(), inputB, verifier)
	if !errors.Is(err, ErrSourceUnverified) || result.Root != "" || calls != 0 {
		t.Fatalf("mirror A validated held source B: %v, requests=%d", err, calls)
	}
	if _, err := os.Lstat(inputB.Destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("mirror mismatch left a published bundle")
	}
	// Without the optional mirror, B is otherwise valid under fresh remote proof.
	inputB.MirrorPath = ""
	result, err = generateAuditReady(context.Background(), inputB, verifier)
	if err != nil || result.Manifest.Source != sourceB || calls != 1 {
		t.Fatalf("B control generation failed: %v, requests=%d", err, calls)
	}
}

func TestGenerationMirrorRawReplacementAfterHoldCannotPublish(t *testing.T) {
	input, verifier, _ := fixtureMirrorAuditInput(t)
	replacement := filepath.Join(privateTempDir(t), "replacement")
	sourceB := input.Closure.Source
	sourceB.Commit = strings.Repeat("f", 40)
	if _, err := ExportRawCapture(context.Background(), &staticSource{snapshot: fixtureSnapshot()}, ExportInput{Destination: replacement, Source: sourceB, StreamID: "synthetic-ledger"}); err != nil {
		t.Fatal(err)
	}
	verifier.hook = func(call int) {
		if call != 1 {
			return
		}
		if err := os.Rename(input.RawCapture, input.RawCapture+"-old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, input.RawCapture); err != nil {
			t.Fatal(err)
		}
	}
	result, err := generateAuditReady(context.Background(), input, verifier)
	if !errors.Is(err, ErrStreamChanged) || result.Root != "" || verifier.proofRequests != 1 {
		t.Fatalf("replaced RAW pathname published: %v, proofs=%d", err, verifier.proofRequests)
	}
	if _, err := os.Lstat(input.Destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replaced RAW pathname left a published bundle")
	}
}
