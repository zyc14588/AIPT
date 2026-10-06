package evidence

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	RemoteProvenanceSchema   = "aipt.remote-provenance/v1"
	RemoteProvenancePolicy   = "ONLINE_GITHUB_REMOTE_PROVENANCE_V1"
	RemoteProvenanceProvider = "GITHUB_PUBLIC_HTTPS_API_V1"
	RemoteProvenanceName     = "remote-provenance.json"
	maxRemoteResponseBytes   = int64(512 << 10)
	remoteRequestTimeout     = 15 * time.Second
	trustedSystemCAFile      = "/etc/ssl/certs/ca-certificates.crt"
	maxSystemCABytes         = int64(1 << 20)
)

var (
	ErrRemoteProvenanceUnavailable = errors.New("BLOCKED_REMOTE_PROVENANCE_UNAVAILABLE")
	ErrRemoteProviderUnsupported   = errors.New("REMOTE_PROVENANCE_PROVIDER_UNSUPPORTED")
	githubOwnerName                = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
	githubRepositoryName           = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
)

// RemoteProvenanceReceipt contains only the deterministic, immutable source
// facts. It carries no network metadata, time, credential or local locator.
type RemoteProvenanceReceipt struct {
	Schema     string `json:"schema"`
	Version    string `json:"version"`
	PolicyID   string `json:"policy_id"`
	Provider   string `json:"provider"`
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Tree       string `json:"tree"`
	Status     string `json:"status"`
}

// The injection seam is package-private. Exported generation and verification
// always instantiate githubSourceVerifier directly; they accept no verifier,
// client, endpoint, proxy or CA parameters and do not use HTTP globals.
type sourceVerifier interface {
	Verify(context.Context, SourceIdentity) (RemoteProvenanceReceipt, error)
}

type githubSourceVerifier struct{}

func (githubSourceVerifier) Verify(ctx context.Context, source SourceIdentity) (RemoteProvenanceReceipt, error) {
	if ctx == nil || validateAuditReadySourceIdentity(source) != nil {
		return RemoteProvenanceReceipt{}, ErrSourceUnverified
	}
	if _, _, _, err := canonicalGitHubRepository(source.Repository); err != nil {
		return RemoteProvenanceReceipt{}, err
	}
	if ctx.Err() != nil {
		return RemoteProvenanceReceipt{}, errors.Join(ErrSourceUnverified, ErrRemoteProvenanceUnavailable)
	}
	client, err := newGitHubHTTPClient()
	if err != nil {
		return RemoteProvenanceReceipt{}, errors.Join(ErrSourceUnverified, ErrRemoteProvenanceUnavailable)
	}
	defer client.CloseIdleConnections()
	return verifyGitHubSource(ctx, source, client)
}

func canonicalGitHubRepository(repository string) (canonical, owner, name string, err error) {
	if ValidateAuditReadyRepositoryIdentity(repository) != nil {
		return "", "", "", ErrSourceUnverified
	}
	parsed, parseErr := url.Parse(repository)
	if parseErr != nil {
		return "", "", "", ErrSourceUnverified
	}
	if parsed.Hostname() != "github.com" {
		return "", "", "", errors.Join(ErrSourceUnverified, ErrRemoteProviderUnsupported)
	}
	if parsed.Host != "github.com" || parsed.RawPath != "" || strings.Contains(parsed.Path, "%") {
		return "", "", "", ErrSourceUnverified
	}
	segments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(segments) != 2 {
		return "", "", "", ErrSourceUnverified
	}
	owner, name = segments[0], strings.TrimSuffix(segments[1], ".git")
	if !githubOwnerName.MatchString(owner) || !githubRepositoryName.MatchString(name) || name == "." || name == ".." || strings.HasSuffix(name, ".git") {
		return "", "", "", ErrSourceUnverified
	}
	return "https://github.com/" + owner + "/" + name, owner, name, nil
}

func receiptForSource(source SourceIdentity) (RemoteProvenanceReceipt, error) {
	if validateAuditReadySourceIdentity(source) != nil {
		return RemoteProvenanceReceipt{}, ErrSourceUnverified
	}
	repository, _, _, err := canonicalGitHubRepository(source.Repository)
	if err != nil {
		return RemoteProvenanceReceipt{}, err
	}
	return RemoteProvenanceReceipt{
		Schema: RemoteProvenanceSchema, Version: ContractVersion,
		PolicyID: RemoteProvenancePolicy, Provider: RemoteProvenanceProvider,
		Repository: repository, Commit: source.Commit, Tree: source.Tree,
		Status: remoteVerificationStatus,
	}, nil
}

func validateRemoteProvenanceReceipt(receipt RemoteProvenanceReceipt, source SourceIdentity) error {
	expected, err := receiptForSource(source)
	if err != nil || receipt != expected {
		return ErrSourceUnverified
	}
	return nil
}

func remoteVerificationFromReceipt(receipt RemoteProvenanceReceipt, source SourceIdentity) RemoteVerification {
	return RemoteVerification{Remote: source.Repository, Commit: receipt.Commit, Status: receipt.Status}
}

func newGitHubHTTPClient() (*http.Client, error) {
	roots, err := trustedSystemRoots()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "api.github.com", RootCAs: roots},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
		DisableCompression:     true,
	}
	return &http.Client{
		Transport: transport, Timeout: remoteRequestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// SystemCertPool honors SSL_CERT_FILE/SSL_CERT_DIR, so it is intentionally
// excluded. Only this fixed root-owned, non-writable system bundle is read.
// The supported native Linux profile fails closed if it is unavailable.
func trustedSystemRoots() (*x509.CertPool, error) {
	fd, err := syscall.Open(trustedSystemCAFile, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrRemoteProvenanceUnavailable
	}
	file := os.NewFile(uintptr(fd), "system-tls-roots")
	defer file.Close()
	var before, after syscall.Stat_t
	if syscall.Fstat(fd, &before) != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Uid != 0 ||
		before.Mode&0o022 != 0 || before.Size < 1 || before.Size > maxSystemCABytes {
		return nil, ErrRemoteProvenanceUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSystemCABytes+1))
	if err != nil || int64(len(data)) != before.Size || syscall.Fstat(fd, &after) != nil || !sameFileState(before, after) {
		return nil, ErrRemoteProvenanceUnavailable
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, ErrRemoteProvenanceUnavailable
	}
	return roots, nil
}

// The client seam is private and used only by offline security probes. The
// production entry point above constructs a fresh fixed transport itself.
func verifyGitHubSource(ctx context.Context, source SourceIdentity, client *http.Client) (RemoteProvenanceReceipt, error) {
	expected, err := receiptForSource(source)
	if ctx == nil || err != nil || client == nil {
		if err != nil {
			return RemoteProvenanceReceipt{}, err
		}
		return RemoteProvenanceReceipt{}, ErrSourceUnverified
	}
	_, owner, name, err := canonicalGitHubRepository(source.Repository)
	if err != nil {
		return RemoteProvenanceReceipt{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, remoteRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet,
		"https://api.github.com/repos/"+owner+"/"+name+"/git/commits/"+source.Commit, nil)
	if err != nil {
		return RemoteProvenanceReceipt{}, ErrSourceUnverified
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "AIPT-Remote-Provenance/1")
	response, err := client.Do(request)
	if err != nil {
		return RemoteProvenanceReceipt{}, errors.Join(ErrSourceUnverified, ErrRemoteProvenanceUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == 403 || response.StatusCode == 429 || response.StatusCode >= 500 {
			return RemoteProvenanceReceipt{}, errors.Join(ErrSourceUnverified, ErrRemoteProvenanceUnavailable)
		}
		return RemoteProvenanceReceipt{}, ErrSourceUnverified
	}
	if response.ContentLength > maxRemoteResponseBytes {
		return RemoteProvenanceReceipt{}, ErrSourceUnverified
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRemoteResponseBytes+1))
	if err != nil {
		return RemoteProvenanceReceipt{}, errors.Join(ErrSourceUnverified, ErrRemoteProvenanceUnavailable)
	}
	if int64(len(body)) > maxRemoteResponseBytes || !utf8.Valid(body) || validateRemoteJSON(body) != nil {
		return RemoteProvenanceReceipt{}, ErrSourceUnverified
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(body, &object) != nil {
		return RemoteProvenanceReceipt{}, ErrSourceUnverified
	}
	var commit string
	var treeObject map[string]json.RawMessage
	var tree string
	if json.Unmarshal(object["sha"], &commit) != nil || json.Unmarshal(object["tree"], &treeObject) != nil ||
		json.Unmarshal(treeObject["sha"], &tree) != nil || commit != source.Commit || tree != source.Tree {
		return RemoteProvenanceReceipt{}, ErrSourceUnverified
	}
	return expected, nil
}

// Reject ambiguous duplicate members, trailing data and excessive nesting,
// including in the metadata that is intentionally omitted from the receipt.
func validateRemoteJSON(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	tokens := 0
	var value func(int) error
	value = func(depth int) error {
		tokens++
		if depth > 32 || tokens > 10000 {
			return ErrSourceUnverified
		}
		token, err := decoder.Token()
		if err != nil {
			return ErrSourceUnverified
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for decoder.More() {
				rawKey, err := decoder.Token()
				key, ok := rawKey.(string)
				if err != nil || !ok || keys[key] {
					return ErrSourceUnverified
				}
				keys[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return ErrSourceUnverified
			}
		case '[':
			for decoder.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return ErrSourceUnverified
			}
		default:
			return ErrSourceUnverified
		}
		return nil
	}
	if value(0) != nil {
		return ErrSourceUnverified
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrSourceUnverified
	}
	return nil
}
