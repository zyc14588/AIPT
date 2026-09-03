package evidence

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

const remoteVerificationStatus = "VERIFIED_IMMUTABLE_REMOTE_COMMIT"

const trustedGitExecutable = "/usr/bin/git"

// GitMirrorVerifier verifies an immutable source object in a local bare Git
// mirror. It never fetches, resolves a branch/tag, invokes a shell, or writes
// the mirror. The directory is passed to Git by an already-open descriptor so
// a pathname swap cannot redirect verification to another repository.
type GitMirrorVerifier struct {
	MirrorPath         string
	ExpectedRepository string
	RemoteName         string
}

func (verifier GitMirrorVerifier) Verify(ctx context.Context, source SourceIdentity) (RemoteVerification, error) {
	if ctx == nil {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify source identity", errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify source identity", err)
	}
	if err := validateAuditReadySourceIdentity(source); err != nil {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify source identity", err)
	}
	if err := ValidateAuditReadyRepositoryIdentity(verifier.ExpectedRepository); err != nil {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify expected repository identity", err)
	}
	if verifier.MirrorPath == "" || source.Repository != verifier.ExpectedRepository {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify source identity", errors.New("source is outside configured repository"))
	}
	remoteName := verifier.RemoteName
	if remoteName == "" {
		remoteName = "origin"
	}
	if err := validContractIdentifier("remote name", remoteName); err != nil || strings.Contains(remoteName, "/") {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify source identity", errors.New("invalid configured remote name"))
	}

	mirror, before, err := openOwnerControlledDirectoryPath(verifier.MirrorPath)
	if err != nil {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "open source mirror", errors.New("mirror path is unsafe"))
	}
	defer mirror.Close()
	fd := int(mirror.Fd())

	run := func(arguments ...string) (string, error) {
		gitInfo, inspectErr := os.Lstat(trustedGitExecutable)
		if inspectErr != nil || !gitInfo.Mode().IsRegular() || gitInfo.Mode().Perm()&0o022 != 0 {
			return "", errors.New("trusted Git executable is unavailable or writable")
		}
		base := []string{"--no-replace-objects", "--git-dir=/proc/self/fd/3"}
		command := exec.CommandContext(ctx, trustedGitExecutable, append(base, arguments...)...)
		command.ExtraFiles = []*os.File{mirror}
		command.Env = []string{
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_NO_LAZY_FETCH=1",
			"GIT_OPTIONAL_LOCKS=0",
			"GIT_TERMINAL_PROMPT=0",
			"LC_ALL=C",
		}
		output, runErr := command.Output()
		if runErr != nil {
			return "", runErr
		}
		if len(output) > 4096 {
			return "", errors.New("git verification output exceeds bound")
		}
		return strings.TrimSuffix(string(output), "\n"), nil
	}

	bare, err := run("rev-parse", "--is-bare-repository")
	if err != nil || bare != "true" {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify source mirror", errors.New("configured source is not a bare Git mirror"))
	}
	readRemote := func() (string, error) {
		return run("config", "--local", "--get", "remote."+remoteName+".url")
	}
	remoteBefore, err := readRemote()
	if err != nil || ValidateAuditReadyRepositoryIdentity(remoteBefore) != nil || remoteBefore != source.Repository {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify source remote", errors.New("remote identity mismatch"))
	}
	objectType, err := run("cat-file", "-t", source.Commit)
	if err != nil || objectType != "commit" {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify source commit", errors.New("commit object is absent or invalid"))
	}
	tree, err := run("show", "-s", "--format=%T", source.Commit)
	if err != nil || tree != source.Tree {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify source tree", errors.New("commit tree mismatch"))
	}
	objectTypeAfter, typeErr := run("cat-file", "-t", source.Commit)
	treeAfter, treeErr := run("show", "-s", "--format=%T", source.Commit)
	remoteAfter, remoteErr := readRemote()
	var after syscall.Stat_t
	statErr := syscall.Fstat(fd, &after)
	if typeErr != nil || treeErr != nil || remoteErr != nil || statErr != nil || objectTypeAfter != objectType ||
		treeAfter != tree || remoteAfter != remoteBefore || !sameFileState(before, after) ||
		!directoryPathMatchesNoSymlinks(verifier.MirrorPath, before, false) {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify stable source identity", errors.New("source mirror changed during verification"))
	}
	return RemoteVerification{Remote: remoteBefore, Commit: source.Commit, Status: remoteVerificationStatus}, nil
}

func validateRemoteVerification(verification RemoteVerification, source SourceIdentity) error {
	if validateAuditReadySourceIdentity(source) != nil || ValidateAuditReadyRepositoryIdentity(verification.Remote) != nil ||
		verification.Remote != source.Repository || verification.Commit != source.Commit || verification.Status != remoteVerificationStatus {
		return fmt.Errorf("%w: remote verification does not bind source", ErrSourceUnverified)
	}
	return nil
}

// ValidateAuditReadyRepositoryIdentity enforces the additive B005 repository
// identity contract without changing the byte-frozen RAW_CAPTURE v1 rules.
// It deliberately returns no parser detail because net/url errors may echo the
// credential-bearing input.
func ValidateAuditReadyRepositoryIdentity(repository string) error {
	invalid := func() error {
		return fmt.Errorf("%w: repository identity must be a credential-free HTTPS URL", ErrSourceUnverified)
	}
	if repository == "" || !utf8.ValidString(repository) || utf8.RuneCountInString(repository) > 512 ||
		containsControl(repository) || strings.Contains(repository, "#") {
		return invalid()
	}
	parsed, err := url.Parse(repository)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" ||
		containsControl(parsed.Host) || containsControl(parsed.Path) {
		return invalid()
	}
	return nil
}

func validateAuditReadySourceIdentity(source SourceIdentity) error {
	if validateSourceIdentity(source) != nil || ValidateAuditReadyRepositoryIdentity(source.Repository) != nil {
		return fmt.Errorf("%w: invalid credential-free immutable source identity", ErrSourceUnverified)
	}
	return nil
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}
