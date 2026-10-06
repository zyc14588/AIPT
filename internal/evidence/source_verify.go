package evidence

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

const remoteVerificationStatus = "VERIFIED_IMMUTABLE_REMOTE_COMMIT"
const localObjectMatchStatus = "LOCAL_OBJECT_MATCH"
const maxGitVerificationBytes = 4096

const trustedGitExecutable = "/usr/bin/git"

// GitMirrorVerifier checks local object consistency in a local bare Git
// mirror. It can return only LOCAL_OBJECT_MATCH and is never remote proof. It never fetches, resolves a branch/tag, invokes a shell, or writes
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
	if verifier.MirrorPath == "" || !localRepositoryIdentityMatches(source.Repository, verifier.ExpectedRepository) {
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
	bounded, cancelVerification := context.WithTimeout(ctx, 5*time.Second)
	defer cancelVerification()

	run := func(arguments ...string) (string, error) {
		gitInfo, inspectErr := os.Lstat(trustedGitExecutable)
		if inspectErr != nil || !gitInfo.Mode().IsRegular() || gitInfo.Mode().Perm()&0o022 != 0 {
			return "", errors.New("trusted Git executable is unavailable or writable")
		}
		base := []string{"--no-replace-objects", "--git-dir=/proc/self/fd/3",
			"-c", "log.showSignature=false", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat"}
		command := exec.CommandContext(bounded, trustedGitExecutable, append(base, arguments...)...)
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		command.Cancel = func() error {
			if command.Process == nil {
				return os.ErrProcessDone
			}
			err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			if errors.Is(err, syscall.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
		command.WaitDelay = 250 * time.Millisecond
		command.ExtraFiles = []*os.File{mirror}
		command.Env = []string{
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_NO_LAZY_FETCH=1",
			"GIT_OPTIONAL_LOCKS=0",
			"GIT_TERMINAL_PROMPT=0",
			"LC_ALL=C",
		}
		stdout := &boundedGitOutput{maximum: maxGitVerificationBytes, cancel: cancelVerification}
		stderr := &boundedGitOutput{maximum: maxGitVerificationBytes, cancel: cancelVerification}
		command.Stdout, command.Stderr = stdout, stderr
		if runErr := command.Run(); runErr != nil || stdout.exceeded || stderr.exceeded {
			return "", errors.New("bounded local Git verification failed")
		}
		return strings.TrimSuffix(stdout.buffer.String(), "\n"), nil
	}

	bare, err := run("rev-parse", "--is-bare-repository")
	if err != nil || bare != "true" {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify source mirror", errors.New("configured source is not a bare Git mirror"))
	}
	readRemote := func() (string, error) {
		return run("config", "--local", "--get", "remote."+remoteName+".url")
	}
	remoteBefore, err := readRemote()
	if err != nil || ValidateAuditReadyRepositoryIdentity(remoteBefore) != nil || !localRepositoryIdentityMatches(remoteBefore, source.Repository) {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify source remote", errors.New("remote identity mismatch"))
	}
	objectType, err := run("cat-file", "-t", source.Commit)
	if err != nil || objectType != "commit" {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify source commit", errors.New("commit object is absent or invalid"))
	}
	tree, err := run("rev-parse", "--verify", source.Commit+"^{tree}")
	if err != nil || tree != source.Tree {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify source tree", errors.New("commit tree mismatch"))
	}
	objectTypeAfter, typeErr := run("cat-file", "-t", source.Commit)
	treeAfter, treeErr := run("rev-parse", "--verify", source.Commit+"^{tree}")
	remoteAfter, remoteErr := readRemote()
	var after syscall.Stat_t
	statErr := syscall.Fstat(fd, &after)
	if typeErr != nil || treeErr != nil || remoteErr != nil || statErr != nil || objectTypeAfter != objectType ||
		treeAfter != tree || remoteAfter != remoteBefore || !sameFileState(before, after) ||
		!directoryPathMatchesNoSymlinks(verifier.MirrorPath, before, false) {
		return RemoteVerification{}, classifyError(ErrSourceUnverified, "verify stable source identity", errors.New("source mirror changed during verification"))
	}
	return RemoteVerification{Remote: remoteBefore, Commit: source.Commit, Status: localObjectMatchStatus}, nil
}

// Generic legacy mirror fixtures keep exact identity matching. Only the
// policy-accepted GitHub suffix equivalent is additionally recognized; this
// local comparison can still return only LOCAL_OBJECT_MATCH.
func localRepositoryIdentityMatches(left, right string) bool {
	if ValidateAuditReadyRepositoryIdentity(left) != nil || ValidateAuditReadyRepositoryIdentity(right) != nil {
		return false
	}
	return left == right || MatchAuditReadyRepositoryIdentity(left, right) == nil
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

// A child can never cause unbounded stdout/stderr buffering. Exceeding either
// bound cancels the owned process group before any further capture.
type boundedGitOutput struct {
	buffer   bytes.Buffer
	maximum  int
	exceeded bool
	cancel   context.CancelFunc
}

func (output *boundedGitOutput) Write(data []byte) (int, error) {
	remaining := output.maximum - output.buffer.Len()
	if output.exceeded || len(data) > remaining {
		output.exceeded = true
		output.cancel()
		return 0, errors.New("local Git output exceeds bound")
	}
	return output.buffer.Write(data)
}
