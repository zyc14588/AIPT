package pilot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSingleRootMappingRejectsBroadOrMultiplePrincipals(t *testing.T) {
	for _, raw := range []string{"", "0 0 4294967295\n", "0 1000 2\n", "0 1000 1\n1 1001 1\n", "1 1000 1\n", "0 4294967295 1\n", "0 -1 1\n", "0 bad 1\n"} {
		if singleRootIDMapping([]byte(raw)) {
			t.Fatalf("broader or invalid mapping accepted: %q", raw)
		}
	}
	for _, raw := range []string{"0 1000 1\n", "         0       1000          1\n", "0 0 1\n"} {
		if !singleRootIDMapping([]byte(raw)) {
			t.Fatalf("single kernel root mapping rejected: %q", raw)
		}
	}
}

// Only the test executable runs. USER alone must never grant access to the
// ancestor mount/network/PID namespace; all owned namespaces use kernel nsfs
// ownership. No global process, library, GPU driver or model is inspected.
func TestOwnedNamespaceKernelOwnershipFixture(t *testing.T) {
	role := os.Getenv("AIPT_NONCANON_NAMESPACE_OWNER_FIXTURE")
	if role != "" {
		if (role == "user" || role == "mount" || role == "all") && namespaceFixtureUserHandleUnavailable() {
			fmt.Fprint(os.Stdout, namespaceFixtureUnavailableMarker)
			os.Exit(namespaceFixtureUnavailableExit)
		}
		want := map[string]bool{"user": true, "mnt": false, "pid": false, "net": false}
		if role == "mount" || role == "all" {
			want["mnt"] = true
		}
		if role == "all" {
			want["pid"], want["net"] = true, true
		}
		for kind, expected := range want {
			if got := ownedKernelNamespace(kind); got != expected {
				t.Fatalf("kernel ownership %s: got %v, want %v; fresh observation=%s", kind, got, expected, namespaceOwnershipFreshObservation(kind))
			}
		}
		if ownedKernelNamespace("unlisted") {
			t.Fatal("unlisted namespace accepted")
		}
		return
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	required := os.Getenv("AIPT_REQUIRE_OWNED_NAMESPACE_FIXTURE") == "1"
	for _, role := range []string{"user", "mount", "all"} {
		t.Run(role, func(t *testing.T) {
			flags := uintptr(syscall.CLONE_NEWUSER)
			if role == "mount" || role == "all" {
				flags |= syscall.CLONE_NEWNS
			}
			if role == "all" {
				flags |= syscall.CLONE_NEWPID | syscall.CLONE_NEWNET
			}
			cmd := exec.Command(executable, "-test.run=^TestOwnedNamespaceKernelOwnershipFixture$")
			cmd.Env = []string{"AIPT_NONCANON_NAMESPACE_OWNER_FIXTURE=" + role}
			cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: flags, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false}
			out, e := cmd.CombinedOutput()
			if e != nil {
				if optionalNamespaceFixtureUnavailable(required, out, e, nil) {
					t.Skip("optional own namespace fixture cannot open its user handle (EACCES)")
				}
				if !required && strings.Contains(e.Error(), syscall.EPERM.Error()) {
					t.Skip("dedicated required own namespace fixture unavailable")
				}
				t.Fatalf("own namespace %s UID%d: %v\n%s", role, os.Getuid(), e, out)
			}
			if strings.Contains(string(out), "--- SKIP") || strings.Contains(string(out), "--- FAIL") {
				t.Fatal("nested fixture skipped/failed " + strconv.Quote(string(out)))
			}
		})
	}
}

// This child closes only its own stdio and checks the real NS_GET_USERNS
// success-to-rejection path. A dedicated inherited marker pipe reports the
// result without relying on the deliberately closed descriptors. No model or
// registered runtime executable runs.
func TestOwnedNamespaceLowDescriptorRejectionClosesOwnership(t *testing.T) {
	if os.Getenv("AIPT_NONCANON_NAMESPACE_LOW_FD_FIXTURE") == "1" {
		marker := os.NewFile(3, "own fixture marker")
		if marker != nil && namespaceFixtureUserHandleUnavailable() {
			fmt.Fprint(marker, namespaceFixtureUnavailableMarker)
			os.Exit(namespaceFixtureUnavailableExit)
		}
		if marker == nil || !ownedKernelNamespace("mnt") {
			if marker != nil {
				fmt.Fprintln(marker, "FAIL: namespace precheck; fresh observation="+namespaceOwnershipFreshObservation("mnt"))
			}
			os.Exit(2)
		}
		for fd := 0; fd <= 2; fd++ {
			if syscall.Close(fd) != nil {
				os.Exit(3)
			}
		}
		for attempt := 0; attempt < 64; attempt++ {
			if ownedKernelNamespace("mnt") {
				fmt.Fprintln(marker, "FAIL: low descriptor policy bypass")
				os.Exit(4)
			}
			for fd := 0; fd <= 2; fd++ {
				_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
				if errno != syscall.EBADF {
					fmt.Fprintln(marker, "FAIL: rejected namespace descriptor leaked")
					os.Exit(5)
				}
			}
		}
		fmt.Fprintln(marker, "PASS: 64 rejected kernel owner descriptors closed")
		os.Exit(0)
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	reader, writer, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestOwnedNamespaceLowDescriptorRejectionClosesOwnership$")
	// One glibc arena avoids CPU-topology opens by new thread allocators
	// while this test child checks deliberately empty stdio descriptors.
	// The parent and production runtime keep their own allocator policy.
	cmd.Env = []string{"AIPT_NONCANON_NAMESPACE_LOW_FD_FIXTURE=1", "MALLOC_ARENA_MAX=1"}
	cmd.ExtraFiles = []*os.File{writer}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false}
	if e = cmd.Start(); e != nil {
		if os.Getenv("AIPT_REQUIRE_OWNED_NAMESPACE_FIXTURE") != "1" && strings.Contains(e.Error(), syscall.EPERM.Error()) {
			t.Skip("dedicated required own namespace fixture unavailable")
		}
		t.Fatal(e)
	}
	writer.Close()
	out, readErr := io.ReadAll(io.LimitReader(reader, 1024))
	waitErr := cmd.Wait()
	contextErr := ctx.Err()
	if optionalNamespaceLowFDFixtureUnavailable(os.Getenv("AIPT_REQUIRE_OWNED_NAMESPACE_FIXTURE") == "1", out, readErr, waitErr, contextErr) {
		t.Skip("optional own namespace fixture cannot open its user handle (EACCES)")
	}
	if readErr != nil || waitErr != nil || string(out) != "PASS: 64 rejected kernel owner descriptors closed\n" {
		t.Fatalf("own kernel low descriptor fixture: read=%v wait=%v marker=%q", readErr, waitErr, out)
	}
	t.Logf("validated own kernel low descriptor marker=%q", out)
}

// This test-only replay occurs after an existing assertion or exit2 condition
// has already failed, before any stdio closure. It observes only this child's
// whitelisted namespace handles. It cannot identify the original call's return
// branch; a successful replay explicitly leaves the original rejection open.
// No raw maps, paths, error strings, environment or arbitrary FD contents leave
// this process. Every namespace/owner descriptor acquired here is closed.
func namespaceOwnershipFreshObservation(kind string) string {
	types := map[string]uintptr{"user": syscall.CLONE_NEWUSER, "pid": syscall.CLONE_NEWPID, "mnt": syscall.CLONE_NEWNS, "net": syscall.CLONE_NEWNET}
	cloneType, listed := types[kind]
	if !listed {
		return "kind-listed=false"
	}
	if uid, gid := os.Geteuid(), os.Getegid(); uid != 0 || gid != 0 {
		return fmt.Sprintf("credentials-root=false euid=%d egid=%d", uid, gid)
	}
	for _, name := range []string{"uid_map", "gid_map"} {
		bytes, err := os.ReadFile("/proc/self/" + name)
		if err != nil {
			return name + "-read=false " + namespaceObservationErrno(err)
		}
		if !singleRootIDMapping(bytes) {
			return fmt.Sprintf("%s-single-root=false bytes=%d", name, len(bytes))
		}
	}
	user, err := os.Open("/proc/self/ns/user")
	if err != nil {
		return "user-open=false " + namespaceObservationErrno(err)
	}
	defer user.Close()
	userInfo, err := user.Stat()
	if err != nil {
		return "user-stat=false " + namespaceObservationErrno(err)
	}
	target, err := os.Open("/proc/self/ns/" + kind)
	if err != nil {
		return "target-open=false " + namespaceObservationErrno(err)
	}
	defer target.Close()
	for i, file := range []*os.File{user, target} {
		var fs syscall.Statfs_t
		if err := syscall.Fstatfs(int(file.Fd()), &fs); err != nil {
			return fmt.Sprintf("nsfs-index=%d fstatfs=false %s", i, namespaceObservationErrno(err))
		}
		if uint64(fs.Type) != 0x6e736673 {
			return fmt.Sprintf("nsfs-index=%d nsfs=false type=%d", i, uint64(fs.Type))
		}
	}
	actual, _, errno := syscall.Syscall(syscall.SYS_IOCTL, target.Fd(), 0xb703, 0)
	if errno != 0 || actual != cloneType {
		return fmt.Sprintf("namespace-type=false errno=%d actual=%d expected=%d", uint64(errno), actual, cloneType)
	}
	if kind == "user" {
		return "fresh-all-guards-accepted=true original-call-branch-unobserved=true"
	}
	ownerFD, _, errno := syscall.Syscall(syscall.SYS_IOCTL, target.Fd(), 0xb701, 0)
	if errno != 0 {
		return fmt.Sprintf("owner-ioctl=false errno=%d", uint64(errno))
	}
	if ownerFD <= 2 {
		err := syscall.Close(int(ownerFD))
		return fmt.Sprintf("owner-low-descriptor=true descriptor=%d close-ok=%t %s", ownerFD, err == nil, namespaceObservationErrno(err))
	}
	owner := os.NewFile(ownerFD, "test namespace owner")
	if owner == nil {
		err := syscall.Close(int(ownerFD))
		return fmt.Sprintf("owner-handle=false close-ok=%t %s", err == nil, namespaceObservationErrno(err))
	}
	defer owner.Close()
	ownerInfo, err := owner.Stat()
	if err != nil {
		return "owner-stat=false " + namespaceObservationErrno(err)
	}
	if !os.SameFile(userInfo, ownerInfo) {
		return "owner-same-file=false"
	}
	return "fresh-all-guards-accepted=true original-call-branch-unobserved=true"
}

func namespaceObservationErrno(err error) string {
	var errno syscall.Errno
	known := errors.As(err, &errno)
	return fmt.Sprintf("errno-known=%t errno=%d", known, uint64(errno))
}

// Q022 draft: probe only before the unchanged positive assertions/64-loop.
// Root credentials and two single-root maps must precede the first self-user
// open. Only a typed EACCES on that open can report optional unavailability.
// A successful probe grants nothing; the original fixture still must pass.
const namespaceFixtureUnavailableMarker = "AIPT_OPTIONAL_NS_USER_HANDLE_EACCES\n"
const namespaceFixtureUnavailableExit = 77

func namespaceFixtureUserHandleUnavailable() bool {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return false
	}
	for _, name := range []string{"uid_map", "gid_map"} {
		raw, err := os.ReadFile("/proc/self/" + name)
		if err != nil || !singleRootIDMapping(raw) {
			return false
		}
	}
	user, err := os.Open("/proc/self/ns/user")
	if err != nil {
		var errno syscall.Errno
		return errors.As(err, &errno) && errno == syscall.EACCES
	}
	user.Close()
	return false
}

func namespaceFixtureUnavailableMarkerMatch(required bool, exitCode int, output []byte, contextErr error) bool {
	return contextErr == nil && !required && exitCode == namespaceFixtureUnavailableExit && string(output) == namespaceFixtureUnavailableMarker
}

// Callers reach here only after CombinedOutput or an explicit cmd.Wait.
// Signals, startup/timeout errors and original exit1/2/4/5 remain failures.
func optionalNamespaceFixtureUnavailable(required bool, output []byte, waitErr, contextErr error) bool {
	var exited *exec.ExitError
	return errors.As(waitErr, &exited) && exited != nil && namespaceFixtureUnavailableMarkerMatch(required, exited.ExitCode(), output, contextErr)
}

// One parent context sample follows actual Wait; neither an actual marker
// read error nor an expired context can become optional unavailability.
func optionalNamespaceLowFDFixtureUnavailable(required bool, output []byte, readErr, waitErr, contextErr error) bool {
	return readErr == nil && contextErr == nil && optionalNamespaceFixtureUnavailable(required, output, waitErr, contextErr)
}

func TestNamespaceFixtureUnavailableMarkerIsExactAndRequiredNeverSkips(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required bool
		code     int
		marker   string
		want     bool
	}{
		{"optional-exact77", false, 77, namespaceFixtureUnavailableMarker, true},
		{"required-exact77", true, 77, namespaceFixtureUnavailableMarker, false},
		{"success-is-not-unavailable", false, 0, namespaceFixtureUnavailableMarker, false},
		{"original-assertion-exit1", false, 1, "--- FAIL: kernel ownership; fresh observation=user-open=false errno-known=true errno=13\n", false},
		{"original-low-fd-exit2", false, 2, "FAIL: namespace precheck; fresh observation=user-open=false errno-known=true errno=13\n", false},
		{"wrong-exit2-exact-marker", false, 2, namespaceFixtureUnavailableMarker, false},
		{"empty", false, 77, "", false},
		{"prefix", false, 77, "FAIL: " + namespaceFixtureUnavailableMarker, false},
		{"suffix", false, 77, namespaceFixtureUnavailableMarker + "FAIL\n", false},
		{"duplicate", false, 77, namespaceFixtureUnavailableMarker + namespaceFixtureUnavailableMarker, false},
		{"extra-newline", false, 77, namespaceFixtureUnavailableMarker + "\n", false},
		{"missing-newline", false, 77, strings.TrimSuffix(namespaceFixtureUnavailableMarker, "\n"), false},
		{"CRLF", false, 77, strings.ReplaceAll(namespaceFixtureUnavailableMarker, "\n", "\r\n"), false},
		{"other-errno", false, 77, "AIPT_OPTIONAL_NS_USER_HANDLE_EPERM\n", false},
		{"signal-code", false, -1, namespaceFixtureUnavailableMarker, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := namespaceFixtureUnavailableMarkerMatch(tc.required, tc.code, []byte(tc.marker), nil); got != tc.want {
				t.Fatalf("required=%t code=%d marker=%q: got %t want %t", tc.required, tc.code, tc.marker, got, tc.want)
			}
		})
	}
}

// A nonzero child ExitError can take precedence over a concurrent ctx error
// in exec.Cmd.Wait. A completed77 child must never hide the parent's deadline.
func TestNamespaceFixtureUnavailableDeadlineOrCancelNeverSkips(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"deadline-exceeded-exact77", context.DeadlineExceeded},
		{"context-canceled-exact77", context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if namespaceFixtureUnavailableMarkerMatch(false, namespaceFixtureUnavailableExit, []byte(namespaceFixtureUnavailableMarker), tc.err) {
				t.Fatal("expired/canceled parent context accepted as optional unavailability")
			}
		})
	}
}

// This synthetic test child only emits the exact marker and exercises actual
// exec.Wait result types; it never creates a namespace or a model process.
func TestNamespaceFixtureUnavailableTypedWaitAndReadErrors(t *testing.T) {
	if role := os.Getenv("AIPT_Q022_NONCANON_MARKER_WAIT_FIXTURE"); role != "" {
		fmt.Fprint(os.Stdout, namespaceFixtureUnavailableMarker)
		switch role {
		case "exit77":
			os.Exit(77)
		case "exit2":
			os.Exit(2)
		case "signal":
			if syscall.Kill(os.Getpid(), syscall.SIGTERM) != nil {
				os.Exit(99)
			}
			select {}
		default:
			os.Exit(99)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	waits := map[string]error{}
	for _, role := range []string{"exit77", "exit2", "signal"} {
		cmd := exec.Command(executable, "-test.run=^TestNamespaceFixtureUnavailableTypedWaitAndReadErrors$")
		cmd.Env = []string{"AIPT_Q022_NONCANON_MARKER_WAIT_FIXTURE=" + role}
		out, waitErr := cmd.CombinedOutput()
		var exited *exec.ExitError
		if !errors.As(waitErr, &exited) || exited == nil || string(out) != namespaceFixtureUnavailableMarker {
			t.Fatalf("actual marker producer did not finish with typed exit: %q %v", out, waitErr)
		}
		waits[role] = waitErr
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	reader.Close()
	writer.Close()
	_, readErr := reader.Read(make([]byte, 1))
	if !errors.Is(readErr, os.ErrClosed) {
		t.Fatalf("expected actual closed marker reader error, got %v", readErr)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, expireCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expireCancel()
	var typedNil *exec.ExitError
	for _, tc := range []struct {
		name                         string
		required                     bool
		readErr, waitErr, contextErr error
		want                         bool
	}{
		{"optional-actual77", false, nil, waits["exit77"], nil, true},
		{"required-actual77", true, nil, waits["exit77"], nil, false},
		{"actual-read-error-with77", false, readErr, waits["exit77"], nil, false},
		{"actual-exit2-sole-marker", false, nil, waits["exit2"], nil, false},
		{"actual-signal-sole-marker", false, nil, waits["signal"], nil, false},
		{"actual-canceled-context-with77", false, nil, waits["exit77"], canceled.Err(), false},
		{"actual-expired-context-with77", false, nil, waits["exit77"], expired.Err(), false},
		{"nil-wait-is-not-unavailable", false, nil, nil, nil, false},
		{"plain-error-is-not-exit", false, nil, errors.New("synthetic untyped wait failure"), nil, false},
		{"typed-nil-error-is-not-exit", false, nil, typedNil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := optionalNamespaceLowFDFixtureUnavailable(tc.required, []byte(namespaceFixtureUnavailableMarker), tc.readErr, tc.waitErr, tc.contextErr); got != tc.want {
				t.Fatalf("marker read/wait/context admission: got %v want %v", got, tc.want)
			}
		})
	}
}
