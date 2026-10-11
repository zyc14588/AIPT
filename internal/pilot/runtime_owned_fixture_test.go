package pilot

import (
	"debug/elf"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func nonCanonSocketRootPlan() FrozenRootPlan {
	return FrozenRootPlan{Schema: "aipt.private.b007-frozen-runtime-root-plan/v1", WorkingDirectories: []string{"/aipt/fixture_work"}, WritableDirectories: []string{"/aipt/private/fixture_data"}}
}

// Only a self-built static Go test binary executes. Its endpoint emits fixed
// NON_CANON text, with no registered helper/native, Node, GGUF or model route.
func TestFrozenSocketOwnershipNamespaceFixture(t *testing.T) {
	role := os.Getenv("AIPT_NONCANON_SOCKET_FIXTURE")
	if role == "server" || role == "shared_server" || role == "socket_holder" {
		port, e := strconv.Atoi(os.Getenv("AIPT_NONCANON_SOCKET_PORT"))
		if e != nil {
			t.Fatal(e)
		}
		if role == "socket_holder" {
			f := os.NewFile(3, "own shared socket fixture")
			if f == nil {
				t.Fatal("missing listener")
			}
			defer f.Close()
			select {}
		}
		l, e := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port))
		if e != nil {
			t.Fatal(e)
		}
		if role == "shared_server" {
			f, e := l.(*net.TCPListener).File()
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			cmd := exec.Command("/aipt/noncanon_fixture", "-test.run=^TestFrozenSocketOwnershipNamespaceFixture$")
			cmd.ExtraFiles = []*os.File{f}
			cmd.Env = []string{"AIPT_NONCANON_SOCKET_FIXTURE=socket_holder", "AIPT_NONCANON_SOCKET_PORT=" + strconv.Itoa(port)}
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile("/aipt/private/fixture_data/shared", []byte("NON_CANON_SOCKET_SHARED"), 0600); e != nil {
				t.Fatal(e)
			}
		}
		server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = os.WriteFile("/aipt/private/fixture_data/received", []byte("NON_CANON_HTTP_RECEIVED"), 0600)
			_, _ = w.Write([]byte("NON_CANON_OWNED_SOCKET"))
		})}
		if e = server.Serve(l); e != nil {
			t.Fatal(e)
		}
		return
	}
	if role == "verify" {
		if os.Getpid() != 1 || verifyZeroCapabilityThreads(1) != nil {
			t.Fatal("own namespace/capability binding")
		}
		start := func(port int, role string) *frozenOwnedProcess {
			f, e := os.Open("/aipt/noncanon_fixture")
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			cmd := exec.Command("/aipt/noncanon_fixture", "-test.run=^TestFrozenSocketOwnershipNamespaceFixture$")
			cmd.Env = []string{"AIPT_NONCANON_SOCKET_FIXTURE=" + role, "AIPT_NONCANON_SOCKET_PORT=" + strconv.Itoa(port)}
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			p, e := startFrozenProcess(cmd, f)
			if e != nil {
				t.Fatal("own static child binding", e)
			}
			return p
		}
		port, e := reserveFrozenPort()
		if e != nil {
			t.Fatal(e)
		}
		p := start(port, "server")
		defer p.stop(time.Second)
		deadline := time.Now().Add(3 * time.Second)
		for {
			if _, e := p.listener(port); e == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("owned listener did not bind")
			}
			time.Sleep(5 * time.Millisecond)
		}
		transport := p.guardedTransport(port)
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: time.Second}
		resp, e := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/noncanon")
		if e != nil {
			t.Fatal("owned connection", e)
		}
		body, e := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if e != nil || string(body) != "NON_CANON_OWNED_SOCKET" {
			t.Fatal("owned response", e)
		}
		if e = p.stop(time.Second); e != nil {
			t.Fatal(e)
		}
		_ = os.Remove("/aipt/private/fixture_data/received")
		foreign := start(port, "server")
		defer foreign.stop(time.Second)
		deadline = time.Now().Add(3 * time.Second)
		for {
			if _, e := foreign.listener(port); e == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("replacement listener")
			}
			time.Sleep(5 * time.Millisecond)
		}
		if resp, e := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/noncanon"); e == nil {
			resp.Body.Close()
			t.Fatal("dead original generation sent HTTP to replacement")
		}
		if _, e = os.Stat("/aipt/private/fixture_data/received"); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("replacement received HTTP bytes", e)
		}
		if e = foreign.stop(time.Second); e != nil {
			t.Fatal(e)
		}
		shared := start(port, "shared_server")
		defer shared.stop(time.Second)
		deadline = time.Now().Add(3 * time.Second)
		for {
			if _, e = os.Stat("/aipt/private/fixture_data/shared"); e == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("shared socket not created")
			}
			time.Sleep(5 * time.Millisecond)
		}
		if _, e = shared.listener(port); e == nil {
			t.Fatal("detached peer shares socket but ownership accepted")
		}
		sharedTransport := shared.guardedTransport(port)
		defer sharedTransport.CloseIdleConnections()
		client.Transport = sharedTransport
		if resp, e := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/noncanon"); e == nil {
			resp.Body.Close()
			t.Fatal("shared socket received governed HTTP")
		}
		if _, e = os.Stat("/aipt/private/fixture_data/received"); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("shared listener received HTTP bytes", e)
		}
		return
	}
	if role == "prepare" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		body, e := os.ReadFile("/proc/self/exe")
		if e != nil {
			t.Fatal(e)
		}
		m := nonCanonCodeManifest(body)
		m.Files[0].GuestPaths = []string{"/aipt/noncanon_fixture"}
		root, raw := prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body})
		c, e := OpenHeldCodeCapsule(raw, inputSHA(raw), root)
		if e != nil {
			t.Fatal(e)
		}
		if e = bringFrozenLoopbackUp(); e != nil {
			t.Fatal(e)
		}
		frozen, e := EnterFrozenRuntimeRoot(c, nonCanonSocketRootPlan())
		if e != nil {
			t.Fatal(e)
		}
		if e = ConstrainChildExecPrivileges(frozen); e != nil {
			t.Fatal(e)
		}
		if e = c.Close(); e != nil {
			t.Fatal(e)
		}
		if e = syscall.Exec("/aipt/noncanon_fixture", []string{"/aipt/noncanon_fixture", "-test.run=^TestFrozenSocketOwnershipNamespaceFixture$"}, []string{"AIPT_NONCANON_SOCKET_FIXTURE=verify"}); e != nil {
			t.Fatal(e)
		}
		return
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	binary, e := elf.Open(exe)
	if e != nil {
		t.Fatal(e)
	}
	dynamic := false
	for _, p := range binary.Progs {
		if p.Type == elf.PT_INTERP {
			dynamic = true
		}
	}
	_ = binary.Close()
	required := os.Getenv("AIPT_REQUIRE_FROZEN_SOCKET_FIXTURE") == "1"
	if dynamic {
		if required {
			t.Fatal("static required")
		}
		t.Skip("run required self-built static namespace fixture")
	}
	cmd := exec.Command(exe, "-test.run=^TestFrozenSocketOwnershipNamespaceFixture$")
	cmd.Env = append(os.Environ(), "AIPT_NONCANON_SOCKET_FIXTURE=prepare")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false}
	out, e := cmd.CombinedOutput()
	if e != nil {
		if !required && (errors.Is(e, syscall.EPERM) || strings.Contains(e.Error(), "operation not permitted")) {
			t.Skip("namespace unavailable")
		}
		t.Fatalf("required owned socket fixture: %v\n%s", e, out)
	}
	if strings.Contains(string(out), "--- SKIP") || strings.Contains(string(out), "--- FAIL") {
		t.Fatal("nested fixture failed/skipped")
	}
}
