package pilot

import (
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This directly exercises the control-request branch's guard. All exit arms
// and the STOP request are ready simultaneously; no select scheduling or
// repetition count can hide the erroneous request-branch choice.
func TestFrozenReadyStopCannotConsumePendingRuntimeFailure(t *testing.T) {
	for _, kind := range []string{"adapter", "native", "counter", "proof", "control"} {
		t.Run(kind, func(t *testing.T) {
			adapterExit, nativeExit := make(chan struct{}), make(chan struct{})
			s := &frozenSupervisor{adapter: &frozenOwnedProcess{exit: adapterExit}, native: &frozenOwnedProcess{exit: nativeExit}, httpExit: make(chan struct{}), proofExit: make(chan struct{})}
			failures := make(chan error, 1)
			requests := make(chan frozenControlRequest, 1)
			requests <- frozenControlRequest{Schema: frozenControlSchema, Operation: "STOP_ADAPTER"}
			switch kind {
			case "adapter":
				close(adapterExit)
			case "native":
				close(nativeExit)
			case "counter":
				close(s.httpExit)
			case "proof":
				close(s.proofExit)
			case "control":
				failures <- ErrRuntimeLaunch
			}
			request := <-requests // Select's request arm has already won.
			finished, e := s.executeFrozenControl(request, failures)
			if request.Operation != "STOP_ADAPTER" || !finished || !errors.Is(e, ErrRuntimeLaunch) || s.adapter == nil {
				t.Fatal("ready STOP masked pending failure or removed current generation")
			}
		})
	}
}

// The static Go fixture performs an actual STOP_ADAPTER control exchange,
// reaps that owned child, and confirms the loop retains the live native
// stand-in. It does not execute the registered helper, Node, native or model.
func TestFrozenDeliberateAdapterStopNamespaceFixture(t *testing.T) {
	role := os.Getenv("AIPT_NONCANON_ADAPTER_STOP_FIXTURE")
	if role == "child" {
		for {
			time.Sleep(time.Minute)
		}
	}
	if role == "verify" {
		if os.Getpid() != 1 || verifyZeroCapabilityThreads(1) != nil {
			t.Fatal("namespace/capability origin")
		}
		start := func() *frozenOwnedProcess {
			executable, e := os.Open("/aipt/noncanon_fixture")
			if e != nil {
				t.Fatal(e)
			}
			defer executable.Close()
			cmd := exec.Command("/aipt/noncanon_fixture", "-test.run=^TestFrozenDeliberateAdapterStopNamespaceFixture$")
			cmd.Env = []string{"AIPT_NONCANON_ADAPTER_STOP_FIXTURE=child"}
			cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
			p, e := startFrozenProcess(cmd, executable)
			if e != nil {
				t.Fatal("owned static child", e)
			}
			return p
		}
		native, adapter := start(), start()
		control, peer := nonCanonControlPair(t)
		s := &frozenSupervisor{control: control, native: native, adapter: adapter, httpExit: make(chan struct{}), proofExit: make(chan struct{}), policy: runtimeLaunchPolicy{Initial: frozenControlRequest{ShutdownTimeoutMS: 1000}}}
		defer s.stopAll()
		done := make(chan error, 1)
		go func() { done <- s.loop() }()
		if e := peer.SetDeadline(time.Now().Add(3 * time.Second)); e != nil {
			t.Fatal(e)
		}
		request, e := json.Marshal(frozenControlRequest{Schema: frozenControlSchema, Operation: "STOP_ADAPTER"})
		if e != nil {
			t.Fatal(e)
		}
		if n, e := peer.Write(request); e != nil || n != len(request) {
			t.Fatal("STOP request", e)
		}
		var reply frozenControlReply
		var frame [4096]byte
		n, e := peer.Read(frame[:])
		if e != nil || decodeFrozenJSON(frame[:n], len(frame), &reply) != nil || reply.Operation != "STOP_ADAPTER" || reply.Result != "PASS" {
			t.Fatal("deliberate STOP exchange", e, reply)
		}
		select {
		case <-adapter.exit:
		default:
			t.Fatal("STOP acknowledged before owned adapter retirement")
		}
		if native.check() != nil {
			t.Fatal("deliberate adapter STOP retired unrelated owned native stand-in")
		}
		select {
		case e := <-done:
			t.Fatal("old adapter exit incorrectly revoked live runtime", e)
		case <-time.After(75 * time.Millisecond):
		}
		_ = peer.Close()
		select {
		case e := <-done:
			if !errors.Is(e, ErrRuntimeLaunch) {
				t.Fatal("control closure did not revoke runtime", e)
			}
		case <-time.After(time.Second):
			t.Fatal("loop did not retire after control closure")
		}
		if s.adapter != nil {
			t.Fatal("completed STOP left prior adapter registered")
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
		manifest := nonCanonCodeManifest(body)
		manifest.Files[0].GuestPaths = []string{"/aipt/noncanon_fixture"}
		path, raw := prepareNonCanonCode(t, manifest, map[string][]byte{"server_fixture": body})
		capsule, e := OpenHeldCodeCapsule(raw, inputSHA(raw), path)
		if e != nil {
			t.Fatal(e)
		}
		root, e := EnterFrozenRuntimeRoot(capsule, nonCanonSocketRootPlan())
		if e != nil || ConstrainChildExecPrivileges(root) != nil || capsule.Close() != nil {
			t.Fatal("private static fixture root", e)
		}
		if e = syscall.Exec("/aipt/noncanon_fixture", []string{"/aipt/noncanon_fixture", "-test.run=^TestFrozenDeliberateAdapterStopNamespaceFixture$"}, []string{"AIPT_NONCANON_ADAPTER_STOP_FIXTURE=verify"}); e != nil {
			t.Fatal(e)
		}
		return
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	image, e := elf.Open(executable)
	if e != nil {
		t.Fatal(e)
	}
	dynamic := false
	for _, program := range image.Progs {
		dynamic = dynamic || program.Type == elf.PT_INTERP
	}
	_ = image.Close()
	required := os.Getenv("AIPT_REQUIRE_FROZEN_ADAPTER_STOP_FIXTURE") == "1"
	if dynamic {
		if required {
			t.Fatal("static fixture executable required")
		}
		t.Skip("dedicated static namespace fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestFrozenDeliberateAdapterStopNamespaceFixture$")
	cmd.Env = []string{"AIPT_NONCANON_ADAPTER_STOP_FIXTURE=prepare"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false}
	out, e := cmd.CombinedOutput()
	if e != nil {
		if !required && errors.Is(e, syscall.EPERM) {
			t.Skip("private namespace unavailable")
		}
		t.Fatalf("required deliberate STOP fixture: %v\n%s", e, out)
	}
	if strings.Contains(string(out), "--- SKIP") || strings.Contains(string(out), "--- FAIL") {
		t.Fatal("nested fixture skipped or failed")
	}
}
