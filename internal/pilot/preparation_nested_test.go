package pilot

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Explicitly selected, static NON_CANON control fixture. Its only nested
// program is this test image: no game, Worker, native, model, database, key,
// source/cache file or official DIAG is opened or executed.
func TestFreshPreparationNestedNamespaceMappingAfterAdmissionFixture(t *testing.T) {
	const selector = "AIPT_B007_TEST_NESTED_PREP_NS"
	const controlBody = "NON_CANON_NESTED_PREPARATION_MAPPING_ONLY"
	const marker = "NON_CANON_NESTED_MAPPING_OK"
	role := os.Getenv(selector)
	if role == "" {
		t.Skip("explicit private static nested-namespace acceptance fixture")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch role {
	case "nested":
		if os.Getpid() != 1 || os.Geteuid() != 0 {
			t.Fatal("nested fixture principal")
		}
		for _, kind := range []string{"user", "pid", "mnt", "net"} {
			if !ownedKernelNamespace(kind) {
				t.Fatal("nested fixture namespace", kind)
			}
		}
		// The nested model-like process still installs a private read-only
		// proc. Making PREP able to map its child does not relax this boundary.
		if syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, "") != nil || syscall.Mount("proc", "/proc", "proc", syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "") != nil {
			t.Fatal("nested read-only proc")
		}
		var fs syscall.Statfs_t
		if syscall.Statfs("/proc", &fs) != nil || fs.Flags&1 == 0 {
			t.Fatal("nested proc became writable")
		}
		fmt.Fprintln(os.Stdout, marker)
		return
	case "prep":
		raw, control, err := receiveFreshPreparationAdmission(ctx, inputSHA([]byte(controlBody)))
		if err != nil {
			t.Fatal("outside-parent preparation admission", err)
		}
		defer control.Close()
		defer clear(raw)
		if string(raw) != controlBody {
			t.Fatal("private control substituted")
		}
		self, err := os.Open("/proc/self/exe")
		if err != nil {
			t.Fatal("held test image")
		}
		defer self.Close()
		var output bytes.Buffer
		cmd := exec.CommandContext(ctx, "/proc/self/fd/3", "-test.run=^TestFreshPreparationNestedNamespaceMappingAfterAdmissionFixture$")
		cmd.ExtraFiles = []*os.File{self}
		cmd.Env = frozenEnvironment(map[string]string{selector: "nested"})
		cmd.Stdout, cmd.Stderr = &output, &output
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false}
		if err = cmd.Run(); err != nil || output.Len() > 4096 || !strings.Contains(output.String(), marker) {
			t.Fatal("PREP could not map and join its owned nested static child", err)
		}
		return
	case "1":
	default:
		t.Fatal("unknown fixture role")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal("test image locator")
	}
	self, err := os.Open(path)
	if err != nil {
		t.Fatal("test image")
	}
	defer self.Close()
	info, err := self.Stat()
	if err != nil || !staticPreparationFile(self) {
		t.Fatal("fixture requires a static CGO-disabled test binary")
	}
	held, err := sealedCodeSnapshot(self, info.Size(), true)
	if err != nil {
		t.Fatal("held fixture image")
	}
	defer held.Close()
	binding, err := task0SealedBytes([]byte(controlBody))
	if err != nil {
		t.Fatal("held control")
	}
	defer binding.Close()
	p, err := launchFreshPreparation(ctx, held, binding, inputSHA([]byte(controlBody)), []string{"-test.run=^TestFreshPreparationNestedNamespaceMappingAfterAdmissionFixture$"}, frozenEnvironment(map[string]string{selector: "prep"}), io.Discard)
	if err != nil {
		t.Fatal("owned static preparation", err)
	}
	defer p.retire()
	select {
	case <-p.exit:
		if p.waitErr != nil {
			t.Fatal("owned nested namespace mapping failed", p.waitErr)
		}
	case <-ctx.Done():
		t.Fatal("owned nested namespace mapping timeout")
	}
}
