package pilot

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

var preparationFixtureBinding = []byte(`{"schema":"aipt.NON_CANON.preparation-marker/v1","model_admission":false}`)

// The only executed file is this CGO-disabled Go test executable. The real
// parent launch function, seal checks, pidfd/executable checks and fixed clone
// flags run; no runtime grant, manager, library, Harness or model is used.
func TestFreshPreparationParentOwnsStaticChildAndAdmission(t *testing.T) {
	if os.Getenv("AIPT_NONCANON_FRESH_PREPARATION_FIXTURE") == "1" {
		raw, control, e := receiveFreshPreparationAdmission(context.Background(), inputSHA(preparationFixtureBinding))
		if e != nil || !bytes.Equal(raw, preparationFixtureBinding) {
			t.Fatal("private preparation admission", e)
		}
		defer control.Close()
		own, e := os.Stat("/proc/self/exe")
		one, oe := os.Stat("/proc/1/exe")
		if e != nil || oe != nil || !os.SameFile(own, one) || os.Getpid() != 1 || !namespaceIsNotHost("mnt") || !namespaceIsNotHost("pid") || !namespaceIsNotHost("user") {
			t.Fatal("own PID1 proc root missing after admission")
		}
		done := freshPreparationFrame{Schema: freshPreparationSchema, Operation: "NON_CANON_PARENT_AND_PROC_PASS", BindingSHA: inputSHA(raw)}
		if preparationPacket(control, &done, true) != nil {
			t.Fatal("own marker completion")
		}
		var stop freshPreparationFrame
		if preparationPacket(control, &stop, false) != nil || stop != (freshPreparationFrame{Schema: freshPreparationSchema, Operation: "NON_CANON_RETIRE", BindingSHA: inputSHA(raw)}) {
			t.Fatal("own marker retirement")
		}
		return
	}
	selfName, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	source, e := os.Open(selfName)
	if e != nil {
		t.Fatal(e)
	}
	defer source.Close()
	info, e := source.Stat()
	if e != nil {
		t.Fatal(e)
	}
	if !staticPreparationFile(source) {
		if os.Getenv("AIPT_REQUIRE_FRESH_PREPARATION_FIXTURE") != "1" {
			t.Skip("dedicated required CGO-disabled preparation fixture")
		}
		t.Fatal("fixture must have the actual static preparation ABI")
	}
	self, e := sealedCodeSnapshot(source, info.Size(), true)
	if e != nil {
		t.Fatal(e)
	}
	defer self.Close()
	raw := t.TempDir() + "/noncanon-binding"
	if os.WriteFile(raw, preparationFixtureBinding, 0600) != nil {
		t.Fatal("noncanon binding write")
	}
	bindingSource, e := os.Open(raw)
	if e != nil {
		t.Fatal(e)
	}
	defer bindingSource.Close()
	binding, e := sealedCodeSnapshot(bindingSource, int64(len(preparationFixtureBinding)), false)
	if e != nil {
		t.Fatal(e)
	}
	defer binding.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var log bytes.Buffer
	p, e := launchFreshPreparation(ctx, self, binding, inputSHA(preparationFixtureBinding), []string{"-test.run=^TestFreshPreparationParentOwnsStaticChildAndAdmission$"}, []string{"AIPT_NONCANON_FRESH_PREPARATION_FIXTURE=1"}, &log)
	if e != nil {
		if os.Getenv("AIPT_REQUIRE_FRESH_PREPARATION_FIXTURE") != "1" && errors.Is(e, syscall.EPERM) {
			t.Skip("dedicated required own namespace fixture unavailable")
		}
		t.Fatal("fresh preparation parent", e, log.String())
	}
	defer p.retire()
	var done freshPreparationFrame
	if p.control.SetDeadline(time.Now().Add(5*time.Second)) != nil || preparationPacket(p.control, &done, false) != nil || done != (freshPreparationFrame{Schema: freshPreparationSchema, Operation: "NON_CANON_PARENT_AND_PROC_PASS", BindingSHA: inputSHA(preparationFixtureBinding)}) {
		t.Fatal("fresh child did not report admitted own proc", log.String())
	}
	stop := freshPreparationFrame{Schema: freshPreparationSchema, Operation: "NON_CANON_RETIRE", BindingSHA: inputSHA(preparationFixtureBinding)}
	if preparationPacket(p.control, &stop, true) != nil {
		t.Fatal("own retirement send")
	}
	select {
	case <-p.exit:
		if p.waitErr != nil {
			t.Fatal("own child wait", p.waitErr, log.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("own child failed to retire")
	}
}

func TestFreshPreparationRejectsUnauthenticatedAdmission(t *testing.T) {
	if raw, control, e := receiveFreshPreparationAdmission(context.Background(), inputSHA(preparationFixtureBinding)); e == nil || raw != nil || control != nil {
		t.Fatal("unowned host process admitted itself")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, e := launchFreshPreparation(ctx, nil, nil, strings.Repeat("a", 64), nil, nil, io.Discard); e == nil || p != nil {
		t.Fatal("cancelled unheld preparation admitted")
	}
	if p, e := launchFreshPreparation(context.Background(), nil, nil, "caller-selected", nil, nil, io.Discard); e == nil || p != nil {
		t.Fatal("caller-selected source admitted")
	}
}
