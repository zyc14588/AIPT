package pilot

import (
	"bufio"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This fixture binds only three tiny, parent-created text files. It never
// opens a registered native executable, helper, model, or backend library.
func TestMemorySourceNamespaceFixture(t *testing.T) {
	if os.Getenv("AIPT_NONCANON_MEMORY_SOURCE_FIXTURE") == "child" {
		// Production opens sources after the dedicated child has its own mount
		// namespace. A parent-opened descriptor names the parent's mount and
		// cannot be used as a bind source in the newly cloned mount namespace.
		var files []*os.File
		for i := 0; i < 3; i++ {
			f, e := os.Open(filepath.Join(os.Getenv("AIPT_NONCANON_SOURCE_DIRECTORY"), "NON_CANON_SOURCE_"+strconv.Itoa(i)))
			if e != nil {
				t.Fatal(e)
			}
			files = append(files, f)
			defer f.Close()
		}
		s, e := bindHeldMemorySources(files)
		if e != nil {
			t.Fatal(e)
		}
		defer s.close()
		fmt.Println("NON_CANON_SOURCES_BOUND")
		line, e := bufio.NewReader(os.Stdin).ReadString('\n')
		if e != nil || line != "NON_CANON_PATHS_REPLACED\n" {
			t.Fatal("fixture coordination", e)
		}
		for i, p := range s.paths {
			held, he := files[i].Stat()
			bound, be := os.Stat(p)
			if he != nil || be != nil || !os.SameFile(held, bound) {
				t.Fatal("binding changed held source inode", he, be)
			}
			body, re := os.ReadFile(p)
			if re != nil || string(body) != "NON_CANON_ORIGINAL_"+strconv.Itoa(i) {
				t.Fatal("binding did not read original source", re)
			}
			if f, we := os.OpenFile(p, os.O_WRONLY, 0); we == nil {
				f.Close()
				t.Fatal("source binding writable")
			} else if !errors.Is(we, syscall.EROFS) {
				t.Fatal("wrong write rejection", we)
			}
			if re := os.Rename(p, p+".replacement"); !errors.Is(re, syscall.EROFS) {
				t.Fatal("source target replaceable", re)
			}
		}
		paths := append([]string{}, s.paths...)
		if e = s.close(); e != nil {
			t.Fatal("source binding cleanup", e)
		}
		for _, p := range paths {
			if _, e = os.Stat(p); !os.IsNotExist(e) {
				t.Fatal("source binding retained after cleanup", e)
			}
		}
		if e = s.close(); e != nil {
			t.Fatal("second cleanup", e)
		}
		return
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	file, e := elf.Open(exe)
	if e != nil {
		t.Fatal(e)
	}
	dynamic := false
	for _, p := range file.Progs {
		if p.Type == elf.PT_INTERP {
			dynamic = true
		}
	}
	file.Close()
	required := os.Getenv("AIPT_REQUIRE_MEMORY_SOURCE_FIXTURE") == "1"
	if dynamic {
		if required {
			t.Fatal("required memory-source fixture needs static CGO_ENABLED=0 test binary")
		}
		t.Skip("dedicated static memory-source namespace check required")
	}
	root := t.TempDir()
	var files []*os.File
	var paths []string
	for i := 0; i < 3; i++ {
		p := filepath.Join(root, "NON_CANON_SOURCE_"+strconv.Itoa(i))
		if e = os.WriteFile(p, []byte("NON_CANON_ORIGINAL_"+strconv.Itoa(i)), 0600); e != nil {
			t.Fatal(e)
		}
		f, e := os.Open(p)
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		files = append(files, f)
		paths = append(paths, p)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, exe, "-test.run=^TestMemorySourceNamespaceFixture$")
	child.Env = []string{"AIPT_NONCANON_MEMORY_SOURCE_FIXTURE=child", "AIPT_NONCANON_SOURCE_DIRECTORY=" + root}
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false}
	input, e := child.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := child.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr strings.Builder
	child.Stderr = &stderr
	if e = child.Start(); e != nil {
		if errors.Is(e, syscall.EPERM) && !required {
			t.Skip("private preparation namespace unavailable")
		}
		t.Fatal("private preparation child", e)
	}
	reader := bufio.NewReader(output)
	line, e := reader.ReadString('\n')
	if e != nil || line != "NON_CANON_SOURCES_BOUND\n" {
		_ = input.Close()
		rest, _ := io.ReadAll(reader)
		_ = child.Wait()
		t.Fatalf("source preparation: %v %q %s %s", e, line, rest, stderr.String())
	}
	for i, p := range paths {
		// Equal bytes deliberately defeat a digest-only source-inode check.
		if e = os.Rename(p, p+".old"); e != nil {
			cancel()
			child.Wait()
			t.Fatal(e)
		}
		if e = os.WriteFile(p, []byte("NON_CANON_ORIGINAL_"+strconv.Itoa(i)), 0600); e != nil {
			cancel()
			child.Wait()
			t.Fatal(e)
		}
		held, he := files[i].Stat()
		replacement, re := os.Stat(p)
		if he != nil || re != nil || os.SameFile(held, replacement) {
			cancel()
			child.Wait()
			t.Fatal("replacement fixture has no different inode")
		}
	}
	_, e = io.WriteString(input, "NON_CANON_PATHS_REPLACED\n")
	_ = input.Close()
	rest, readErr := io.ReadAll(reader)
	waitErr := child.Wait()
	if e != nil || readErr != nil || waitErr != nil {
		t.Fatalf("held source check: %v %v %v %s %s", e, readErr, waitErr, rest, stderr.String())
	}
}
