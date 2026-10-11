package pilot

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const task0SetupCapabilityMask uint32 = 1 << 31

// Production calls use only their own proc root or an already authenticated
// owned child's proc root. A changing roster is never an accepted sample.
func task0PrivilegeThreads(root string, mask, uid, gid uint32) ([]string, error) {
	for attempt := 0; attempt < 4; attempt++ {
		before, err := task0ThreadRoster(root)
		if err != nil {
			return nil, ErrRuntimeLaunch
		}
		for _, tid := range before {
			raw, err := os.ReadFile(root + "/task/" + tid + "/status")
			if err != nil || !task0ThreadStatusValid(raw, mask, uid, gid) {
				return nil, ErrRuntimeLaunch
			}
		}
		after, err := task0ThreadRoster(root)
		if err != nil {
			return nil, ErrRuntimeLaunch
		}
		if slices.Equal(before, after) {
			return after, nil
		}
		if attempt < 3 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	return nil, ErrRuntimeLaunch
}

func task0ThreadRoster(root string) ([]string, error) {
	entries, err := os.ReadDir(root + "/task")
	if err != nil || len(entries) == 0 || len(entries) > 512 {
		return nil, ErrRuntimeLaunch
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		id, err := strconv.Atoi(entry.Name())
		if err != nil || id < 1 || !entry.IsDir() {
			return nil, ErrRuntimeLaunch
		}
		ids = append(ids, entry.Name())
	}
	return ids, nil
}

func task0ThreadStatusValid(raw []byte, mask, uid, gid uint32) bool {
	if len(raw) == 0 || len(raw) > 65536 || (mask != 0 && mask != task0SetupCapabilityMask) {
		return false
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if _, exists := fields[key]; exists {
			return false
		}
		fields[key] = strings.TrimSpace(value)
	}
	zero, active := "0000000000000000", fmt.Sprintf("%016x", uint64(mask))
	if fields["CapInh"] != zero || fields["CapAmb"] != zero || fields["NoNewPrivs"] != "1" {
		return false
	}
	for _, key := range []string{"CapEff", "CapPrm", "CapBnd"} {
		if fields[key] != active {
			return false
		}
	}
	for _, owner := range []struct {
		key string
		id  uint32
	}{{"Uid", uid}, {"Gid", gid}} {
		id := strconv.FormatUint(uint64(owner.id), 10)
		if strings.Join(strings.Fields(fields[owner.key]), " ") != strings.Join([]string{id, id, id, id}, " ") {
			return false
		}
	}
	return true
}

// This is irreversible. AllThreadsSyscall must cover every Go OS thread;
// CGO/unsupported builds fail rather than falling back to a single-thread call.
// Newly created runtime threads inherit these locked, reduced credentials.
func task0ConvergePrivileges(mask uint32) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Getpid() != 1 || os.Geteuid() != 0 ||
		!namespaceIsNotHost("user") || !namespaceIsNotHost("pid") || !namespaceIsNotHost("mnt") ||
		(mask != 0 && mask != task0SetupCapabilityMask) {
		return ErrRuntimeLaunch
	}
	const lockedSecurebits = 1 | 2 | 4 | 8 | 64 | 128
	if _, _, e := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, 28, lockedSecurebits, 0, 0, 0, 0); e != 0 {
		return ErrRuntimeLaunch
	}
	raw, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	last, parseErr := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || parseErr != nil || last < 31 || last >= 64 {
		return ErrRuntimeLaunch
	}
	for cap := 0; cap <= last; cap++ {
		if mask == task0SetupCapabilityMask && cap == 31 {
			continue
		}
		if _, _, e := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, 24, uintptr(cap), 0, 0, 0, 0); e != 0 {
			return ErrRuntimeLaunch
		}
	}
	if _, _, e := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, 47, 4, 0, 0, 0, 0); e != 0 {
		return ErrRuntimeLaunch
	}
	if _, _, e := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0); e != 0 {
		return ErrRuntimeLaunch
	}
	type header struct {
		Version uint32
		PID     int32
	}
	type data struct{ Effective, Permitted, Inheritable uint32 }
	h := header{Version: 0x20080522}
	d := [2]data{{Effective: mask, Permitted: mask}, {}}
	_, _, e := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&d)), 0)
	runtime.KeepAlive(&h)
	runtime.KeepAlive(&d)
	if e != 0 {
		return ErrRuntimeLaunch
	}
	if _, err := task0PrivilegeThreads("/proc/self", mask, 0, 0); err != nil {
		return ErrRuntimeLaunch
	}
	return nil
}
