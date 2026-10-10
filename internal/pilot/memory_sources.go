package pilot

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"
)

// This is a preparation-only binding of original cache-source inodes. It is
// not an immutable executable capsule or runtime-origin acceptance. The
// unchanged manager still hashes and seals each source before execution; the
// Q004 runtime root must independently freeze the whole executable closure.
type heldMemorySources struct {
	pid         int
	user, mount os.FileInfo
	base        string
	paths       []string
	mounted     int
	rootMounted bool
	closed      bool
}

func (s *heldMemorySources) ownedNamespace() bool {
	if s == nil || s.pid != os.Getpid() || os.Geteuid() != 0 {
		return false
	}
	u, ue := os.Stat("/proc/self/ns/user")
	m, me := os.Stat("/proc/self/ns/mnt")
	return ue == nil && me == nil && os.SameFile(u, s.user) && os.SameFile(m, s.mount) && namespaceIsNotHost("user") && namespaceIsNotHost("mnt")
}

// The caller must be a dedicated freshly exec'd child created with NEWUSER
// and NEWNS. This function never unshares a running Go process or changes the
// host mount namespace. A partially prepared result remains cleanup-owned.
func bindHeldMemorySources(files []*os.File) (*heldMemorySources, error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 || len(files) != 3 || !namespaceIsNotHost("user") || !namespaceIsNotHost("mnt") {
		return nil, fmt.Errorf("%w: dedicated namespace precondition", ErrMemory)
	}
	for _, f := range files {
		if f == nil {
			return nil, fmt.Errorf("%w: missing source FD", ErrMemory)
		}
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() <= 0 {
			return nil, fmt.Errorf("%w: source file type", ErrMemory)
		}
	}
	u, ue := os.Stat("/proc/self/ns/user")
	m, me := os.Stat("/proc/self/ns/mnt")
	if ue != nil || me != nil {
		return nil, fmt.Errorf("%w: namespace identity", ErrMemory)
	}
	s := &heldMemorySources{pid: os.Getpid(), user: u, mount: m, base: "/tmp/aipt-b007-held-memory-sources"}
	if e := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); e != nil {
		return nil, fmt.Errorf("%w: mount propagation: %v", ErrMemory, e)
	}
	// Sources under the original /tmp were held before this private mount.
	// No host process can replace these private binding targets.
	if e := syscall.Mount("tmpfs", "/tmp", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "size=16m,mode=0700"); e != nil {
		return nil, fmt.Errorf("%w: private temporary root: %v", ErrMemory, e)
	}
	if e := os.Mkdir(s.base, 0700); e != nil {
		return s, fmt.Errorf("%w: private target directory", ErrMemory)
	}
	if e := syscall.Mount("tmpfs", s.base, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "size=1m,mode=0700"); e != nil {
		return s, fmt.Errorf("%w: private binding root: %v", ErrMemory, e)
	}
	s.rootMounted = true
	for i, f := range files {
		target, e := rootFileTarget(s.base, "/source_"+strconv.Itoa(i))
		if e != nil {
			return s, fmt.Errorf("%w: binding target", ErrMemory)
		}
		s.paths = append(s.paths, target)
		if e := syscall.Mount("/proc/self/fd/"+strconv.Itoa(int(f.Fd())), target, "", syscall.MS_BIND, ""); e != nil {
			return s, fmt.Errorf("%w: named source bind: %v", ErrMemory, e)
		}
		s.mounted++
		flags := uintptr(syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_RDONLY | syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC)
		if e := syscall.Mount("", target, "", flags, ""); e != nil {
			return s, fmt.Errorf("%w: source read-only bind: %v", ErrMemory, e)
		}
		bound, be := os.Stat(target)
		held, he := f.Stat()
		if be != nil || he != nil || !os.SameFile(bound, held) {
			return s, fmt.Errorf("%w: source inode mismatch", ErrMemory)
		}
	}
	if e := syscall.Mount("", s.base, "tmpfs", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); e != nil {
		return s, fmt.Errorf("%w: root read-only remount: %v", ErrMemory, e)
	}
	return s, nil
}

func (s *heldMemorySources) close() error {
	if s == nil || s.closed {
		return nil
	}
	if !s.ownedNamespace() {
		return ErrMemory
	}
	for s.mounted > 0 {
		if syscall.Unmount(s.paths[s.mounted-1], 0) != nil {
			return ErrMemory
		}
		s.mounted--
	}
	if s.rootMounted {
		if syscall.Unmount(s.base, 0) != nil {
			return ErrMemory
		}
		s.rootMounted = false
	}
	if e := os.Remove(s.base); e != nil && !os.IsNotExist(e) {
		return ErrMemory
	}
	s.closed = true
	return nil
}
