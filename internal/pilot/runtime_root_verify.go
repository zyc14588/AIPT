package pilot

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func verifyZeroCapabilityThreads(pid int) error {
	if pid < 1 {
		return ErrRuntimeLaunch
	}
	base := "/proc/" + strconv.Itoa(pid) + "/task"
	tasks, e := os.ReadDir(base)
	if e != nil || len(tasks) == 0 || len(tasks) > 512 {
		return ErrRuntimeLaunch
	}
	for _, task := range tasks {
		n, e := strconv.Atoi(task.Name())
		if e != nil || n < 1 {
			return ErrRuntimeLaunch
		}
		raw, e := os.ReadFile(base + "/" + task.Name() + "/status")
		if e != nil || len(raw) > 64<<10 {
			return ErrRuntimeLaunch
		}
		fields := map[string]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			key, value, ok := strings.Cut(line, ":")
			if ok {
				fields[key] = strings.TrimSpace(value)
			}
		}
		for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
			v, e := strconv.ParseUint(fields[key], 16, 64)
			if e != nil || v != 0 {
				return ErrRuntimeLaunch
			}
		}
		if fields["NoNewPrivs"] != "1" {
			return ErrRuntimeLaunch
		}
		for _, key := range []string{"Uid", "Gid"} {
			v := strings.Fields(fields[key])
			if len(v) != 4 {
				return ErrRuntimeLaunch
			}
			for _, part := range v {
				if part != "0" {
					return ErrRuntimeLaunch
				}
			}
		}
	}
	return nil
}

func verifyRuntimeMount(p string, kind int64, noexec bool) error {
	var st syscall.Statfs_t
	if syscall.Statfs(p, &st) != nil || (kind != 0 && st.Type != kind) {
		return ErrRuntimeLaunch
	}
	flags := int64(syscall.MS_RDONLY | syscall.MS_NOSUID | syscall.MS_NODEV)
	if noexec {
		flags |= syscall.MS_NOEXEC
	}
	if st.Flags&flags != flags {
		return ErrRuntimeLaunch
	}
	return nil
}

func verifyPrivateWritableMount(p string) error {
	var st syscall.Statfs_t
	if syscall.Statfs(p, &st) != nil || st.Type != 0x01021994 || st.Flags&syscall.MS_RDONLY != 0 ||
		st.Flags&int64(syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC) != int64(syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC) {
		return ErrRuntimeLaunch
	}
	entries, e := os.ReadDir(p)
	if e != nil || len(entries) != 0 {
		return ErrRuntimeLaunch
	}
	return nil
}

func verifyHardwareMounts() error {
	raw, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil || len(raw) > 3<<20 {
		return ErrRuntimeLaunch
	}
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return ErrRuntimeLaunch
		}
		target := fields[4]
		if target != "/sys" && !strings.HasPrefix(target, "/sys/") {
			continue
		}
		if strings.Contains(target, "\\") {
			return ErrRuntimeLaunch
		}
		if target == "/sys" {
			found = true
		}
		flags := "," + fields[5] + ","
		for _, flag := range []string{"ro", "nosuid", "nodev", "noexec"} {
			if !strings.Contains(flags, ","+flag+",") {
				return ErrRuntimeLaunch
			}
		}
	}
	if !found {
		return ErrRuntimeLaunch
	}
	return nil
}

func verifyFrozenSysfs(p FrozenRootPlan) error {
	if p.HardwareSysfs {
		if verifyRuntimeMount("/sys", 0x62656572, true) != nil || verifyHardwareMounts() != nil {
			return ErrRuntimeLaunch
		}
		return nil
	}
	// With hardware disabled, /sys belongs to the immutable root tmpfs and
	// must be empty. An undeclared hardware mount cannot use the walk skip.
	if verifyRuntimeMount("/sys", 0x01021994, false) != nil {
		return ErrRuntimeLaunch
	}
	entries, err := os.ReadDir("/sys")
	if err != nil || len(entries) != 0 {
		return ErrRuntimeLaunch
	}
	root, re := os.Stat("/")
	sys, se := os.Lstat("/sys")
	if re != nil || se != nil || !sys.IsDir() || sys.Mode()&os.ModeSymlink != 0 {
		return ErrRuntimeLaunch
	}
	r, rok := root.Sys().(*syscall.Stat_t)
	s, sok := sys.Sys().(*syscall.Stat_t)
	if !rok || !sok || r.Dev != s.Dev {
		return ErrRuntimeLaunch
	}
	return nil
}

// Stage 1 runs after a same-file exec of the verified helper. This check
// covers every asset alias and every non-kernel, non-private-data directory,
// rather than trusting an environment marker or a read-only / flag alone.
func verifyFrozenRuntimeRoot(c *HeldCodeCapsule, p FrozenRootPlan) error {
	if c == nil || os.Getpid() != 1 || os.Geteuid() != 0 || verifyZeroCapabilityThreads(1) != nil || verifyRuntimeMount("/", 0x01021994, false) != nil ||
		verifyRuntimeMount("/proc", 0x9fa0, true) != nil || verifyFrozenSysfs(p) != nil {
		return ErrRuntimeLaunch
	}
	var rootStat syscall.Stat_t
	if syscall.Lstat("/", &rootStat) != nil {
		return ErrRuntimeLaunch
	}
	self, e := os.Stat("/proc/self/ns/pid")
	init, ie := os.Stat("/proc/1/ns/pid")
	if e != nil || ie != nil || !os.SameFile(self, init) {
		return ErrRuntimeLaunch
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !digest(c.identity) || validateFrozenRootPlan(p, c.manifest) != nil {
		return ErrRuntimeLaunch
	}
	allowed := map[string]bool{"/": true, "/proc": true, "/sys": true, "/dev": true, "/dev/dri": true, "/dev/shm": true, "/tmp": true}
	add := func(p string) {
		for {
			allowed[p] = true
			if p == "/" {
				break
			}
			p = path.Dir(p)
		}
	}
	for _, d := range append(append([]string{}, p.WorkingDirectories...), p.WritableDirectories...) {
		add(d)
	}
	for _, d := range []string{"/tmp", "/dev/shm"} {
		if verifyPrivateWritableMount(d) != nil {
			return ErrRuntimeLaunch
		}
	}
	for _, d := range p.WritableDirectories {
		if verifyPrivateWritableMount(d) != nil {
			return ErrRuntimeLaunch
		}
	}
	for _, f := range c.manifest.Files {
		var first os.FileInfo
		for i, guest := range f.GuestPaths {
			add(guest)
			st, e := os.Lstat(guest)
			var inode syscall.Stat_t
			mode := os.FileMode(0400)
			if f.Executable {
				mode = 0500
			}
			if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != mode || st.Size() != f.Bytes || syscall.Lstat(guest, &inode) != nil || inode.Dev != rootStat.Dev || verifyRuntimeMount(guest, 0x01021994, f.Kind != "ELF") != nil {
				return ErrRuntimeLaunch
			}
			if i == 0 {
				first = st
				fd, e := syscall.Open(guest, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
				if e != nil {
					return ErrRuntimeLaunch
				}
				file := os.NewFile(uintptr(fd), "frozen guest code verification")
				h := sha256.New()
				n, re := io.Copy(h, io.NewSectionReader(file, 0, f.Bytes))
				ce := file.Close()
				if re != nil || ce != nil || n != f.Bytes || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
					return ErrRuntimeLaunch
				}
			} else if !os.SameFile(first, st) {
				return ErrRuntimeLaunch
			}
		}
	}
	devices := append([]FrozenDevice{{Path: "/dev/null", Major: 1, Minor: 3}, {Path: "/dev/zero", Major: 1, Minor: 5}, {Path: "/dev/urandom", Major: 1, Minor: 9}}, p.AMDDevices...)
	for _, d := range devices {
		add(d.Path)
		var st syscall.Stat_t
		if syscall.Lstat(d.Path, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFCHR {
			return ErrRuntimeLaunch
		}
		major, minor := linuxDeviceNumbers(uint64(st.Rdev))
		if major != d.Major || minor != d.Minor {
			return ErrRuntimeLaunch
		}
	}
	skip := map[string]bool{"/proc": true, "/sys": true, "/tmp": true, "/dev/shm": true}
	for _, d := range p.WritableDirectories {
		skip[d] = true
	}
	count := 0
	e = filepath.WalkDir("/", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return ErrRuntimeLaunch
		}
		count++
		if count > 16384 || !allowed[p] || d.Type()&os.ModeSymlink != 0 {
			return ErrRuntimeLaunch
		}
		if d.IsDir() && skip[p] {
			return fs.SkipDir
		}
		if d.IsDir() {
			var st syscall.Stat_t
			if syscall.Lstat(p, &st) != nil || st.Dev != rootStat.Dev || verifyRuntimeMount(p, 0x01021994, false) != nil {
				return ErrRuntimeLaunch
			}
		}
		return nil
	})
	if e != nil {
		return ErrRuntimeLaunch
	}
	// Even an inherited directory FD could escape the intended filesystem.
	fds, e := os.ReadDir("/proc/self/fd")
	if e != nil || len(fds) > 4096 {
		return ErrRuntimeLaunch
	}
	for _, f := range fds {
		n, e := strconv.Atoi(f.Name())
		if e != nil {
			return ErrRuntimeLaunch
		}
		if n <= 2 {
			continue
		}
		var st syscall.Stat_t
		if syscall.Fstat(n, &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
			return ErrRuntimeLaunch
		}
	}
	return nil
}
