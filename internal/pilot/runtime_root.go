package pilot

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

var ErrFrozenRoot = errors.New("B007 private frozen runtime root rejected")

type FrozenDevice struct {
	Path  string `json:"path"`
	Major uint32 `json:"major"`
	Minor uint32 `json:"minor"`
}

// The final helper authenticates this plan as a DATA member of its accepted
// capsule. These fields describe only a private filesystem, not code-origin
// acceptance, a model profile, certification, or permission to invoke a model.
type FrozenRootPlan struct {
	Schema              string         `json:"schema"`
	WorkingDirectories  []string       `json:"working_directories"`
	WritableDirectories []string       `json:"writable_directories"`
	HardwareSysfs       bool           `json:"hardware_sysfs"`
	AMDDevices          []FrozenDevice `json:"amd_devices"`
}

type FrozenRuntimeRoot struct {
	pid     int
	entered bool
}

func safeRootDirectory(p string) bool {
	return len(p) > 1 && len(p) <= 1024 && strings.HasPrefix(p, "/") && p == path.Clean(p) && !strings.ContainsAny(p, "\\\x00\r\n")
}

func validateFrozenRootPlan(p FrozenRootPlan, m RuntimeCodeManifest) error {
	if p.Schema != "aipt.private.b007-frozen-runtime-root-plan/v1" || len(p.WorkingDirectories) == 0 || len(p.WorkingDirectories) > 8 || len(p.WritableDirectories) > 8 || len(p.AMDDevices) > 9 || (len(p.AMDDevices) > 0 && !p.HardwareSysfs) {
		return ErrFrozenRoot
	}
	dirs := map[string]bool{}
	for _, d := range append(append([]string{}, p.WorkingDirectories...), p.WritableDirectories...) {
		if !safeRootDirectory(d) || dirs[d] {
			return ErrFrozenRoot
		}
		for _, reserved := range []string{"/proc", "/sys", "/dev", "/tmp"} {
			if d == reserved || strings.HasPrefix(d, reserved+"/") {
				return ErrFrozenRoot
			}
		}
		for _, f := range m.Files {
			for _, guest := range f.GuestPaths {
				if d == guest || strings.HasPrefix(d, guest+"/") {
					return ErrFrozenRoot
				}
			}
		}
		dirs[d] = true
	}
	for _, d := range p.WritableDirectories {
		if !strings.HasPrefix(d, "/aipt/private/") {
			return ErrFrozenRoot
		}
		for _, f := range m.Files {
			for _, guest := range f.GuestPaths {
				if guest == d || strings.HasPrefix(guest, d+"/") {
					return ErrFrozenRoot
				}
			}
		}
		for _, other := range p.WritableDirectories {
			if d != other && strings.HasPrefix(d, other+"/") {
				return ErrFrozenRoot
			}
		}
	}
	devices := map[string]bool{}
	for _, d := range p.AMDDevices {
		ok := d.Path == "/dev/kfd"
		if strings.HasPrefix(d.Path, "/dev/dri/renderD") {
			n, e := strconv.Atoi(strings.TrimPrefix(d.Path, "/dev/dri/renderD"))
			ok = e == nil && n >= 128 && n <= 255 && d.Path == "/dev/dri/renderD"+strconv.Itoa(n)
		}
		if !ok || d.Major == 0 || devices[d.Path] {
			return ErrFrozenRoot
		}
		devices[d.Path] = true
	}
	return nil
}

func namespaceIsNotHost(kind string) bool {
	return ownedKernelNamespace(kind)
}

func linuxDeviceNumbers(n uint64) (uint32, uint32) {
	return uint32((n>>8)&0xfff | (n>>32)&0xfffff000), uint32(n&0xff | (n>>12)&0xffffff00)
}

func holdFrozenDevice(d FrozenDevice) (*os.File, error) {
	fd, e := syscall.Open(d.Path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrFrozenRoot
	}
	f := os.NewFile(uintptr(fd), "held B007 kernel device")
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		f.Close()
		return nil, ErrFrozenRoot
	}
	major, minor := linuxDeviceNumbers(uint64(st.Rdev))
	if major != d.Major || minor != d.Minor {
		f.Close()
		return nil, ErrFrozenRoot
	}
	return f, nil
}

func rootDirectory(base, guest string) error {
	if guest != "/" && !safeRootDirectory(guest) {
		return ErrFrozenRoot
	}
	return os.MkdirAll(base+guest, 0755)
}

func rootFileTarget(base, guest string) (string, error) {
	if !safeRootDirectory(guest) {
		return "", ErrFrozenRoot
	}
	if e := rootDirectory(base, path.Dir(guest)); e != nil {
		return "", e
	}
	target := base + guest
	fd, e := syscall.Open(target, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return "", e
	}
	if e = syscall.Close(fd); e != nil {
		return "", e
	}
	return target, nil
}

func bindFrozenObject(base, guest string, f *os.File, code, device bool) error {
	target, e := rootFileTarget(base, guest)
	if e != nil {
		return e
	}
	source := "/proc/self/fd/" + strconv.Itoa(int(f.Fd()))
	if e = syscall.Mount(source, target, "", syscall.MS_BIND, ""); e != nil {
		return e
	}
	flags := uintptr(syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_RDONLY | syscall.MS_NOSUID)
	if !code {
		flags |= syscall.MS_NOEXEC
	}
	if !device {
		flags |= syscall.MS_NODEV
	}
	return syscall.Mount("", target, "", flags, "")
}

// A memfd has an anonymous dentry and is not bind-mountable on this kernel.
// Copy only from the already verified, write-sealed object into a newly
// created private tmpfs inode. Close its only writer, check the exact copy
// digest, then make every alias and the whole filesystem read-only. No code
// source is a mutable host path and constrained children cannot remount it.
func copyFrozenCode(base string, spec RuntimeCodeFile, source *os.File) error {
	first, e := rootFileTarget(base, spec.GuestPaths[0])
	if e != nil {
		return e
	}
	fd, e := syscall.Open(first, syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "private tmpfs code copy")
	hash := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, hash), io.NewSectionReader(source, 0, spec.Bytes))
	if e != nil || n != spec.Bytes || hex.EncodeToString(hash.Sum(nil)) != spec.SHA256 {
		f.Close()
		return ErrFrozenRoot
	}
	mode := os.FileMode(0400)
	if spec.Executable {
		mode = 0500
	}
	if e = f.Chmod(mode); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	for i, guest := range spec.GuestPaths {
		target := first
		if i > 0 {
			target, e = rootFileTarget(base, guest)
			if e != nil {
				return e
			}
		}
		if e = syscall.Mount(first, target, "", syscall.MS_BIND, ""); e != nil {
			return e
		}
		flags := uintptr(syscall.MS_REMOUNT | syscall.MS_BIND | syscall.MS_RDONLY | syscall.MS_NOSUID | syscall.MS_NODEV)
		if spec.Kind != "ELF" {
			flags |= syscall.MS_NOEXEC
		}
		if e = syscall.Mount("", target, "", flags, ""); e != nil {
			return e
		}
	}
	return nil
}

type recursiveMountAttributes struct{ Set, Clear, Propagation, UserNS uint64 }

func freezeHardwareTree(target string) error {
	// mount_setattr on the fixed Linux amd64 class, recursively. A plain
	// read-only bind cannot make pre-existing nested mounts read-only.
	p, e := syscall.BytePtrFromString(target)
	if e != nil {
		return e
	}
	attr := recursiveMountAttributes{Set: 1 | 2 | 4 | 8} // RDONLY | NOSUID | NODEV | NOEXEC
	dirfd := int64(-100)
	_, _, eno := syscall.Syscall6(442, uintptr(dirfd), uintptr(unsafe.Pointer(p)), 0x8000, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if eno != 0 {
		return eno
	}
	return nil
}

// EnterFrozenRuntimeRoot may only run in a dedicated freshly exec'd helper,
// inside distinct user, PID and mount namespaces. Its caller MUST lock the OS
// thread for setup and every later child exec. On any failure the helper exits;
// no partially prepared root is usable. Code comes only from write-sealed
// capsule objects; writable mounts are NOEXEC and no host directory is kept.
// Kernel proc/sysfs/device interfaces are the explicit hardware trust base.
func EnterFrozenRuntimeRoot(c *HeldCodeCapsule, p FrozenRootPlan) (*FrozenRuntimeRoot, error) {
	if c == nil || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 || !namespaceIsNotHost("user") || !namespaceIsNotHost("pid") || !namespaceIsNotHost("mnt") {
		return nil, ErrFrozenRoot
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !digest(c.identity) || validateFrozenRootPlan(p, c.manifest) != nil {
		return nil, ErrFrozenRoot
	}
	var deviceFiles []*os.File
	defer func() {
		for _, f := range deviceFiles {
			_ = f.Close()
		}
	}()
	devices := append([]FrozenDevice{{Path: "/dev/null", Major: 1, Minor: 3}, {Path: "/dev/zero", Major: 1, Minor: 5}, {Path: "/dev/urandom", Major: 1, Minor: 9}}, p.AMDDevices...)
	for _, d := range devices {
		f, e := holdFrozenDevice(d)
		if e != nil {
			return nil, ErrFrozenRoot
		}
		deviceFiles = append(deviceFiles, f)
	}
	if e := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); e != nil {
		return nil, ErrFrozenRoot
	}
	// Mount over /tmp in this helper's mount namespace before creating anything;
	// no host directory or file is created, modified or retained as a fallback.
	if e := syscall.Mount("tmpfs", "/tmp", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "size=16m,mode=0700"); e != nil {
		return nil, ErrFrozenRoot
	}
	base := "/tmp/aipt-b007-frozen-root"
	if e := os.Mkdir(base, 0700); e != nil {
		return nil, ErrFrozenRoot
	}
	var imageBytes int64 = 16 << 20
	for _, spec := range c.manifest.Files {
		imageBytes += spec.Bytes
	}
	if e := syscall.Mount("tmpfs", base, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "size="+strconv.FormatInt(imageBytes, 10)+",mode=0755"); e != nil {
		return nil, ErrFrozenRoot
	}
	directories := append(append([]string{"/proc", "/sys", "/dev", "/dev/shm", "/tmp"}, p.WorkingDirectories...), p.WritableDirectories...)
	for _, d := range directories {
		if e := rootDirectory(base, d); e != nil {
			return nil, ErrFrozenRoot
		}
	}
	for _, spec := range c.manifest.Files {
		f := c.files[spec.AssetID]
		if f == nil {
			return nil, ErrFrozenRoot
		}
		seals, _, eno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), 0x40a, 0)
		if eno != 0 || seals&0xf != 0xf {
			return nil, ErrFrozenRoot
		}
		if e := copyFrozenCode(base, spec, f); e != nil {
			return nil, fmt.Errorf("%w: private frozen code copy: %w", ErrFrozenRoot, e)
		}
	}
	for i, d := range devices {
		if e := bindFrozenObject(base, d.Path, deviceFiles[i], false, true); e != nil {
			return nil, fmt.Errorf("%w: device bind: %w", ErrFrozenRoot, e)
		}
	}
	if p.HardwareSysfs {
		if e := syscall.Mount("/sys", base+"/sys", "", syscall.MS_BIND|syscall.MS_REC, ""); e != nil {
			return nil, fmt.Errorf("%w: hardware bind: %w", ErrFrozenRoot, e)
		}
		if e := freezeHardwareTree(base + "/sys"); e != nil {
			return nil, fmt.Errorf("%w: recursive hardware freeze: %w", ErrFrozenRoot, e)
		}
	}
	for _, d := range append([]string{"/tmp", "/dev/shm"}, p.WritableDirectories...) {
		if e := syscall.Mount("tmpfs", base+d, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "size=64m,mode=0700"); e != nil {
			return nil, ErrFrozenRoot
		}
	}
	if e := syscall.Mount("", base, "", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV, ""); e != nil {
		return nil, ErrFrozenRoot
	}
	if e := syscall.Chroot(base); e != nil {
		return nil, ErrFrozenRoot
	}
	if e := os.Chdir(p.WorkingDirectories[0]); e != nil {
		return nil, ErrFrozenRoot
	}
	if e := syscall.Mount("proc", "/proc", "proc", syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); e != nil {
		return nil, ErrFrozenRoot
	}
	// No directory descriptor may preserve an escape to the old filesystem.
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		return nil, ErrFrozenRoot
	}
	for _, entry := range entries {
		n, e := strconv.Atoi(entry.Name())
		if e != nil || n <= 2 {
			continue
		}
		var st syscall.Stat_t
		if syscall.Fstat(n, &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
			if e = syscall.Close(n); e != nil {
				return nil, ErrFrozenRoot
			}
		}
	}
	return &FrozenRuntimeRoot{pid: os.Getpid(), entered: true}, nil
}

// ConstrainChildExecPrivileges retains setup privileges in this trusted helper
// but removes all capabilities on subsequent exec, including UID 0's special
// treatment. It must be called on the same locked OS thread used to spawn each
// child. The final helper verifies each child reports zero capabilities and
// NoNewPrivs before it can receive a model request.
func ConstrainChildExecPrivileges(root *FrozenRuntimeRoot) error {
	if root == nil || !root.entered || root.pid != os.Getpid() || os.Geteuid() != 0 {
		return ErrFrozenRoot
	}
	const secureBits = 1 | 2 | 4 | 8 | 64 | 128 // NOROOT / NO_SETUID_FIXUP / NO_AMBIENT_RAISE, each locked
	if _, _, eno := syscall.Syscall6(syscall.SYS_PRCTL, 28, secureBits, 0, 0, 0, 0); eno != 0 {
		return ErrFrozenRoot
	}
	for cap := uintptr(0); cap < 64; cap++ {
		present, _, eno := syscall.Syscall6(syscall.SYS_PRCTL, 23, cap, 0, 0, 0, 0)
		if eno == syscall.EINVAL {
			continue
		}
		if eno != 0 {
			return ErrFrozenRoot
		}
		if present != 0 {
			if _, _, eno = syscall.Syscall6(syscall.SYS_PRCTL, 24, cap, 0, 0, 0, 0); eno != 0 {
				return ErrFrozenRoot
			}
		}
	}
	// Clear the inheritable set without removing the helper's current effective
	// and permitted setup capabilities. Child exec obtains neither of those.
	type capHeader struct {
		Version uint32
		PID     int32
	}
	type capData struct{ Effective, Permitted, Inheritable uint32 }
	h := capHeader{Version: 0x20080522}
	var d [2]capData
	if _, _, eno := syscall.Syscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&d)), 0); eno != 0 {
		return ErrFrozenRoot
	}
	d[0].Inheritable = 0
	d[1].Inheritable = 0
	if _, _, eno := syscall.Syscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&d)), 0); eno != 0 {
		return ErrFrozenRoot
	}
	if _, _, eno := syscall.Syscall6(syscall.SYS_PRCTL, 47, 4, 0, 0, 0, 0); eno != 0 {
		return ErrFrozenRoot
	}
	if _, _, eno := syscall.Syscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0); eno != 0 {
		return ErrFrozenRoot
	}
	return nil
}
