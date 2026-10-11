package pilot

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// A single-root mapping cannot describe the initial host user namespace. Its
// only mapped principal is the account selected by the authenticated parent
// launcher. Kernel namespace ownership, rather than permission to inspect the
// unrelated global PID 1, proves that mount/PID/network namespaces belong to
// this restricted user namespace. The helper's exact parent launcher, held
// executable and accepted policy still grant the authority to enter a root.
func singleRootIDMapping(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 256 {
		return false
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 3 || fields[0] != "0" || fields[2] != "1" {
		return false
	}
	outer, e := strconv.ParseUint(fields[1], 10, 32)
	return e == nil && outer < 0xffffffff
}

func ownedKernelNamespace(kind string) bool {
	types := map[string]uintptr{"user": syscall.CLONE_NEWUSER, "pid": syscall.CLONE_NEWPID, "mnt": syscall.CLONE_NEWNS, "net": syscall.CLONE_NEWNET}
	cloneType, ok := types[kind]
	if !ok || os.Geteuid() != 0 || os.Getegid() != 0 {
		return false
	}
	for _, name := range []string{"uid_map", "gid_map"} {
		raw, e := os.ReadFile("/proc/self/" + name)
		if e != nil || !singleRootIDMapping(raw) {
			return false
		}
	}
	user, e := os.Open("/proc/self/ns/user")
	if e != nil {
		return false
	}
	defer user.Close()
	userInfo, e := user.Stat()
	if e != nil {
		return false
	}
	file, e := os.Open("/proc/self/ns/" + kind)
	if e != nil {
		return false
	}
	defer file.Close()
	for _, f := range []*os.File{user, file} {
		var fs syscall.Statfs_t
		if syscall.Fstatfs(int(f.Fd()), &fs) != nil || uint64(fs.Type) != 0x6e736673 { // NSFS_MAGIC
			return false
		}
	}
	actualType, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), 0xb703, 0) // NS_GET_NSTYPE
	if errno != 0 || actualType != cloneType {
		return false
	}
	if kind == "user" {
		return true
	}
	ownerFD, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), 0xb701, 0) // NS_GET_USERNS
	if errno != 0 {
		return false
	}
	if ownerFD <= 2 {
		_ = syscall.Close(int(ownerFD))
		return false
	}
	owner := os.NewFile(ownerFD, "kernel owning user namespace")
	defer owner.Close()
	ownerInfo, e := owner.Stat()
	return e == nil && os.SameFile(userInfo, ownerInfo)
}
