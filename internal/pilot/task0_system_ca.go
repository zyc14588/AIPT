package pilot

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

const task0SystemCAPath = "/etc/ssl/certs/ca-certificates.crt"
const task0SystemCASHA = "80eedd808e4cbd6fd42e125da2ea225fd1365d8e29edef8bcc45ff8bc7044ce2"
const task0SystemCABytes int64 = 182140
const task0SystemCAPolicy = "B007_PARENT_SEALED_CA_TO_PREP_READONLY_TMPFS_V1"
const task0Q013AuthoritySHA = "7227316d4d2a4efcbf61d957853cd5fb73c66757df765d08de1cf8dd2a497425"
const task0SetupPolicy = "B007_CAP0_PREP_FIXED_SETUP_NAMESPACE_SUCCESSOR_V1"
const task0Q014AuthoritySHA = "be7639384a7621828e0a67fa23e983c4bbdbafeea426e05294d441717c3ed5ff"

type task0SystemCABinding struct {
	Policy         string `json:"policy"`
	AuthoritySHA   string `json:"authority_sha256"`
	SetupPolicy    string `json:"setup_policy"`
	SetupAuthority string `json:"setup_authority_sha256"`
}

func task0SystemCABindingValid(b task0SystemCABinding) bool {
	return b == (task0SystemCABinding{task0SystemCAPolicy, task0Q013AuthoritySHA, task0SetupPolicy, task0Q014AuthoritySHA})
}

type task0ParentSystemCA struct {
	original, snapshot *os.File
	originalState      syscall.Stat_t
	generation         string
}

func task0InitialParentDomain() bool {
	if os.Getpid() == 1 || os.Getuid() != 1000 || os.Geteuid() != 1000 || os.Getgid() != 1000 || os.Getegid() != 1000 {
		return false
	}
	for _, spec := range []struct {
		kind  string
		inode uint64
		clone uintptr
	}{{"user", 0xeffffffd, syscall.CLONE_NEWUSER}, {"pid", 0xeffffffc, syscall.CLONE_NEWPID},
		{"mnt", 0xeffffff8, syscall.CLONE_NEWNS}, {"net", 0xeffffff9, syscall.CLONE_NEWNET}} {
		fd, err := syscall.Open("/proc/self/ns/"+spec.kind, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			return false
		}
		var st syscall.Stat_t
		var fs syscall.Statfs_t
		kind, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0xb703, 0)
		valid := syscall.Fstat(fd, &st) == nil && syscall.Fstatfs(fd, &fs) == nil && uint64(fs.Type) == 0x6e736673 &&
			st.Ino == spec.inode && errno == 0 && kind == spec.clone
		syscall.Close(fd)
		if !valid {
			return false
		}
	}
	for _, mapping := range []string{"uid_map", "gid_map"} {
		raw, err := os.ReadFile("/proc/self/" + mapping)
		if err != nil || strings.Join(strings.Fields(string(raw)), " ") != "0 0 4294967295" {
			return false
		}
	}
	return true
}

func task0ReadOnlyFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	return os.NewFile(uintptr(fd), "held fixed B007 input"), nil
}

func task0CAFileState(f *os.File) (syscall.Stat_t, error) {
	var s syscall.Stat_t
	if f == nil || syscall.Fstat(int(f.Fd()), &s) != nil {
		return s, ErrRuntimeLaunch
	}
	return s, nil
}

func task0OriginalCAMetadata(s syscall.Stat_t) bool {
	return s.Uid == 0 && s.Mode&syscall.S_IFMT == syscall.S_IFREG && s.Mode&0022 == 0 && s.Nlink == 1 && s.Size == task0SystemCABytes
}

func task0CAExactBytes(f *os.File) bool {
	if f == nil {
		return false
	}
	raw, err := io.ReadAll(io.NewSectionReader(f, 0, task0SystemCABytes+1))
	defer clear(raw)
	return err == nil && int64(len(raw)) == task0SystemCABytes && inputSHA(raw) == task0SystemCASHA
}

func (p *task0ParentSystemCA) stableOriginal() bool {
	if p == nil || p.original == nil || !task0InitialParentDomain() || !task0OriginalCAMetadata(p.originalState) {
		return false
	}
	before, err := task0CAFileState(p.original)
	named, ne := os.Lstat(task0SystemCAPath)
	held, he := p.original.Stat()
	if err != nil || ne != nil || he != nil || !os.SameFile(named, held) || !task0SamePrivateRecordState(p.originalState, before) || !task0CAExactBytes(p.original) {
		return false
	}
	after, err := task0CAFileState(p.original)
	named, ne = os.Lstat(task0SystemCAPath)
	return err == nil && ne == nil && os.SameFile(named, held) && task0SamePrivateRecordState(before, after)
}

func openTask0ParentSystemCA() (*task0ParentSystemCA, error) {
	if !task0InitialParentDomain() {
		return nil, ErrRuntimeLaunch
	}
	original, err := task0ReadOnlyFile(task0SystemCAPath)
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	p := &task0ParentSystemCA{original: original}
	fail := func() (*task0ParentSystemCA, error) { p.close(); return nil, ErrRuntimeLaunch }
	p.originalState, err = task0CAFileState(original)
	if err != nil || !p.stableOriginal() {
		return fail()
	}
	raw, err := io.ReadAll(io.NewSectionReader(original, 0, task0SystemCABytes+1))
	defer clear(raw)
	if err != nil || int64(len(raw)) != task0SystemCABytes || inputSHA(raw) != task0SystemCASHA {
		return fail()
	}
	p.snapshot, err = task0SealedBytes(raw)
	if err != nil || !task0SealedCAValid(p.snapshot, 1000) || !p.stableOriginal() {
		return fail()
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return fail()
	}
	p.generation = hex.EncodeToString(nonce[:])
	return p, nil
}

// The owner calls close only after joining its PREP, including failed starts.
func (p *task0ParentSystemCA) close() {
	if p == nil {
		return
	}
	if p.snapshot != nil {
		p.snapshot.Close()
	}
	if p.original != nil {
		p.original.Close()
	}
}

func task0SealedCAValid(f *os.File, uid uint32) bool {
	return task0SealedCAMetadata(f, uid) && task0CAExactBytes(f)
}

// Anonymous memfd objects have no directory links. This is separate from
// the single-link named host original and private tmpfs materialization.
func task0SealedCAMetadata(f *os.File, uid uint32) bool {
	s, err := task0CAFileState(f)
	if err != nil || s.Uid != uid || s.Mode&syscall.S_IFMT != syscall.S_IFREG || s.Mode&07777 != 0400 || s.Nlink != 0 || s.Size != task0SystemCABytes {
		return false
	}
	seals, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), 0x40a, 0)
	return e == 0 && seals&0xf == 0xf
}

type task0MaterializedCA struct {
	source, original, materialized, target *os.File
	directory                              *os.File
	root                                   string
	state                                  syscall.Stat_t
}

// root is the authenticated outside Parent's newly created, held empty
// directory. This creates no host CA file and changes only PREP's private MNT.
// There is deliberately no unmount path after capability convergence.
func materializeTask0SystemCA(source, original, rootFD *os.File) (*task0MaterializedCA, error) {
	if os.Getpid() != 1 || os.Geteuid() != 0 || !namespaceIsNotHost("user") || !namespaceIsNotHost("pid") ||
		!namespaceIsNotHost("mnt") || !task0SealedCAValid(source, 0) || original == nil || rootFD == nil {
		return nil, ErrRuntimeLaunch
	}
	o, err := task0CAFileState(original)
	d, de := task0CAFileState(rootFD)
	root, re := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(rootFD.Fd())))
	if err != nil || de != nil || re != nil || o.Uid != 65534 || o.Mode&syscall.S_IFMT != syscall.S_IFREG || o.Mode&0022 != 0 ||
		o.Size != task0SystemCABytes || o.Nlink != 1 || !task0CAExactBytes(original) ||
		d.Uid != 0 || d.Mode&syscall.S_IFMT != syscall.S_IFDIR || d.Mode&07777 != 0700 ||
		!strings.HasPrefix(root, "/tmp/aipt-b007-q014-runtime-ca-") || filepath.Clean(root) != root || filepath.Base(root) != "ca-root" || strings.ContainsAny(root, "\x00\r\n") {
		return nil, ErrRuntimeLaunch
	}
	named, err := os.Lstat(root)
	held, he := rootFD.Stat()
	entries, ee := os.ReadDir(root)
	if err != nil || he != nil || ee != nil || !os.SameFile(named, held) || len(entries) != 0 {
		return nil, ErrRuntimeLaunch
	}
	// The inherited Parent descriptor pins identity but carries the Parent's
	// mount reference. Resolve that same inode afresh in PREP's owned mount
	// namespace before using a descriptor as this namespace's mount target.
	currentFD, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	current := os.NewFile(uintptr(currentFD), "held PREP mountpoint in own namespace")
	defer current.Close()
	currentState, err := task0CAFileState(current)
	if err != nil || currentState.Dev != d.Dev || currentState.Ino != d.Ino || currentState.Uid != 0 || currentState.Mode&07777 != 0700 {
		return nil, ErrRuntimeLaunch
	}
	if syscall.Mount("tmpfs", "/proc/self/fd/"+strconv.Itoa(currentFD), "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "size=1m,mode=0700") != nil {
		return nil, ErrRuntimeLaunch
	}
	directoryFD, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	directory := os.NewFile(uintptr(directoryFD), "held own PREP tmpfs root")
	var directoryFS syscall.Statfs_t
	var directoryState syscall.Stat_t
	if syscall.Fstatfs(directoryFD, &directoryFS) != nil || uint64(directoryFS.Type) != 0x01021994 ||
		syscall.Fstat(directoryFD, &directoryState) != nil || directoryState.Uid != 0 || directoryState.Mode&syscall.S_IFMT != syscall.S_IFDIR || directoryState.Mode&07777 != 0700 ||
		(directoryState.Dev == d.Dev && directoryState.Ino == d.Ino) {
		directory.Close()
		return nil, ErrRuntimeLaunch
	}
	// Copy only through a held, verified private tmpfs directory. A rename of
	// the Parent's empty host mountpoint cannot redirect this writer to disk.
	fd, err := syscall.Openat(directoryFD, "system-ca", syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		directory.Close()
		return nil, ErrRuntimeLaunch
	}
	writer := os.NewFile(uintptr(fd), "owned PREP CA materialization writer")
	n, copyErr := io.Copy(writer, io.NewSectionReader(source, 0, task0SystemCABytes+1))
	modeErr, syncErr := writer.Chmod(0400), writer.Sync()
	state, statErr := task0CAFileState(writer)
	closeErr := writer.Close()
	if copyErr != nil || modeErr != nil || syncErr != nil || statErr != nil || closeErr != nil || n != task0SystemCABytes {
		directory.Close()
		return nil, ErrRuntimeLaunch
	}
	m := &task0MaterializedCA{source: source, original: original, directory: directory, root: root, state: state}
	readFD, err := syscall.Openat(directoryFD, "system-ca", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		directory.Close()
		return nil, ErrRuntimeLaunch
	}
	m.materialized = os.NewFile(uintptr(readFD), "held own tmpfs CA")
	fail := func() (*task0MaterializedCA, error) { m.closeTargets(); return nil, ErrRuntimeLaunch }
	if syscall.Mount("/proc/self/fd/"+strconv.Itoa(int(m.materialized.Fd())), task0SystemCAPath, "", syscall.MS_BIND, "") != nil ||
		syscall.Mount("", task0SystemCAPath, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "") != nil ||
		syscall.Mount("", "/proc/self/fd/"+strconv.Itoa(directoryFD), "tmpfs", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "size=1m,mode=0700") != nil {
		return fail()
	}
	m.target, err = task0ReadOnlyFile(task0SystemCAPath)
	if err != nil || !m.valid("/proc/self") {
		return fail()
	}
	return m, nil
}

func task0MaterializedCAFileValid(f *os.File, dev, ino uint64) bool {
	s, err := task0CAFileState(f)
	var fs syscall.Statfs_t
	return err == nil && s.Uid == 0 && s.Mode&syscall.S_IFMT == syscall.S_IFREG && s.Mode&07777 == 0400 &&
		s.Size == task0SystemCABytes && s.Nlink == 1 && s.Dev == dev && s.Ino == ino && task0CAExactBytes(f) &&
		syscall.Fstatfs(int(f.Fd()), &fs) == nil && uint64(fs.Type) == 0x01021994 && fs.Flags&15 == 15
}

func (m *task0MaterializedCA) valid(procRoot string) bool {
	if m == nil || !task0SealedCAValid(m.source, 0) || !task0CAExactBytes(m.original) ||
		!task0MaterializedCAFileValid(m.materialized, m.state.Dev, m.state.Ino) || !task0MaterializedCAFileValid(m.target, m.state.Dev, m.state.Ino) {
		return false
	}
	s, se := task0CAFileState(m.source)
	o, oe := task0CAFileState(m.original)
	if se != nil || oe != nil || (s.Dev == m.state.Dev && s.Ino == m.state.Ino) || (o.Dev == m.state.Dev && o.Ino == m.state.Ino) || (s.Dev == o.Dev && s.Ino == o.Ino) {
		return false
	}
	for _, path := range []string{m.root + "/system-ca", task0SystemCAPath} {
		f, err := task0ReadOnlyFile(path)
		if err != nil {
			return false
		}
		valid := task0MaterializedCAFileValid(f, m.state.Dev, m.state.Ino)
		f.Close()
		if !valid {
			return false
		}
	}
	return task0CAMountAliasesValid(procRoot, m.root, m.state.Dev) && task0CANoWriterFD(procRoot, m.state.Dev, m.state.Ino)
}

func task0CAMountAliasesValid(procRoot, root string, dev uint64) bool {
	raw, err := os.ReadFile(procRoot + "/mountinfo")
	if err != nil || len(raw) > 4<<20 {
		return false
	}
	return task0CAMountAliases(raw, root, dev)
}

func task0CAMountAliases(raw []byte, root string, dev uint64) bool {
	if len(raw) == 0 || len(raw) > 4<<20 || !task0PreparationPath(root) {
		return false
	}
	major, minor := linuxDeviceNumbers(dev)
	device := fmt.Sprintf("%d:%d", major, minor)
	aliases := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		v := strings.Fields(line)
		if len(v) < 10 || v[2] != device {
			continue
		}
		sep := slices.Index(v, "-")
		if sep < 6 || sep+3 >= len(v) || v[sep+1] != "tmpfs" || (v[4] != root && v[4] != task0SystemCAPath) || aliases[v[4]] {
			return false
		}
		for _, flag := range []string{"ro", "nosuid", "nodev", "noexec"} {
			if !strings.Contains(","+v[5]+",", ","+flag+",") {
				return false
			}
		}
		if !strings.Contains(","+v[sep+3]+",", ",ro,") {
			return false
		}
		for _, option := range v[6:sep] {
			if strings.HasPrefix(option, "shared:") || strings.HasPrefix(option, "master:") {
				return false
			}
		}
		aliases[v[4]] = true
	}
	return len(aliases) == 2 && aliases[root] && aliases[task0SystemCAPath]
}

func task0CANoWriterFD(procRoot string, dev, ino uint64) bool {
	entries, err := os.ReadDir(procRoot + "/fd")
	if err != nil {
		return false
	}
	count := 0
	for _, entry := range entries {
		info, err := os.Stat(procRoot + "/fd/" + entry.Name())
		if os.IsNotExist(err) {
			continue // The directory enumeration's temporary descriptor.
		}
		if err != nil {
			return false
		}
		s, ok := info.Sys().(*syscall.Stat_t)
		if !ok || s.Dev != dev || s.Ino != ino {
			continue
		}
		raw, err := os.ReadFile(procRoot + "/fdinfo/" + entry.Name())
		if err != nil {
			return false
		}
		flagsFound := false
		for _, line := range strings.Split(string(raw), "\n") {
			if v, ok := strings.CutPrefix(line, "flags:"); ok {
				flags, err := strconv.ParseUint(strings.TrimSpace(v), 8, 64)
				if err != nil || flags&syscall.O_ACCMODE != syscall.O_RDONLY {
					return false
				}
				flagsFound = true
			}
		}
		if !flagsFound {
			return false
		}
		count++
	}
	return count >= 2
}

func (m *task0MaterializedCA) closeTargets() {
	if m == nil {
		return
	}
	if m.target != nil {
		m.target.Close()
	}
	if m.materialized != nil {
		m.materialized.Close()
	}
	if m.directory != nil {
		m.directory.Close()
	}
}
