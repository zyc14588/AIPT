package pilot

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const task0CAAdmissionSchema = "aipt.private.b007-fixed-ca-preparation-admission/v1"

// Every identity is checked against a held object or an outside-parent
// binding. The child's proof never supplies a new path, authority or program.
type task0CAProof struct {
	CA              task0SystemCABinding `json:"system_ca"`
	BindingSHA      string               `json:"preparation_binding_sha256"`
	ExecutableSHA   string               `json:"preparation_executable_sha256"`
	Generation      string               `json:"generation"`
	SetupSHA        string               `json:"setup_executable_sha256"`
	SetupBindingSHA string               `json:"setup_binding_sha256"`
	SetupAdmitted   bool                 `json:"fixed_setup_admitted_before_cap0"`
	Original        task0SetupFDIdentity `json:"original"`
	Source          task0SetupFDIdentity `json:"sealed_source"`
	Materialized    task0SetupFDIdentity `json:"materialized"`
	Bytes           int64                `json:"ca_bytes"`
	SHA256          string               `json:"ca_sha256"`
	Threads         int                  `json:"complete_current_thread_count"`
}

type task0CAFrame struct {
	Schema     string                  `json:"schema"`
	Operation  string                  `json:"operation"`
	BindingSHA string                  `json:"binding_sha256"`
	Generation string                  `json:"generation"`
	Nonce      string                  `json:"nonce"`
	Proof      *task0CAProof           `json:"proof,omitempty"`
	Result     *task0PreparationResult `json:"result,omitempty"`
}

func task0CAPacket(c *net.UnixConn, f *task0CAFrame, write bool) error {
	if c == nil || f == nil {
		return ErrRuntimeLaunch
	}
	if write {
		raw, err := json.Marshal(f)
		if err != nil || len(raw) > 4096 {
			return ErrRuntimeLaunch
		}
		n, err := c.Write(raw)
		if err != nil || n != len(raw) {
			return ErrRuntimeLaunch
		}
		return nil
	}
	var raw [4097]byte
	n, err := c.Read(raw[:])
	if err != nil || n < 1 || n > 4096 || decodeFrozenJSON(raw[:n], 4096, f) != nil {
		return ErrRuntimeLaunch
	}
	return nil
}

func task0CAFrameValid(f task0CAFrame, operation, binding, generation, nonce string) bool {
	return f.Schema == task0CAAdmissionSchema && f.Operation == operation && f.BindingSHA == binding &&
		f.Generation == generation && f.Nonce == nonce && digest(binding) && digest(generation) && digest(nonce)
}

func task0CAIdentity(f *os.File) (task0SetupFDIdentity, error) {
	s, err := task0CAFileState(f)
	if err != nil || s.Ino == 0 {
		return task0SetupFDIdentity{}, ErrRuntimeLaunch
	}
	return task0SetupFDIdentity{s.Dev, s.Ino}, nil
}

func task0CAProofIdentities(p *task0CAProof) bool {
	return p != nil && task0SystemCABindingValid(p.CA) && digest(p.BindingSHA) && digest(p.ExecutableSHA) && digest(p.Generation) &&
		digest(p.SetupSHA) && digest(p.SetupBindingSHA) && p.SetupAdmitted && p.Bytes == task0SystemCABytes && p.SHA256 == task0SystemCASHA &&
		p.Threads >= 1 && p.Threads <= 512 && p.Original.Ino != 0 && p.Source.Ino != 0 && p.Materialized.Ino != 0 &&
		p.Original != p.Source && p.Original != p.Materialized && p.Source != p.Materialized
}

type task0CAParentDirectory struct {
	outer, root           string
	outerFD, rootFD       *os.File
	outerState, rootState syscall.Stat_t
}

func openTask0CAParentDirectory() (*task0CAParentDirectory, error) {
	if !task0InitialParentDomain() {
		return nil, ErrRuntimeLaunch
	}
	outer, err := os.MkdirTemp("/tmp", "aipt-b007-q014-runtime-ca-")
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	d := &task0CAParentDirectory{outer: outer, root: filepath.Join(outer, "ca-root")}
	// These are new, empty, Parent-owned directories. No recursive removal is
	// ever used for the materialization mountpoint or any input/evidence path.
	if os.Chmod(outer, 0700) != nil || os.Mkdir(d.root, 0700) != nil {
		_ = os.Remove(outer)
		return nil, ErrRuntimeLaunch
	}
	for i, path := range []string{d.outer, d.root} {
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			d.close()
			_ = os.Remove(d.root)
			_ = os.Remove(d.outer)
			return nil, ErrRuntimeLaunch
		}
		f := os.NewFile(uintptr(fd), "held own empty CA mountpoint")
		s, err := task0CAFileState(f)
		if i == 0 {
			d.outerFD, d.outerState = f, s
		} else {
			d.rootFD, d.rootState = f, s
		}
		if err != nil || s.Uid != 1000 || s.Mode&syscall.S_IFMT != syscall.S_IFDIR || s.Mode&07777 != 0700 {
			d.close()
			return nil, ErrRuntimeLaunch
		}
	}
	if !d.stableEmpty() {
		d.close()
		return nil, ErrRuntimeLaunch
	}
	return d, nil
}

func (d *task0CAParentDirectory) stableEmpty() bool {
	if d == nil || d.outerFD == nil || d.rootFD == nil {
		return false
	}
	for _, spec := range []struct {
		path  string
		file  *os.File
		state syscall.Stat_t
	}{{d.outer, d.outerFD, d.outerState}, {d.root, d.rootFD, d.rootState}} {
		s, err := task0CAFileState(spec.file)
		named, ne := os.Lstat(spec.path)
		held, he := spec.file.Stat()
		if err != nil || ne != nil || he != nil || !os.SameFile(named, held) || !task0SameReportDirectory(s, spec.state) {
			return false
		}
	}
	entries, err := os.ReadDir(d.root)
	outer, oe := os.ReadDir(d.outer)
	return err == nil && oe == nil && len(entries) == 0 && len(outer) == 1 && outer[0].Name() == "ca-root" && outer[0].IsDir()
}

// Called only after a direct PREP join. A missing join proof leaves the
// owned empty paths for diagnosis; it never triggers broad host cleanup.
func (d *task0CAParentDirectory) removeAfterJoin(joined bool) error {
	if !joined || !d.stableEmpty() || os.Remove(d.root) != nil {
		return ErrRuntimeLaunch
	}
	entries, err := os.ReadDir(d.outer)
	held, he := d.outerFD.Stat()
	named, ne := os.Lstat(d.outer)
	if err != nil || he != nil || ne != nil || len(entries) != 0 || !os.SameFile(held, named) || os.Remove(d.outer) != nil {
		return ErrRuntimeLaunch
	}
	return nil
}

func (d *task0CAParentDirectory) close() {
	if d != nil {
		if d.rootFD != nil {
			_ = d.rootFD.Close()
		}
		if d.outerFD != nil {
			_ = d.outerFD.Close()
		}
	}
}

// The observation UID is authenticated by the outside parent's fixed 0 to
// 1000 mapping. A child's claimed owner cannot change the readback domain.
func task0ObservedCAFile(f *os.File, owner uint32, identity task0SetupFDIdentity) bool {
	s, err := task0CAFileState(f)
	var fs syscall.Statfs_t
	return err == nil && s.Uid == owner && s.Mode&syscall.S_IFMT == syscall.S_IFREG && s.Mode&07777 == 0400 && s.Nlink == 1 &&
		s.Size == task0SystemCABytes && s.Dev == identity.Dev && s.Ino == identity.Ino && task0CAExactBytes(f) &&
		syscall.Fstatfs(int(f.Fd()), &fs) == nil && uint64(fs.Type) == 0x01021994 && fs.Flags&15 == 15
}

func task0ParentCAReadback(p *freshPreparationProcess, self *os.File, b task0ParentBinding, ca *task0ParentSystemCA, directory *task0CAParentDirectory, proof *task0CAProof) (int, error) {
	if p == nil || ca == nil || directory == nil || !task0CAProofIdentities(proof) || proof.CA != b.SystemCA ||
		proof.BindingSHA != b.PreparationSHA || proof.ExecutableSHA != b.ExecutableSHA || proof.Generation != ca.generation ||
		!ca.stableOriginal() || !task0SealedCAValid(ca.snapshot, 1000) || !directory.stableEmpty() || verifiedPreparationChild(p.command, self) != nil {
		return 0, ErrRuntimeLaunch
	}
	a, err := decodeTask0Preparation(b.Preparation, b.PreparationSHA)
	if err != nil {
		return 0, ErrRuntimeLaunch
	}
	if proof.SetupSHA != a.binding.Setup.SHA256 || proof.SetupBindingSHA != a.setup.identity {
		return 0, ErrRuntimeLaunch
	}
	original, oe := task0CAIdentity(ca.original)
	source, se := task0CAIdentity(ca.snapshot)
	if oe != nil || se != nil || proof.Original != original || proof.Source != source {
		return 0, ErrRuntimeLaunch
	}
	base := "/proc/" + strconv.Itoa(p.command.Process.Pid)
	if parent, err := task0ObservedParentPID(p.command.Process.Pid); err != nil || parent != os.Getpid() {
		return 0, ErrRuntimeLaunch
	}
	threads, err := task0PrivilegeThreads(base, 0, 1000, 1000)
	if err != nil {
		return 0, ErrRuntimeLaunch
	}
	for _, path := range []string{base + "/root" + task0SystemCAPath, base + "/root" + directory.root + "/system-ca"} {
		f, err := task0ReadOnlyFile(path)
		if err != nil {
			return 0, ErrRuntimeLaunch
		}
		valid := task0ObservedCAFile(f, 1000, proof.Materialized)
		closeErr := f.Close()
		if !valid || closeErr != nil {
			return 0, ErrRuntimeLaunch
		}
	}
	if !task0CAMountAliasesValid(base, directory.root, proof.Materialized.Dev) || !task0CANoWriterFD(base, proof.Materialized.Dev, proof.Materialized.Ino) ||
		verifiedPreparationChild(p.command, self) != nil || !ca.stableOriginal() {
		return 0, ErrRuntimeLaunch
	}
	return len(threads), nil
}

func task0ObservedParentPID(pid int) (int, error) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil || len(raw) > 65536 {
		return 0, ErrRuntimeLaunch
	}
	return task0StatusParentPID(raw)
}

func task0StatusParentPID(raw []byte) (int, error) {
	// Status is used rather than a process name parsed out of /proc/stat.
	var value int
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			if value != 0 {
				return 0, ErrRuntimeLaunch
			}
			var err error
			value, err = strconv.Atoi(strings.TrimSpace(line[5:]))
			if err != nil || value < 1 {
				return 0, ErrRuntimeLaunch
			}
		}
	}
	if value == 0 {
		return 0, ErrRuntimeLaunch
	}
	return value, nil
}

func launchTask0CAPreparation(ctx context.Context, self, binding *os.File, b task0ParentBinding, ca *task0ParentSystemCA, directory *task0CAParentDirectory, environment []string) (*freshPreparationProcess, string, *task0CAProof, error) {
	if ctx == nil || ctx.Err() != nil || self == nil || binding == nil || ca == nil || !ca.stableOriginal() || !directory.stableEmpty() ||
		!staticPreparationFile(self) || inputSHAFileMetadata(self) != b.ExecutableSHA || inputSHAFileMetadata(binding) != b.PreparationSHA {
		return nil, "", nil, ErrRuntimeLaunch
	}
	control, child, err := task0PrivateControlPair()
	if err != nil {
		return nil, "", nil, ErrRuntimeLaunch
	}
	defer child.Close()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3")
	cmd.Env = append([]string(nil), environment...)
	cmd.ExtraFiles = []*os.File{self, binding, child, ca.snapshot, ca.original, directory.rootFD}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000, Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000, Size: 1}}, GidMappingsEnableSetgroups: false, PidFD: &pidfd}
	if err = cmd.Start(); err != nil {
		if pidfd >= 0 {
			syscall.Close(pidfd)
		}
		control.Close()
		return nil, "", nil, ErrRuntimeLaunch
	}
	child.Close()
	cmd.Env = nil
	if pidfd >= 0 {
		syscall.Close(pidfd)
	}
	p := &freshPreparationProcess{command: cmd, control: control, exit: make(chan struct{})}
	go func() { p.waitErr = cmd.Wait(); close(p.exit) }()
	fail := func() (*freshPreparationProcess, string, *task0CAProof, error) {
		_ = p.retire()
		// Preserve this directly owned process even when admission fails.
		return p, "", nil, ErrRuntimeLaunch
	}
	if control.SetDeadline(time.Now().Add(60*time.Second)) != nil || verifiedPreparationChild(cmd, self) != nil {
		return fail()
	}
	var frame task0CAFrame
	if task0CAPacket(control, &frame, false) != nil || !task0SameJSON(frame, task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "READY", BindingSHA: b.PreparationSHA}) {
		return fail()
	}
	nonce, err := task0SetupNonce()
	if err != nil {
		return fail()
	}
	admission := task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "ADMIT", BindingSHA: b.PreparationSHA, Generation: ca.generation, Nonce: nonce}
	if task0CAPacket(control, &admission, true) != nil {
		return fail()
	}
	admission.Operation = "ADMITTED"
	if task0CAPacket(control, &frame, false) != nil || !task0SameJSON(frame, admission) || verifiedPreparationChild(cmd, self) != nil {
		return fail()
	}
	admission.Operation = "CONFIRMED"
	if task0CAPacket(control, &admission, true) != nil {
		return fail()
	}
	used := map[string]bool{nonce: true}
	expected := nonce
	for attempt := 0; attempt < 4; attempt++ {
		if task0CAPacket(control, &frame, false) != nil || !task0CAFrameValid(frame, "CA_READY", b.PreparationSHA, ca.generation, expected) || frame.Result != nil {
			return fail()
		}
		count, err := task0ParentCAReadback(p, self, b, ca, directory, frame.Proof)
		if err != nil {
			return fail()
		}
		next, err := task0SetupNonce()
		if err != nil || used[next] {
			return fail()
		}
		used[next] = true
		response := frame
		response.Nonce = next
		if count != frame.Proof.Threads {
			if attempt == 3 {
				return fail()
			}
			response.Operation = "CA_RESAMPLE"
			if task0CAPacket(control, &response, true) != nil {
				return fail()
			}
			expected = next
			continue
		}
		proof := *frame.Proof
		response.Operation = "CA_ADMIT"
		if task0CAPacket(control, &response, true) != nil {
			return fail()
		}
		response.Operation = "CA_ADMITTED"
		if task0CAPacket(control, &frame, false) != nil || !task0SameJSON(frame, response) {
			return fail()
		}
		if _, err := task0ParentCAReadback(p, self, b, ca, directory, &proof); err != nil {
			return fail()
		}
		response.Operation = "CA_CONFIRMED"
		if task0CAPacket(control, &response, true) != nil || control.SetDeadline(time.Time{}) != nil {
			return fail()
		}
		return p, next, &proof, nil
	}
	return fail()
}

type task0AcceptedPreparationRuntime struct {
	self, binding, source, original, mountpoint *os.File
	control                                     *net.UnixConn
	ca                                          *task0MaterializedCA
	setup                                       *task0SetupClient
	proof                                       task0CAProof
	admissionNonce                              string
	joined                                      bool
}

func receiveTask0CAPreparation(ctx context.Context, bindingSHA string) (*task0AcceptedPreparationRuntime, []byte, error) {
	if ctx == nil || ctx.Err() != nil || !digest(bindingSHA) || os.Getpid() != 1 || os.Geteuid() != 0 ||
		!namespaceIsNotHost("user") || !namespaceIsNotHost("pid") || !namespaceIsNotHost("mnt") {
		return nil, nil, ErrRuntimeLaunch
	}
	r := &task0AcceptedPreparationRuntime{}
	fail := func() (*task0AcceptedPreparationRuntime, []byte, error) {
		_ = r.retire()
		return nil, nil, ErrRuntimeLaunch
	}
	slots := []**os.File{&r.self, &r.binding, &r.source, &r.original, &r.mountpoint}
	for i, fd := range []int{3, 4, 6, 7, 8} {
		syscall.CloseOnExec(fd)
		f, err := frozenBorrowFile(fd)
		if err != nil {
			return fail()
		}
		*slots[i] = f
		syscall.Close(fd)
	}
	ss, err := task0CAFileState(r.self)
	actual, ae := os.Stat("/proc/self/exe")
	held, he := r.self.Stat()
	seals, _, se := syscall.Syscall(syscall.SYS_FCNTL, r.self.Fd(), 0x40a, 0)
	if err != nil || ae != nil || he != nil || !os.SameFile(actual, held) || ss.Uid != 0 || ss.Nlink != 0 || ss.Mode&07777 != 0500 ||
		!staticPreparationFile(r.self) || se != 0 || seals&15 != 15 {
		return fail()
	}
	bs, err := task0CAFileState(r.binding)
	seals, _, se = syscall.Syscall(syscall.SYS_FCNTL, r.binding.Fd(), 0x40a, 0)
	if err != nil || bs.Uid != 0 || bs.Nlink != 0 || bs.Mode&syscall.S_IFMT != syscall.S_IFREG || bs.Mode&07777 != 0400 || bs.Size < 1 || bs.Size > task0PreparationBindingMaxBytes || se != 0 || seals&15 != 15 {
		return fail()
	}
	raw, err := io.ReadAll(io.NewSectionReader(r.binding, 0, bs.Size))
	if err != nil || inputSHA(raw) != bindingSHA {
		clear(raw)
		return fail()
	}
	peer, pe := syscall.GetsockoptUcred(5, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	kind, ke := syscall.GetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if pe != nil || ke != nil || kind != syscall.SOCK_SEQPACKET || peer.Pid != 0 || peer.Uid != 0 || peer.Gid != 0 {
		clear(raw)
		return fail()
	}
	syscall.CloseOnExec(5)
	socket := os.NewFile(5, "own outside Parent control")
	c, err := net.FileConn(socket)
	socket.Close()
	if err != nil {
		clear(raw)
		return fail()
	}
	var ok bool
	r.control, ok = c.(*net.UnixConn)
	if !ok {
		c.Close()
		clear(raw)
		return fail()
	}
	if r.control.SetDeadline(time.Now().Add(60*time.Second)) != nil {
		clear(raw)
		return fail()
	}
	frame := task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "READY", BindingSHA: bindingSHA}
	if task0CAPacket(r.control, &frame, true) != nil {
		clear(raw)
		return fail()
	}
	if task0CAPacket(r.control, &frame, false) != nil || !task0CAFrameValid(frame, "ADMIT", bindingSHA, frame.Generation, frame.Nonce) || frame.Proof != nil || frame.Result != nil {
		clear(raw)
		return fail()
	}
	r.proof.Generation, r.admissionNonce = frame.Generation, frame.Nonce
	frame.Operation = "ADMITTED"
	if task0CAPacket(r.control, &frame, true) != nil {
		clear(raw)
		return fail()
	}
	frame.Operation = "CONFIRMED"
	var confirmed task0CAFrame
	if task0CAPacket(r.control, &confirmed, false) != nil || !task0SameJSON(frame, confirmed) || ctx.Err() != nil {
		clear(raw)
		return fail()
	}
	if syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, "") != nil || syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "") != nil {
		clear(raw)
		return fail()
	}
	return r, raw, nil
}

func (r *task0AcceptedPreparationRuntime) admitCA(a *acceptedTask0Preparation) error {
	if r == nil || a == nil || a.setup == nil || r.control == nil {
		return ErrRuntimeLaunch
	}
	ca, err := materializeTask0SystemCA(r.source, r.original, r.mountpoint)
	if err != nil {
		return ErrRuntimeLaunch
	}
	r.ca = ca
	setupImage, err := task0HoldPreparationHelper(a.binding.Setup)
	if err != nil {
		return ErrRuntimeLaunch
	}
	defer setupImage.Close()
	setupBinding, err := task0SealedBytes(a.binding.SetupBinding)
	if err != nil {
		return ErrRuntimeLaunch
	}
	defer setupBinding.Close()
	controlFD, err := r.control.SyscallConn()
	if err != nil {
		return ErrRuntimeLaunch
	}
	var controlIdentity task0SetupFDIdentity
	if controlFD.Control(func(fd uintptr) {
		var s syscall.Stat_t
		if syscall.Fstat(int(fd), &s) == nil {
			controlIdentity = task0SetupFDIdentity{s.Dev, s.Ino}
		}
	}) != nil || controlIdentity.Ino == 0 {
		return ErrRuntimeLaunch
	}
	forbidden := make([]task0SetupFDIdentity, 0, 6)
	for _, f := range []*os.File{r.self, r.binding, r.source, r.original, r.ca.materialized} {
		id, err := task0CAIdentity(f)
		if err != nil {
			return ErrRuntimeLaunch
		}
		forbidden = append(forbidden, id)
	}
	forbidden = append(forbidden, controlIdentity)
	r.setup, err = launchTask0Setup(setupImage, setupBinding, a.setup, r.proof.Generation, forbidden)
	if err != nil {
		return ErrRuntimeLaunch
	}
	if task0ConvergePrivileges(0) != nil {
		return ErrRuntimeLaunch
	}
	r.proof.CA = a.binding.SystemCA
	r.proof.BindingSHA = a.identity
	r.proof.ExecutableSHA = inputSHAFileMetadata(r.self)
	r.proof.SetupSHA = a.binding.Setup.SHA256
	r.proof.SetupBindingSHA = a.setup.identity
	r.proof.SetupAdmitted = true
	r.proof.Original, _ = task0CAIdentity(r.original)
	r.proof.Source, _ = task0CAIdentity(r.source)
	r.proof.Materialized, _ = task0CAIdentity(r.ca.materialized)
	r.proof.Bytes, r.proof.SHA256 = task0SystemCABytes, task0SystemCASHA
	nonce := r.admissionNonce
	used := map[string]bool{nonce: true}
	for attempt := 0; attempt < 4; attempt++ {
		if r.guard() != nil {
			return ErrRuntimeLaunch
		}
		threads, err := task0PrivilegeThreads("/proc/self", 0, 0, 0)
		if err != nil {
			return ErrRuntimeLaunch
		}
		r.proof.Threads = len(threads)
		ready := task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "CA_READY", BindingSHA: a.identity, Generation: r.proof.Generation, Nonce: nonce, Proof: &r.proof}
		if task0CAPacket(r.control, &ready, true) != nil {
			return ErrRuntimeLaunch
		}
		var response task0CAFrame
		if task0CAPacket(r.control, &response, false) != nil || !task0CAFrameValid(response, response.Operation, a.identity, r.proof.Generation, response.Nonce) ||
			(response.Operation != "CA_ADMIT" && response.Operation != "CA_RESAMPLE") || used[response.Nonce] || response.Result != nil || response.Proof == nil || *response.Proof != r.proof || r.guard() != nil {
			return ErrRuntimeLaunch
		}
		used[response.Nonce] = true
		if response.Operation == "CA_RESAMPLE" {
			if attempt == 3 {
				return ErrRuntimeLaunch
			}
			nonce = response.Nonce
			continue
		}
		r.admissionNonce = response.Nonce
		response.Operation = "CA_ADMITTED"
		if task0CAPacket(r.control, &response, true) != nil {
			return ErrRuntimeLaunch
		}
		response.Operation = "CA_CONFIRMED"
		var confirmation task0CAFrame
		if task0CAPacket(r.control, &confirmation, false) != nil || !task0SameJSON(confirmation, response) || r.guard() != nil || r.control.SetDeadline(time.Time{}) != nil {
			return ErrRuntimeLaunch
		}
		return nil
	}
	return ErrRuntimeLaunch
}

func (r *task0AcceptedPreparationRuntime) guard() error {
	if r == nil || r.ca == nil || r.setup == nil || !r.ca.valid("/proc/self") || inputSHAFileMetadata(r.binding) != r.proof.BindingSHA && r.proof.BindingSHA != "" {
		return ErrRuntimeLaunch
	}
	if _, err := task0PrivilegeThreads("/proc/self", 0, 0, 0); err != nil {
		return ErrRuntimeLaunch
	}
	return nil
}

func (r *task0AcceptedPreparationRuntime) joinSetup(result *task0PreparationResult) error {
	if r == nil || result == nil || r.setup == nil || r.setup.retire() != nil || !r.setup.shutdownOK {
		return ErrRuntimeLaunch
	}
	r.joined = true
	result.Schema = "aipt.private.b007-task0-preparation-result/v2"
	result.Generation, result.CAAdmissionNonce = r.proof.Generation, r.admissionNonce
	result.SetupCreated, result.SetupJoined, result.SetupWaited = r.setup.created, r.setup.joined, true
	return r.guard()
}

// PREP retains all accepted CA and binding inputs through the final report
// exchange. All role and SETUP joins precede closure; no unmount or capability
// restoration is attempted by this zero-capability process.
func (r *task0AcceptedPreparationRuntime) retire() error {
	if r == nil {
		return nil
	}
	var result error
	if r.setup != nil && !r.joined {
		if r.setup.retire() != nil {
			result = ErrRuntimeLaunch
		} else {
			r.joined = true
		}
	}
	if r.control != nil {
		if r.control.Close() != nil {
			result = ErrRuntimeLaunch
		}
	}
	if r.setup != nil && !r.setup.directJoinCompleted() {
		// Keep the full PREP owner (and all held inputs) reachable. Its fixed
		// entry waits for this cleanup before returning from a failed run.
		task0RetainInputsUntilDirectJoin(r.setup.process, func() { _ = r.closeHeldInputs() })
		return ErrRuntimeLaunch
	}
	if r.closeHeldInputs() != nil {
		result = ErrRuntimeLaunch
	}
	return result
}

func (r *task0AcceptedPreparationRuntime) closeHeldInputs() error {
	var result error
	if r.ca != nil {
		r.ca.closeTargets()
	}
	for _, f := range []*os.File{r.mountpoint, r.original, r.source, r.binding, r.self} {
		if f != nil {
			if f.Close() != nil {
				result = ErrRuntimeLaunch
			}
		}
	}
	return result
}
