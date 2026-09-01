package modelgateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

const (
	memfdCloseOnExec  = 0x0001
	memfdAllowSealing = 0x0002
	fcntlAddSeals     = 0x0409
	sealSeal          = 0x0001
	sealShrink        = 0x0002
	sealGrow          = 0x0004
	sealWrite         = 0x0008
)

// verifiedAsset is the file object that crossed the digest boundary.  Its
// descriptor is retained for the lifetime of the governed runtime and is the
// object inherited by children. The object is an anonymous, write-sealed
// memfd snapshot: neither pathname replacement nor an in-place write to the
// registered inode can change the bytes executed or loaded after validation.
type verifiedAsset struct {
	mu         sync.Mutex
	file       *os.File
	info       os.FileInfo
	digest     string
	executable bool
	closed     bool
}

func openVerifiedAsset(path, expected string, executable bool) (*verifiedAsset, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open(canonical, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	source := os.NewFile(uintptr(fd), "aipt-registration-source")
	if source == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("registered asset descriptor unavailable")
	}
	failSource := func(cause error) (*verifiedAsset, error) {
		_ = source.Close()
		return nil, cause
	}
	sourceInfo, err := source.Stat()
	if err != nil || !sourceInfo.Mode().IsRegular() {
		return failSource(errors.New("registered asset is not a regular file"))
	}
	if executable && sourceInfo.Mode().Perm()&0o111 == 0 {
		return failSource(errors.New("registered executable is not executable"))
	}
	file, err := sealedMemfdSnapshot(source, executable)
	_ = source.Close()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*verifiedAsset, error) {
		_ = file.Close()
		return nil, cause
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fail(errors.New("sealed asset snapshot is not a regular file"))
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fail(err)
	}
	observed := hex.EncodeToString(hash.Sum(nil))
	if observed != expected {
		return fail(errors.New("registered asset digest mismatch"))
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	return &verifiedAsset{file: file, info: info, digest: observed, executable: executable}, nil
}

func memfdCreateSyscall() (uintptr, error) {
	// The runtime is intentionally Linux-specific (/proc FDs, pidfds, and
	// network namespaces). Keep the raw syscall table explicit so this security
	// boundary does not add a new third-party dependency.
	switch runtime.GOARCH {
	case "amd64":
		return 319, nil
	case "386":
		return 356, nil
	case "arm64", "riscv64", "loong64":
		return 279, nil
	case "arm":
		return 385, nil
	case "ppc64", "ppc64le":
		return 360, nil
	case "s390x":
		return 350, nil
	case "mips64", "mips64le":
		return 5314, nil
	default:
		return 0, errors.New("sealed asset snapshots are unsupported on this architecture")
	}
}

func sealedMemfdSnapshot(source *os.File, executable bool) (*os.File, error) {
	if source == nil {
		return nil, errors.New("asset source unavailable")
	}
	number, err := memfdCreateSyscall()
	if err != nil {
		return nil, err
	}
	name, err := syscall.BytePtrFromString("aipt-verified-asset")
	if err != nil {
		return nil, err
	}
	fd, _, errno := syscall.Syscall(number, uintptr(unsafe.Pointer(name)), memfdCloseOnExec|memfdAllowSealing, 0)
	if errno != 0 {
		return nil, fmt.Errorf("create sealed asset snapshot: %w", errno)
	}
	file := os.NewFile(fd, "aipt-sealed-asset")
	if file == nil {
		_ = syscall.Close(int(fd))
		return nil, errors.New("sealed asset descriptor unavailable")
	}
	fail := func(cause error) (*os.File, error) {
		_ = file.Close()
		return nil, cause
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	if _, err := io.Copy(file, source); err != nil {
		return fail(err)
	}
	mode := os.FileMode(0o400)
	if executable {
		mode = 0o500
	}
	if err := file.Chmod(mode); err != nil {
		return fail(err)
	}
	seals := uintptr(sealSeal | sealShrink | sealGrow | sealWrite)
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), fcntlAddSeals, seals); errno != 0 {
		return fail(fmt.Errorf("seal asset snapshot: %w", errno))
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	return file, nil
}

func (asset *verifiedAsset) readAll(limit int64) ([]byte, error) {
	if asset == nil || limit < 1 {
		return nil, errors.New("verified asset unavailable")
	}
	asset.mu.Lock()
	defer asset.mu.Unlock()
	if asset.closed || asset.file == nil || asset.info == nil || asset.info.Size() < 0 || asset.info.Size() > limit {
		return nil, errors.New("verified asset exceeds the read bound")
	}
	return io.ReadAll(io.NewSectionReader(asset.file, 0, asset.info.Size()))
}

func (asset *verifiedAsset) descriptor() (*os.File, error) {
	if asset == nil {
		return nil, errors.New("verified asset unavailable")
	}
	asset.mu.Lock()
	defer asset.mu.Unlock()
	if asset.closed || asset.file == nil {
		return nil, errors.New("verified asset retired")
	}
	return asset.file, nil
}

func (asset *verifiedAsset) close() error {
	if asset == nil {
		return nil
	}
	asset.mu.Lock()
	defer asset.mu.Unlock()
	if asset.closed {
		return nil
	}
	asset.closed = true
	if asset.file == nil {
		return nil
	}
	err := asset.file.Close()
	asset.file = nil
	return err
}

func inheritedAssetPath(extraFileIndex int) string {
	return "/proc/self/fd/" + strconv.Itoa(3+extraFileIndex)
}

func verifyProcessExecutableAsset(pid int, expected *verifiedAsset) error {
	if pid <= 1 || expected == nil || expected.info == nil {
		return errors.New("managed executable identity unavailable")
	}
	observedInfo, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return err
	}
	if !os.SameFile(observedInfo, expected.info) {
		return errors.New("managed process executable differs from verified file object")
	}
	return nil
}
