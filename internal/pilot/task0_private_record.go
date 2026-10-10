package pilot

import (
	"os"
	"syscall"
)

// Private execution records are exclusive, synced and retained even on a
// partial write. A failed record cannot be replaced with a success receipt.
func persistTask0PrivateRecord(budget *GlobalBudget, name string, raw []byte) error {
	if budget == nil || budget.checkRoot() != nil || !runPattern.MatchString(name) || len(raw) < 1 || len(raw) > 1<<20 {
		return ErrTask0
	}
	fd, err := syscall.Openat(int(budget.root.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return ErrTask0
	}
	f := os.NewFile(uintptr(fd), "held private Task0 record")
	defer f.Close()
	if n, err := f.Write(raw); err != nil || n != len(raw) || f.Chmod(0400) != nil || f.Sync() != nil || budget.root.Sync() != nil || budget.checkRoot() != nil {
		return ErrTask0
	}
	return nil
}
