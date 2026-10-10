package pilot

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// A generation handle and a held executable inode stay bound for the entire
// request. Numeric PIDs, addresses and a readiness response grant no authority.
type frozenOwnedProcess struct {
	command    *exec.Cmd
	executable os.FileInfo
	exit       chan struct{}
	mu         sync.Mutex
	waitError  error
}

func startFrozenProcess(command *exec.Cmd, executable *os.File) (*frozenOwnedProcess, error) {
	if command == nil || executable == nil || os.Getpid() != 1 || verifyZeroCapabilityThreads(1) != nil {
		return nil, ErrRuntimeLaunch
	}
	info, e := executable.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return nil, ErrRuntimeLaunch
	}
	pidfd := -1
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, PidFD: &pidfd}
	if e = command.Start(); e != nil {
		if pidfd >= 0 {
			_ = syscall.Close(pidfd)
		}
		return nil, ErrRuntimeLaunch
	}
	p := &frozenOwnedProcess{command: command, executable: info, exit: make(chan struct{})}
	go func() { e := command.Wait(); p.mu.Lock(); p.waitError = e; p.mu.Unlock(); close(p.exit) }()
	held := false
	e = command.Process.WithHandle(func(uintptr) { held = true })
	if pidfd >= 0 {
		_ = syscall.Close(pidfd)
	}
	if e != nil || !held || p.check() != nil {
		_ = command.Process.Kill()
		select {
		case <-p.exit:
		case <-time.After(time.Second):
		}
		return nil, ErrRuntimeLaunch
	}
	return p, nil
}

func (p *frozenOwnedProcess) check() error {
	if p == nil || p.command == nil || p.command.Process == nil {
		return ErrRuntimeLaunch
	}
	select {
	case <-p.exit:
		return ErrRuntimeLaunch
	default:
	}
	if p.command.Process.Signal(syscall.Signal(0)) != nil {
		return ErrRuntimeLaunch
	}
	info, e := os.Stat("/proc/" + strconv.Itoa(p.command.Process.Pid) + "/exe")
	if e != nil || !os.SameFile(info, p.executable) || verifyZeroCapabilityThreads(p.command.Process.Pid) != nil {
		return ErrRuntimeLaunch
	}
	return nil
}

func (p *frozenOwnedProcess) stop(timeout time.Duration) error {
	if p == nil {
		return nil
	}
	if timeout <= 0 || timeout > 30*time.Second {
		return ErrRuntimeLaunch
	}
	select {
	case <-p.exit:
		return nil
	default:
	}
	// Go retains the pidfd: these signals cannot reach a reused numeric PID.
	_ = p.command.Process.Signal(syscall.SIGTERM)
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-p.exit:
		return nil
	case <-t.C:
	}
	_ = p.command.Process.Kill()
	select {
	case <-p.exit:
		return nil
	case <-time.After(time.Second):
		return ErrRuntimeLaunch
	}
}

type frozenTCPSocket struct {
	table, local, remote, state, inode string
	localPort, remotePort              int
}

func parseFrozenTCPTable(raw []byte, table string) ([]frozenTCPSocket, error) {
	if len(raw) == 0 || len(raw) > 2<<20 || (table != "tcp" && table != "tcp6") {
		return nil, ErrRuntimeLaunch
	}
	var out []frozenTCPSocket
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 10 {
			return nil, ErrRuntimeLaunch
		}
		la, lp, ok := strings.Cut(f[1], ":")
		ra, rp, rok := strings.Cut(f[2], ":")
		l, le := strconv.ParseUint(lp, 16, 16)
		r, re := strconv.ParseUint(rp, 16, 16)
		if !ok || !rok || le != nil || re != nil || len(f[3]) != 2 || len(la) != (map[string]int{"tcp": 8, "tcp6": 32})[table] || len(ra) != len(la) {
			return nil, ErrRuntimeLaunch
		}
		if _, e := strconv.ParseUint(f[9], 10, 64); e != nil {
			return nil, ErrRuntimeLaunch
		}
		out = append(out, frozenTCPSocket{table: table, local: la, remote: ra, state: f[3], inode: f[9], localPort: int(l), remotePort: int(r)})
		if len(out) > 4096 {
			return nil, ErrRuntimeLaunch
		}
	}
	return out, nil
}

func frozenTCPSockets() ([]frozenTCPSocket, error) {
	var out []frozenTCPSocket
	for _, table := range []string{"tcp", "tcp6"} {
		raw, e := os.ReadFile("/proc/net/" + table)
		if e != nil {
			return nil, ErrRuntimeLaunch
		}
		part, e := parseFrozenTCPTable(raw, table)
		if e != nil {
			return nil, e
		}
		out = append(out, part...)
	}
	return out, nil
}

// The caller is namespace init with its own read-only procfs. We scan every
// visible process, including detached descendants outside the original group.
func frozenNamespacePIDs() ([]int, error) {
	if os.Getpid() != 1 {
		return nil, ErrRuntimeLaunch
	}
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return nil, ErrRuntimeLaunch
	}
	var out []int
	for _, entry := range entries {
		n, e := strconv.Atoi(entry.Name())
		if e == nil && n > 0 {
			out = append(out, n)
		}
	}
	if len(out) == 0 || len(out) > 256 {
		return nil, ErrRuntimeLaunch
	}
	return out, nil
}

func frozenSocketOwners(inode string) ([]int, error) {
	pids, e := frozenNamespacePIDs()
	if e != nil || inode == "0" {
		return nil, ErrRuntimeLaunch
	}
	var out []int
	for _, pid := range pids {
		base := "/proc/" + strconv.Itoa(pid) + "/fd"
		files, e := os.ReadDir(base)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || len(files) > 4096 {
			return nil, ErrRuntimeLaunch
		}
		owner := false
		for _, file := range files {
			target, e := os.Readlink(filepath.Join(base, file.Name()))
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return nil, ErrRuntimeLaunch
			}
			if target == "socket:["+inode+"]" {
				owner = true
			}
		}
		if owner {
			out = append(out, pid)
		}
	}
	return out, nil
}

func (p *frozenOwnedProcess) listener(port int) (string, error) {
	if p.check() != nil || port < 1 || port > 65535 {
		return "", ErrRuntimeLaunch
	}
	all, e := frozenTCPSockets()
	if e != nil {
		return "", e
	}
	var match *frozenTCPSocket
	for i := range all {
		v := &all[i]
		if v.state == "0A" && v.localPort == port {
			if match != nil {
				return "", ErrRuntimeLaunch
			}
			match = v
		}
	}
	if match == nil || match.table != "tcp" || match.local != "0100007F" || match.inode == "0" {
		return "", ErrRuntimeLaunch
	}
	owners, e := frozenSocketOwners(match.inode)
	if e != nil || len(owners) != 1 || owners[0] != p.command.Process.Pid || p.check() != nil {
		return "", ErrRuntimeLaunch
	}
	return match.inode, nil
}

func (p *frozenOwnedProcess) accepted(ctx context.Context, connection net.Conn) error {
	l, ok := connection.LocalAddr().(*net.TCPAddr)
	r, rok := connection.RemoteAddr().(*net.TCPAddr)
	if !ok || !rok || l.IP.String() != "127.0.0.1" || r.IP.String() != "127.0.0.1" {
		return ErrRuntimeLaunch
	}
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if p.check() != nil {
			return ErrRuntimeLaunch
		}
		all, e := frozenTCPSockets()
		if e != nil {
			return e
		}
		var match *frozenTCPSocket
		for i := range all {
			v := &all[i]
			if v.table == "tcp" && v.state == "01" && v.local == "0100007F" && v.remote == "0100007F" && v.localPort == r.Port && v.remotePort == l.Port {
				if match != nil {
					return ErrRuntimeLaunch
				}
				match = v
			}
		}
		if match != nil && match.inode != "0" {
			owners, e := frozenSocketOwners(match.inode)
			if e != nil || len(owners) != 1 || owners[0] != p.command.Process.Pid || p.check() != nil {
				return ErrRuntimeLaunch
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ErrRuntimeLaunch
		case <-timer.C:
			return ErrRuntimeLaunch
		case <-ticker.C:
		}
	}
}

// The HTTP transport receives a connection only after the native process owns
// its established server-side socket. Port replacement cannot see HTTP bytes.
func (p *frozenOwnedProcess) guardedTransport(port int) *http.Transport {
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	return &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 16384, ResponseHeaderTimeout: 30 * time.Second, DialContext: func(ctx context.Context, network, requested string) (net.Conn, error) {
		if (network != "tcp" && network != "tcp4") || requested != address {
			return nil, ErrRuntimeLaunch
		}
		before, e := p.listener(port)
		if e != nil {
			return nil, e
		}
		connection, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", address)
		if e != nil {
			return nil, e
		}
		after, e := p.listener(port)
		if e != nil || before != after || p.accepted(ctx, connection) != nil {
			_ = connection.Close()
			return nil, ErrRuntimeLaunch
		}
		return connection, nil
	}}
}
