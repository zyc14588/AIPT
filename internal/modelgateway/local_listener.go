package modelgateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var errManagedListenerNotReady = errors.New("managed listener not ready")

type listenerOwnershipError struct{ reason string }

func (e *listenerOwnershipError) Error() string {
	if e == nil || e.reason == "" {
		return "managed listener ownership mismatch"
	}
	return "managed listener ownership mismatch: " + e.reason
}

func ownershipMismatch(reason string) error { return &listenerOwnershipError{reason: reason} }

type managedListenerIdentity struct {
	inode string
}

// managedProcessIdentity holds a kernel pidfd for the exact process generation
// launched by AIPT. A numeric PID alone is insufficient: Linux may reuse it
// after the child is reaped, while the pidfd remains tied to the original task.
type managedProcessIdentity struct {
	pid     int
	process *os.Process
	mu      sync.Mutex
	closed  bool
}

func bindManagedProcessIdentity(process *os.Process, pidfd int) (*managedProcessIdentity, error) {
	if process == nil || process.Pid <= 0 || pidfd < 0 {
		if pidfd >= 0 {
			_ = syscall.Close(pidfd)
		}
		return nil, ownershipMismatch("invalid launched process identity")
	}
	retainedHandle := false
	if err := process.WithHandle(func(_ uintptr) { retainedHandle = true }); err != nil || !retainedHandle {
		_ = syscall.Close(pidfd)
		return nil, ownershipMismatch("kernel process-generation handle was not retained")
	}
	// os.StartProcess duplicates an explicitly requested SysProcAttr.PidFD into
	// os.Process before returning. WithHandle above proves that duplication did
	// not silently fall back to a numeric PID. Close AIPT's extra descriptor;
	// Process.Signal below now necessarily uses the retained generation handle.
	_ = syscall.Close(pidfd)
	identity := &managedProcessIdentity{pid: process.Pid, process: process}
	if err := identity.requireAlive(); err != nil {
		identity.close()
		return nil, err
	}
	return identity, nil
}

func (identity *managedProcessIdentity) requireAlive() error {
	if identity == nil || identity.pid <= 0 || identity.process == nil {
		return ownershipMismatch("launched process generation unavailable")
	}
	identity.mu.Lock()
	defer identity.mu.Unlock()
	if identity.closed {
		return ownershipMismatch("launched process generation retired")
	}
	if err := identity.process.Signal(syscall.Signal(0)); err != nil {
		return ownershipMismatch("launched process generation exited")
	}
	return nil
}

func (identity *managedProcessIdentity) close() {
	if identity == nil {
		return
	}
	identity.mu.Lock()
	defer identity.mu.Unlock()
	if identity.closed {
		return
	}
	identity.closed = true
}

type procTCPListener struct {
	table   string
	address string
	port    int
	inode   string
}

type procTCPConnection struct {
	table         string
	localAddress  string
	localPort     int
	remoteAddress string
	remotePort    int
	state         string
	inode         string
}

// verifyManagedListenerOwnership closes the bind/readiness TOCTOU when the
// managed binary cannot inherit AIPT's pre-bound socket. The exact selected
// tcp4 listener must be the launched PID's only TCP listener, the selected port
// must have no competing listener entry, and no process in the launched
// process group may share the socket inode. Callers attest the same inode both
// before and after guarded HTTP identity probes before exposing the endpoint.
func verifyManagedListenerOwnership(process *managedProcessIdentity, selectedPort int) (managedListenerIdentity, error) {
	if process == nil || selectedPort < 1 || selectedPort > 65535 {
		return managedListenerIdentity{}, ownershipMismatch("invalid process or port identity")
	}
	if err := process.requireAlive(); err != nil {
		return managedListenerIdentity{}, err
	}
	pid := process.pid
	processSockets, err := processSocketInodes(pid)
	if err != nil {
		return managedListenerIdentity{}, ownershipMismatch("launched process sockets unavailable")
	}
	listeners, err := procTCPListeners()
	if err != nil {
		return managedListenerIdentity{}, ownershipMismatch("kernel listener table unavailable")
	}
	selected := make([]procTCPListener, 0, 1)
	owned := make([]procTCPListener, 0, 1)
	for _, listener := range listeners {
		if listener.port == selectedPort {
			selected = append(selected, listener)
		}
		if processSockets[listener.inode] {
			owned = append(owned, listener)
		}
	}
	if len(selected) == 0 && len(owned) == 0 {
		return managedListenerIdentity{}, errManagedListenerNotReady
	}
	if len(selected) != 1 || len(owned) != 1 {
		return managedListenerIdentity{}, ownershipMismatch(fmt.Sprintf("selected=%d owned=%d", len(selected), len(owned)))
	}
	want := selected[0]
	if want.table != "tcp" || want.address != "0100007F" ||
		owned[0].inode != want.inode || !processSockets[want.inode] {
		return managedListenerIdentity{}, ownershipMismatch("selected listener address or owning descriptor differs")
	}
	owners, err := managedProcessGroupSocketOwners(pid, want.inode)
	if err != nil || len(owners) != 1 || owners[0] != pid {
		return managedListenerIdentity{}, ownershipMismatch(fmt.Sprintf("owner scan error=%v owners=%v expected=%d", err, owners, pid))
	}
	if err := process.requireAlive(); err != nil {
		return managedListenerIdentity{}, err
	}
	return managedListenerIdentity{inode: want.inode}, nil
}

func procTCPListeners() ([]procTCPListener, error) {
	var result []procTCPListener
	for _, table := range []string{"tcp", "tcp6"} {
		raw, err := os.ReadFile(filepath.Join("/proc/net", table))
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(raw), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			address, portHex, found := strings.Cut(fields[1], ":")
			if !found {
				return nil, errors.New("malformed proc TCP listener")
			}
			port, err := strconv.ParseUint(portHex, 16, 16)
			if err != nil || fields[9] == "" || fields[9] == "0" {
				return nil, errors.New("malformed proc TCP listener identity")
			}
			result = append(result, procTCPListener{
				table: table, address: address, port: int(port), inode: fields[9],
			})
		}
	}
	return result, nil
}

func procTCPConnections() ([]procTCPConnection, error) {
	var result []procTCPConnection
	for _, table := range []string{"tcp", "tcp6"} {
		raw, err := os.ReadFile(filepath.Join("/proc/net", table))
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(raw), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			localAddress, localPortHex, localOK := strings.Cut(fields[1], ":")
			remoteAddress, remotePortHex, remoteOK := strings.Cut(fields[2], ":")
			localPort, localErr := strconv.ParseUint(localPortHex, 16, 16)
			remotePort, remoteErr := strconv.ParseUint(remotePortHex, 16, 16)
			if !localOK || !remoteOK || localErr != nil || remoteErr != nil || fields[9] == "" {
				return nil, errors.New("malformed proc TCP connection identity")
			}
			result = append(result, procTCPConnection{
				table: table, localAddress: localAddress, localPort: int(localPort),
				remoteAddress: remoteAddress, remotePort: int(remotePort), state: fields[3], inode: fields[9],
			})
		}
	}
	return result, nil
}

// dialManagedListener does not release HTTP bytes until the established
// server-side socket is proven to belong to the exact launched PID. The
// stable AIPT-owned proxy uses this dialer for every new upstream connection,
// so a post-start crash and port rebind can complete a TCP handshake but can
// never receive a request or governed context.
func dialManagedListener(ctx context.Context, process *managedProcessIdentity, selectedPort int) (net.Conn, error) {
	before, err := verifyManagedListenerOwnership(process, selectedPort)
	if err != nil {
		return nil, err
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(selectedPort)))
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (net.Conn, error) {
		_ = connection.Close()
		return nil, cause
	}
	after, err := verifyManagedListenerOwnership(process, selectedPort)
	if err != nil || before.inode != after.inode {
		return fail(ownershipMismatch("listener changed while establishing guarded connection"))
	}
	if err := verifyManagedAcceptedConnection(ctx, process, connection); err != nil {
		return fail(err)
	}
	return connection, nil
}

func verifyManagedAcceptedConnection(ctx context.Context, process *managedProcessIdentity, connection net.Conn) error {
	if err := process.requireAlive(); err != nil {
		return err
	}
	pid := process.pid
	local, localOK := connection.LocalAddr().(*net.TCPAddr)
	remote, remoteOK := connection.RemoteAddr().(*net.TCPAddr)
	if !localOK || !remoteOK || local.IP.String() != "127.0.0.1" || remote.IP.String() != "127.0.0.1" {
		return ownershipMismatch("guarded connection is not exact IPv4 loopback")
	}
	deadline := time.NewTimer(500 * time.Millisecond)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		entries, err := procTCPConnections()
		if err != nil {
			return ownershipMismatch("kernel connection table unavailable")
		}
		var match *procTCPConnection
		for index := range entries {
			entry := &entries[index]
			if entry.table != "tcp" || entry.state != "01" ||
				entry.localAddress != "0100007F" || entry.remoteAddress != "0100007F" ||
				entry.localPort != remote.Port || entry.remotePort != local.Port {
				continue
			}
			if match != nil {
				return ownershipMismatch("ambiguous accepted connection identity")
			}
			match = entry
		}
		if match != nil && match.inode != "0" {
			sockets, err := processSocketInodes(pid)
			if err != nil || !sockets[match.inode] {
				return ownershipMismatch("accepted connection belongs to another process")
			}
			owners, err := managedProcessGroupSocketOwners(pid, match.inode)
			if err != nil || len(owners) != 1 || owners[0] != pid {
				return ownershipMismatch("accepted connection ownership is ambiguous")
			}
			if err := process.requireAlive(); err != nil {
				return err
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ownershipMismatch("accepted connection ownership was not established")
		case <-deadline.C:
			return ownershipMismatch("accepted connection ownership was not established")
		case <-ticker.C:
		}
	}
}

func processSocketInodes(pid int) (map[string]bool, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return nil, err
	}
	result := make(map[string]bool)
	for _, entry := range entries {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if inode, ok := socketInode(target); ok {
			result[inode] = true
		}
	}
	return result, nil
}

func socketInode(target string) (string, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return "", false
	}
	inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
	if inode == "" {
		return "", false
	}
	return inode, true
}

func processRealUID(pid int) (string, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[1] == "" {
			break
		}
		return fields[1], nil
	}
	return "", errors.New("process UID unavailable")
}

func processGroupID(pid int) (int, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// The comm field is parenthesized and may contain spaces or parentheses;
	// the final ')' is the only stable boundary before state, ppid, and pgrp.
	closeIndex := strings.LastIndexByte(string(raw), ')')
	if closeIndex < 0 || closeIndex+1 >= len(raw) {
		return 0, errors.New("process group identity unavailable")
	}
	fields := strings.Fields(string(raw[closeIndex+1:]))
	if len(fields) < 3 {
		return 0, errors.New("process group identity unavailable")
	}
	group, err := strconv.Atoi(fields[2])
	if err != nil || group <= 0 {
		return 0, errors.New("process group identity unavailable")
	}
	return group, nil
}

func managedProcessGroupSocketOwners(expectedPID int, inode string) ([]int, error) {
	wantUID, err := processRealUID(expectedPID)
	if err != nil {
		return nil, err
	}
	wantGroup, err := processGroupID(expectedPID)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var owners []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		uid, err := processRealUID(pid)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if uid != wantUID {
			continue
		}
		group, err := processGroupID(pid)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if group != wantGroup {
			continue
		}
		sockets, err := processSocketInodes(pid)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			// An uninspectable member of the managed process group could hold an
			// inherited descriptor. Exclusivity cannot be proved, so fail closed.
			return nil, err
		}
		if sockets[inode] {
			owners = append(owners, pid)
		}
	}
	return owners, nil
}
