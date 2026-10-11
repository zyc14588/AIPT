package pilot

import (
	"encoding/json"
	"net"
	"os"
	"syscall"
)

// SCM_RIGHTS transfers only the role's fixed slots. Truncated, unsolicited or
// duplicate control messages fail closed and every received descriptor closes
// on failure. A pidfd reply is authenticated by the admitted fixed SETUP.
func task0SetupWrite(c *net.UnixConn, frame task0SetupFrame, files []*os.File) error {
	if c == nil || len(files) > 11 {
		return ErrRuntimeLaunch
	}
	raw, err := json.Marshal(frame)
	if err != nil || len(raw) > 2048 {
		return ErrRuntimeLaunch
	}
	fds := make([]int, 0, len(files))
	for _, f := range files {
		if f == nil {
			return ErrRuntimeLaunch
		}
		fds = append(fds, int(f.Fd()))
	}
	var rights []byte
	if len(fds) > 0 {
		rights = syscall.UnixRights(fds...)
	}
	n, oob, err := c.WriteMsgUnix(raw, rights, nil)
	if err != nil || n != len(raw) || oob != len(rights) {
		return ErrRuntimeLaunch
	}
	return nil
}

func task0SetupRead(c *net.UnixConn) (task0SetupFrame, []*os.File, error) {
	var frame task0SetupFrame
	if c == nil {
		return frame, nil, ErrRuntimeLaunch
	}
	var raw [2049]byte
	control := make([]byte, syscall.CmsgSpace(11*4))
	n, size, flags, _, readErr := c.ReadMsgUnix(raw[:], control)
	files := []*os.File{}
	fail := func() (task0SetupFrame, []*os.File, error) {
		for _, f := range files {
			f.Close()
		}
		return task0SetupFrame{}, nil, ErrRuntimeLaunch
	}
	messages, parseErr := syscall.ParseSocketControlMessage(control[:size])
	valid := parseErr == nil && len(messages) <= 1
	for _, message := range messages {
		fds, err := syscall.ParseUnixRights(&message)
		if err != nil {
			valid = false
			continue
		}
		for _, fd := range fds {
			syscall.CloseOnExec(fd)
			files = append(files, os.NewFile(uintptr(fd), "fixed SETUP received role descriptor"))
		}
	}
	if readErr != nil || parseErr != nil || !valid || len(files) > 11 || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || n < 1 || n > 2048 || decodeFrozenJSON(raw[:n], 2048, &frame) != nil {
		return fail()
	}
	return frame, files, nil
}
