package pilot

import (
	"io"
	"os"
	"syscall"
)

func task0SetupPipe(f *os.File, access int) bool {
	s, err := task0CAFileState(f)
	if err != nil || s.Mode&syscall.S_IFMT != syscall.S_IFIFO {
		return false
	}
	flags, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFL, 0)
	return e == 0 && flags&syscall.O_ACCMODE == uintptr(access)
}

func task0SetupChildControl(f *os.File) bool {
	s, err := task0CAFileState(f)
	if err != nil || s.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return false
	}
	kind, err := syscall.GetsockoptInt(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_TYPE)
	peer, pe := syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	return err == nil && pe == nil && kind == syscall.SOCK_SEQPACKET && peer.Pid == 0 && peer.Uid == 0 && peer.Gid == 0
}

func task0SetupSealedInput(f *os.File, hash string, size int64, executable bool) bool {
	s, err := task0CAFileState(f)
	mode := uint32(0400)
	if executable {
		mode = 0500
	}
	if err != nil || s.Uid != 0 || s.Nlink != 0 || s.Mode&syscall.S_IFMT != syscall.S_IFREG || s.Mode&07777 != mode || s.Size != size {
		return false
	}
	held, err := frozenSealedFile(int(f.Fd()), hash, size)
	if err != nil {
		return false
	}
	held.Close()
	return true
}

func task0SetupCredential(f *os.File) (string, error) {
	s, err := task0CAFileState(f)
	if err != nil || s.Uid != 0 || s.Nlink != 0 || s.Mode&syscall.S_IFMT != syscall.S_IFREG || s.Mode&07777 != 0400 || s.Size < 1 || s.Size > 4096 {
		return "", ErrRuntimeLaunch
	}
	seals, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), 0x40a, 0)
	if e != 0 || seals&0xf != 0xf {
		return "", ErrRuntimeLaunch
	}
	raw, err := io.ReadAll(io.NewSectionReader(f, 0, 4097))
	defer clear(raw)
	if err != nil || int64(len(raw)) != s.Size || !task0PreparationCredentialValid(string(raw)) {
		return "", ErrRuntimeLaunch
	}
	return string(raw), nil
}

func task0SetupInputs(a *acceptedTask0Setup, role task0SetupRole, files []*os.File, forbidden []task0SetupFDIdentity) (string, error) {
	want := 5
	if role.Role == "GAME" {
		want = 4
	} else if role.Role == "LOCAL" {
		want = 11
	}
	if a == nil || a.roles[role.Role] != role || len(files) != want || len(forbidden) != 6 {
		return "", ErrRuntimeLaunch
	}
	for _, f := range files {
		s, err := task0CAFileState(f)
		if err != nil {
			return "", ErrRuntimeLaunch
		}
		for _, no := range forbidden {
			if no.Ino == 0 || (s.Dev == no.Dev && s.Ino == no.Ino) {
				return "", ErrRuntimeLaunch
			}
		}
	}
	if !task0SetupSealedInput(files[0], role.ProgramSHA, role.ProgramBytes, true) || !staticPreparationFilePrefix(files[0]) || !task0SetupChildControl(files[1]) {
		return "", ErrRuntimeLaunch
	}
	c, err := OpenEmbeddedCodeCapsule(files[0], role.ManifestSHA)
	if err != nil {
		return "", ErrRuntimeLaunch
	}
	defer c.Close()
	if role.Role == "LOCAL" {
		policy, err := frozenCapsulePolicy(c)
		if err != nil || !task0SameJSON(policy, a.policy) || !task0SameJSON(c.manifest, a.manifest) ||
			!task0SetupSealedInput(files[3], policy.GGUFSHA256, policy.GGUFBytes, false) || !task0SetupPipe(files[7], syscall.O_RDONLY) || !task0SetupPipe(files[8], syscall.O_WRONLY) {
			return "", ErrRuntimeLaunch
		}
		specs := map[string]RuntimeCodeFile{}
		for _, f := range c.manifest.Files {
			specs[f.AssetID] = f
		}
		for index, id := range map[int]string{2: policy.NativeAsset, 4: policy.NodeAsset, 5: policy.WorkerAsset, 6: policy.RouteAsset, 9: policy.NodeAsset, 10: policy.BundleAsset} {
			spec, ok := specs[id]
			if !ok || !task0SetupSealedInput(files[index], spec.SHA256, spec.Bytes, spec.Executable) {
				return "", ErrRuntimeLaunch
			}
		}
		return "", nil
	}
	if !task0SetupPipe(files[2], syscall.O_RDONLY) || !task0SetupPipe(files[3], syscall.O_WRONLY) {
		return "", ErrRuntimeLaunch
	}
	if role.Role == "GAME" {
		if validateTask0Capsule(c) != nil {
			return "", ErrRuntimeLaunch
		}
		return "", nil
	}
	p, err := frozenTask0RemotePolicy(c)
	entry, ok := a.dispatch.profiles[role.ProfileBinding]
	if err != nil || !ok || !task0SameJSON(p.Profile, entry.Profile) || !task0SameJSON(p.Sampling, entry.Sampling) {
		return "", ErrRuntimeLaunch
	}
	return task0SetupCredential(files[4])
}
