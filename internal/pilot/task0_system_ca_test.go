package pilot

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestTask0SealedCASourceAcceptsAnonymousMemfdMetadataOnly(t *testing.T) {
	// Deliberately not a certificate. This regression executes memfd_create,
	// fstat and seal readback, while the full fixed-CA byte check still rejects.
	body := make([]byte, task0SystemCABytes)
	f, err := task0SealedBytes(body)
	if err != nil {
		t.Fatal("memfd source creation", err)
	}
	defer f.Close()
	s, err := task0CAFileState(f)
	if err != nil || s.Nlink != 0 || !task0SealedCAMetadata(f, uint32(os.Geteuid())) || task0SealedCAValid(f, uint32(os.Geteuid())) {
		t.Fatal("anonymous metadata rejected or non-CA bytes accepted")
	}
	_, writeErr := f.WriteAt([]byte{1}, 0)
	if task0SealedCAMetadata(f, uint32(os.Geteuid())+1) || writeErr == nil || f.Truncate(task0SystemCABytes-1) == nil {
		t.Fatal("wrong owner or write/size mutation accepted")
	}
	named := filepath.Join(t.TempDir(), "NON-CANON-single-link-regular-control")
	if os.WriteFile(named, body, 0400) != nil || os.Chmod(named, 0400) != nil {
		t.Fatal("regular negative control")
	}
	regular, err := os.Open(named)
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if task0SealedCAMetadata(regular, uint32(os.Geteuid())) {
		t.Fatal("named readonly regular file substituted for sealed memfd")
	}
}

func TestTask0CAContractsRejectSourceAndSetupPolicySubstitution(t *testing.T) {
	good := task0SystemCABinding{task0SystemCAPolicy, task0Q013AuthoritySHA, task0SetupPolicy, task0Q014AuthoritySHA}
	if !task0SystemCABindingValid(good) {
		t.Fatal("accepted composite policies rejected")
	}
	for i := 0; i < 4; i++ {
		bad := good
		fields := []*string{&bad.Policy, &bad.AuthoritySHA, &bad.SetupPolicy, &bad.SetupAuthority}
		*fields[i] = "foreign-policy-or-authority"
		if task0SystemCABindingValid(bad) {
			t.Fatal("foreign CA/SETUP policy accepted")
		}
	}
	if task0SystemCABindingValid(task0SystemCABinding{}) {
		t.Fatal("unbound CA policy accepted")
	}
}

func TestTask0OriginalCARejectsWritableNonRootAndLinkedSources(t *testing.T) {
	good := syscall.Stat_t{Uid: 0, Mode: syscall.S_IFREG | 0644, Nlink: 1, Size: task0SystemCABytes}
	if !task0OriginalCAMetadata(good) {
		t.Fatal("fixed original metadata rejected")
	}
	for _, scenario := range []string{"owner", "group_write", "other_write", "hardlink", "length", "fifo", "directory"} {
		t.Run(scenario, func(t *testing.T) {
			bad := good
			switch scenario {
			case "owner":
				bad.Uid = 1000
			case "group_write":
				bad.Mode |= 0020
			case "other_write":
				bad.Mode |= 0002
			case "hardlink":
				bad.Nlink++
			case "length":
				bad.Size--
			case "fifo":
				bad.Mode = syscall.S_IFIFO | 0644
			case "directory":
				bad.Mode = syscall.S_IFDIR | 0755
			}
			if task0OriginalCAMetadata(bad) {
				t.Fatal("unsafe original CA metadata accepted")
			}
		})
	}
}

func TestTask0CARequiresReadonlyPrivateSuperblockAndEveryAlias(t *testing.T) {
	const root = "/tmp/aipt-b007-q014-runtime-ca-NON_CANON/ca-root"
	good := "1 0 0:42 / " + root + " ro,nosuid,nodev,noexec - tmpfs tmpfs ro,size=1024k\n" +
		"2 0 0:42 /system-ca " + task0SystemCAPath + " ro,nosuid,nodev,noexec - tmpfs tmpfs ro,size=1024k\n"
	if !task0CAMountAliases([]byte(good), root, 42) {
		t.Fatal("two private readonly aliases rejected")
	}
	for _, scenario := range []string{"writable_alias", "writable_superblock", "missing_noexec", "missing_nodev", "missing_nosuid", "shared", "slave", "extra_alias", "duplicate_alias", "missing_target", "foreign_fs"} {
		t.Run(scenario, func(t *testing.T) {
			bad := good
			switch scenario {
			case "writable_alias":
				bad = strings.Replace(bad, " ro,nosuid", " rw,nosuid", 1)
			case "writable_superblock":
				bad = strings.Replace(bad, "tmpfs ro,", "tmpfs rw,", 1)
			case "missing_noexec":
				bad = strings.Replace(bad, ",noexec", "", 1)
			case "missing_nodev":
				bad = strings.Replace(bad, ",nodev", "", 1)
			case "missing_nosuid":
				bad = strings.Replace(bad, ",nosuid", "", 1)
			case "shared":
				bad = strings.Replace(bad, " - tmpfs", " shared:12 - tmpfs", 1)
			case "slave":
				bad = strings.Replace(bad, " - tmpfs", " master:12 - tmpfs", 1)
			case "extra_alias":
				bad += "3 0 0:42 /system-ca /foreign-alias ro,nosuid,nodev,noexec - tmpfs tmpfs ro\n"
			case "duplicate_alias":
				bad += strings.Split(good, "\n")[0] + "\n"
			case "missing_target":
				bad = strings.Split(good, "\n")[0] + "\n"
			case "foreign_fs":
				bad = strings.Replace(bad, " - tmpfs", " - ext4", 1)
			}
			if task0CAMountAliases([]byte(bad), root, 42) {
				t.Fatal("mutable or extra CA alias accepted")
			}
		})
	}
}

func TestTask0AllThreadPrivilegesRejectExtraCapabilityAndMalformedStatus(t *testing.T) {
	zero := "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n"
	setup := strings.NewReplacer("CapPrm:\t0000000000000000", "CapPrm:\t0000000080000000", "CapEff:\t0000000000000000", "CapEff:\t0000000080000000", "CapBnd:\t0000000000000000", "CapBnd:\t0000000080000000").Replace(zero)
	if !task0ThreadStatusValid([]byte(zero), 0, 0, 0) || !task0ThreadStatusValid([]byte(setup), task0SetupCapabilityMask, 0, 0) {
		t.Fatal("exact active PREP/SETUP mask rejected")
	}
	if task0ThreadStatusValid([]byte(setup), 0, 0, 0) || task0ThreadStatusValid([]byte(zero), task0SetupCapabilityMask, 0, 0) || task0ThreadStatusValid([]byte(setup), task0SetupCapabilityMask|1, 0, 0) {
		t.Fatal("wrong actor mask accepted")
	}
	for _, raw := range []string{strings.Replace(setup, "80000000", "80000001", 1), strings.Replace(setup, "CapInh:\t0000000000000000", "CapInh:\t0000000080000000", 1),
		strings.Replace(setup, "CapAmb:\t0000000000000000", "CapAmb:\t0000000080000000", 1), strings.Replace(setup, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1),
		strings.Replace(setup, "Uid:\t0\t0\t0\t0", "Uid:\t0\t1000\t0\t0", 1), strings.Replace(setup, "Gid:\t0\t0\t0\t0", "Gid:\t0\t0", 1),
		strings.Replace(setup, "CapEff:\t0000000080000000\n", "", 1), setup + "CapEff:\t0000000080000000\n", ""} {
		if task0ThreadStatusValid([]byte(raw), task0SetupCapabilityMask, 0, 0) {
			t.Fatal("incomplete or excessive privilege status accepted")
		}
	}
}

func TestTask0ThreadReadbackBindsTheAuthenticatedObservationDomain(t *testing.T) {
	const outer = "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n"
	if !task0ThreadStatusValid([]byte(outer), 0, 1000, 1000) || task0ThreadStatusValid([]byte(outer), 0, 0, 0) || task0ThreadStatusValid([]byte(outer), 0, 1000, 0) {
		t.Fatal("wrong observation-domain mapping accepted")
	}
	mixed := strings.Replace(outer, "Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t0\t1000\t1000", 1)
	if task0ThreadStatusValid([]byte(mixed), 0, 1000, 1000) {
		t.Fatal("mixed mapped credentials accepted")
	}
}
