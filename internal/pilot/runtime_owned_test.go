package pilot

import (
	"testing"
)

func TestFrozenTCPTableRejectsAmbiguousOrMalformedFields(t *testing.T) {
	header := "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	good := header + "0: 0100007F:3E80 0100007F:4E20 01 00000000:00000000 00:00000000 00000000 0 0 31415 1\n"
	got, e := parseFrozenTCPTable([]byte(good), "tcp")
	if e != nil || len(got) != 1 || got[0].localPort != 16000 || got[0].remotePort != 20000 || got[0].inode != "31415" {
		t.Fatal("kernel endpoint parse", e)
	}
	for _, raw := range []string{"", header + "malformed\n", header + "0: 0100007F:GG 0100007F:4E20 01 0 0 0 0 0 31415\n", header + "0: 0100007F:3E80 0100007F:4E20 01 0 0 0 0 0 NaN\n", header + "0: 7F:3E80 0100007F:4E20 01 0 0 0 0 0 31415\n"} {
		if _, e := parseFrozenTCPTable([]byte(raw), "tcp"); e == nil {
			t.Fatal("malformed accepted")
		}
	}
}

func TestFrozenProofBufferCannotResetOrGrowUnbounded(t *testing.T) {
	p := &frozenProofBuffer{}
	if n, e := p.Write([]byte("NON_CANON_DIGEST_ONLY\n")); e != nil || n != 22 {
		t.Fatal(n, e)
	}
	b := p.snapshot()
	b[0] = 'X'
	if p.snapshot()[0] != 'N' {
		t.Fatal("mutable proof read")
	}
	if _, e := p.Write(make([]byte, 16384)); e == nil {
		t.Fatal("unbounded proof")
	}
	if len(p.snapshot()) != 22 {
		t.Fatal("failed append changed proof")
	}
}

func TestFrozenGenerationRejectsMissingKernelBinding(t *testing.T) {
	if (*frozenOwnedProcess)(nil).check() == nil {
		t.Fatal("missing generation accepted")
	}
	if e := (*frozenOwnedProcess)(nil).stop(0); e != nil {
		t.Fatal(e)
	}
}
