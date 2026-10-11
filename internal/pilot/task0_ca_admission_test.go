package pilot

import (
	"strings"
	"testing"
)

func TestTask0CAAdmissionRejectsStaleGenerationAndUnsolicitedAuthority(t *testing.T) {
	binding, generation, nonce := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	f := task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "CA_ADMIT", BindingSHA: binding, Generation: generation, Nonce: nonce}
	if !task0CAFrameValid(f, "CA_ADMIT", binding, generation, nonce) {
		t.Fatal("bound control rejected")
	}
	for _, scenario := range []string{"schema", "binding", "generation", "nonce", "operation"} {
		t.Run(scenario, func(t *testing.T) {
			bad := f
			switch scenario {
			case "schema":
				bad.Schema = "caller"
			case "binding":
				bad.BindingSHA = strings.Repeat("d", 64)
			case "generation":
				bad.Generation = strings.Repeat("d", 64)
			case "nonce":
				bad.Nonce = strings.Repeat("d", 64)
			case "operation":
				bad.Operation = "COMPLETE"
			}
			if task0CAFrameValid(bad, "CA_ADMIT", binding, generation, nonce) {
				t.Fatal("foreign or replayed control accepted")
			}
		})
	}
	p := task0CAProof{CA: task0SystemCABinding{task0SystemCAPolicy, task0Q013AuthoritySHA, task0SetupPolicy, task0Q014AuthoritySHA}, BindingSHA: binding, ExecutableSHA: binding, Generation: generation, SetupSHA: binding, SetupBindingSHA: binding, SetupAdmitted: true, Original: task0SetupFDIdentity{1, 2}, Source: task0SetupFDIdentity{2, 3}, Materialized: task0SetupFDIdentity{3, 4}, Bytes: task0SystemCABytes, SHA256: task0SystemCASHA, Threads: 4}
	if !task0CAProofIdentities(&p) {
		t.Fatal("three distinct bound identities rejected")
	}
	for _, scenario := range []string{"q013", "q014", "setup_admission", "setup_binding", "source_alias", "materialized_alias", "thread_zero", "thread_overflow", "wrong_bytes", "wrong_ca"} {
		t.Run(scenario, func(t *testing.T) {
			bad := p
			switch scenario {
			case "q013":
				bad.CA.AuthoritySHA = binding
			case "q014":
				bad.CA.SetupAuthority = binding
			case "setup_admission":
				bad.SetupAdmitted = false
			case "setup_binding":
				bad.SetupBindingSHA = ""
			case "source_alias":
				bad.Source = bad.Original
			case "materialized_alias":
				bad.Materialized = bad.Source
			case "thread_zero":
				bad.Threads = 0
			case "thread_overflow":
				bad.Threads = 513
			case "wrong_bytes":
				bad.Bytes++
			case "wrong_ca":
				bad.SHA256 = binding
			}
			if task0CAProofIdentities(&bad) {
				t.Fatal("unsupported identity or authority accepted")
			}
		})
	}
}

func TestTask0ParentRejectsIncompleteOrUnboundOwningJoins(t *testing.T) {
	r := task0PreparationResult{Schema: "aipt.private.b007-task0-preparation-result/v2", BindingSHA: strings.Repeat("a", 64), RunID: task0DiagnosticRunID, Status: "COMPLETED_NON_QUAL", EvidenceRootSHA: strings.Repeat("b", 64), Generation: strings.Repeat("c", 64), CAAdmissionNonce: strings.Repeat("d", 64), SetupCreated: 7, SetupJoined: 7, SetupWaited: true}
	if !task0ParentResultValid(r, r.BindingSHA) {
		t.Fatal("typed joined control rejected")
	}
	for _, scenario := range []string{"no_generation", "no_admission", "missing_child", "no_setup_wait", "extra_creation", "no_local_and_game"} {
		t.Run(scenario, func(t *testing.T) {
			bad := r
			switch scenario {
			case "no_generation":
				bad.Generation = ""
			case "no_admission":
				bad.CAAdmissionNonce = ""
			case "missing_child":
				bad.SetupJoined--
			case "no_setup_wait":
				bad.SetupWaited = false
			case "extra_creation":
				bad.SetupCreated = 35
				bad.SetupJoined = 35
			case "no_local_and_game":
				bad.SetupCreated = 1
				bad.SetupJoined = 1
			}
			if task0ParentResultValid(bad, r.BindingSHA) {
				t.Fatal("incomplete owning joins accepted")
			}
		})
	}
}

func TestTask0StatusParentReadbackRejectsMissingDuplicateOrKernelParent(t *testing.T) {
	if p, err := task0StatusParentPID([]byte("Name:\tNON_CANON\nPPid:\t17\n")); err != nil || p != 17 {
		t.Fatal("observer parent rejected")
	}
	for _, raw := range []string{"", "Name:\tNON_CANON\n", "PPid:\t0\n", "PPid:\t-1\n", "PPid:\t17\nPPid:\t18\n", "PPid:\tcaller\n"} {
		if _, err := task0StatusParentPID([]byte(raw)); err == nil {
			t.Fatal("unbound parent accepted")
		}
	}
}
