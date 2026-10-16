package pilot

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func q034FixtureProof() task0CAProof {
	d := func(c string) string { return strings.Repeat(c, 64) }
	return task0CAProof{CA: task0SystemCABinding{task0SystemCAPolicy, task0Q013AuthoritySHA, task0SetupPolicy, task0Q014AuthoritySHA}, BindingSHA: d("a"), ExecutableSHA: d("b"), Generation: d("c"), SetupSHA: d("e"), SetupBindingSHA: d("f"), SetupAdmitted: true, Original: task0SetupFDIdentity{1, 2}, Source: task0SetupFDIdentity{3, 4}, Materialized: task0SetupFDIdentity{7, 8}, Bytes: task0SystemCABytes, SHA256: task0SystemCASHA, Threads: 3}
}

func q034Binding(p task0CAProof) task0ParentBinding {
	return task0ParentBinding{PreparationSHA: p.BindingSHA, ExecutableSHA: p.ExecutableSHA, SystemCA: p.CA}
}
func q034Pair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	a, b := task0SetupSocketFixture(t)
	if a.SetDeadline(time.Now().Add(3*time.Second)) != nil || b.SetDeadline(time.Now().Add(3*time.Second)) != nil {
		t.Fatal("component deadline")
	}
	return a, b
}

// These are protocol components using a real seqpacket pair and synthetic
// proof callbacks. They do not spawn PREP/SETUP or consume a native claim.
func TestTask0CAConfirmedCompleteHandshakeAndBoundedResampling(t *testing.T) {
	for resamples := 0; resamples <= 3; resamples++ {
		t.Run(string(rune('0'+resamples)), func(t *testing.T) {
			parent, child := q034Pair(t)
			proof := q034FixtureProof()
			childProof := proof
			initial := strings.Repeat("1", 64)
			var trace task0CAConfirmedHandshakeTrace
			ready := false
			done := make(chan error, 1)
			go func() {
				done <- completeTask0CAConfirmedPREPHandshake(child, &childProof, initial, &trace, &ready, func() error { return nil }, func() (int, error) { return 3, nil })
			}()
			o := &task0PreparationCAConfirmedObserver{}
			stage := ""
			calls := 0
			err := o.completeCAHandshake(parent, q034Binding(proof), proof.Generation, initial, func(f *task0CAFrame) error { _, e := task0CAConfirmedReadFrame(parent, f); return e }, func(p *task0CAProof) (int, error) {
				calls++
				if calls <= resamples {
					return p.Threads + 1, nil
				}
				return p.Threads, nil
			}, func() error { return nil }, &stage)
			childErr := <-done
			if err != nil || childErr != nil || !ready || stage != "CA_CONFIRMED_BEFORE_BUSINESS" || !o.record.StopACKObserved || !task0SameJSON(o.handshake, trace) || len(trace.CAResampleNonces) != resamples || o.record.CAResampleCount != resamples {
				t.Fatalf("handshake or resample transcript: %v %v", err, childErr)
			}
			retirement := task0CAConfirmedRetirement{Schema: task0CAConfirmedRetirementSchema, BindingSHA: proof.BindingSHA, ExecutableSHA: proof.ExecutableSHA, Generation: proof.Generation, Nonce: initial, SetupSHA: proof.SetupSHA, SetupBindingSHA: proof.SetupBindingSHA, CA: proof.CA, Original: proof.Original, Source: proof.Source, Root: task0SetupFDIdentity{5, 6}, Materialized: proof.Materialized, CAReadySent: true, Setup: task0CAConfirmedSetupWait{SpawnAttempted: true, Started: true, Admitted: true, AdmissionNonce: strings.Repeat("2", 64), ShutdownAttempted: true, ShutdownNonce: strings.Repeat("3", 64), ShutdownAcknowledged: true, WaitCompleted: true}, Handshake: trace}
			if !task0CAConfirmedRetirementValid(retirement, q034Binding(proof), proof.SetupSHA, proof.SetupBindingSHA, proof.Generation, initial, proof.Original, proof.Source, retirement.Root, &proof) {
				t.Fatal("complete synthetic typed retirement rejected")
			}
			for _, mutate := range []func(*task0CAConfirmedRetirement){func(r *task0CAConfirmedRetirement) { r.Setup.WaitCompleted = false }, func(r *task0CAConfirmedRetirement) { r.Setup.Created = 1 }, func(r *task0CAConfirmedRetirement) { r.Handshake.CAAdmissionNonce = r.Nonce }, func(r *task0CAConfirmedRetirement) {
				r.Handshake.CAReadyProofs[0].ExecutableSHA = strings.Repeat("9", 64)
			}, func(r *task0CAConfirmedRetirement) { r.Handshake.CAReadyNonces[0] = strings.Repeat("9", 64) }} {
				raw, _ := json.Marshal(retirement)
				var bad task0CAConfirmedRetirement
				_ = json.Unmarshal(raw, &bad)
				mutate(&bad)
				if task0CAConfirmedRetirementValid(bad, q034Binding(proof), proof.SetupSHA, proof.SetupBindingSHA, proof.Generation, initial, proof.Original, proof.Source, bad.Root, &proof) {
					t.Fatal("synthetic missing Wait, business or replay mutation accepted")
				}
			}
		})
	}
}

func TestTask0CAConfirmedParentRequiresReceivedBoundStopACK(t *testing.T) {
	for _, scenario := range []string{"missing", "schema", "binding", "image", "generation", "initial", "final", "proof", "stopped", "confirmed", "resample"} {
		t.Run(scenario, func(t *testing.T) {
			parent, child := q034Pair(t)
			proof := q034FixtureProof()
			initial := strings.Repeat("1", 64)
			done := make(chan error, 1)
			go func() {
				ready := task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "CA_READY", BindingSHA: proof.BindingSHA, Generation: proof.Generation, Nonce: initial, Proof: &proof}
				if err := task0CAPacket(child, &ready, true); err != nil {
					done <- err
					return
				}
				var f task0CAFrame
				if _, err := task0CAConfirmedReadFrame(child, &f); err != nil {
					done <- err
					return
				}
				f.Operation = "CA_ADMITTED"
				if err := task0CAPacket(child, &f, true); err != nil {
					done <- err
					return
				}
				if _, err := task0CAConfirmedReadFrame(child, &f); err != nil {
					done <- err
					return
				}
				if scenario == "missing" {
					done <- child.CloseWrite()
					return
				}
				ack := task0CAConfirmedStopACK{Schema: "aipt.private.b007-ca-confirmed-stopped-before-business/v1", BindingSHA: proof.BindingSHA, ExecutableSHA: proof.ExecutableSHA, Generation: proof.Generation, InitialNonce: initial, Handshake: task0CAConfirmedHandshakeTrace{CAReadyNonces: []string{initial}, CAReadyProofs: []task0CAProof{proof}, CAAdmissionNonce: f.Nonce, CAAdmitted: true, CAConfirmed: true, StoppedBeforeBusiness: true}}
				bad := strings.Repeat("9", 64)
				switch scenario {
				case "schema":
					ack.Schema = "foreign"
				case "binding":
					ack.BindingSHA = bad
				case "image":
					ack.ExecutableSHA = bad
				case "generation":
					ack.Generation = bad
				case "initial":
					ack.InitialNonce = bad
				case "final":
					ack.Handshake.CAAdmissionNonce = bad
				case "proof":
					ack.Handshake.CAReadyProofs[0].Threads++
				case "stopped":
					ack.Handshake.StoppedBeforeBusiness = false
				case "confirmed":
					ack.Handshake.CAConfirmed = false
				case "resample":
					ack.Handshake.CAResampleNonces = []string{bad}
				}
				raw, _ := json.Marshal(ack)
				_, err := child.Write(raw)
				done <- err
			}()
			o := &task0PreparationCAConfirmedObserver{}
			stage := ""
			err := o.completeCAHandshake(parent, q034Binding(proof), proof.Generation, initial, func(f *task0CAFrame) error { _, e := task0CAConfirmedReadFrame(parent, f); return e }, func(p *task0CAProof) (int, error) { return p.Threads, nil }, func() error { return nil }, &stage)
			if childErr := <-done; childErr != nil {
				t.Fatal(childErr)
			}
			if err != ErrRuntimeLaunch || !o.record.CAConfirmedSent || o.record.StopACKObserved || o.handshake.StoppedBeforeBusiness {
				t.Fatal("send-only confirmation or foreign ACK accepted")
			}
		})
	}
}

func TestTask0CAConfirmedPREPRejectsReplayForeignProofAndBusiness(t *testing.T) {
	for _, scenario := range []string{"replay", "binding", "generation", "proof", "result", "business", "fourth-resample"} {
		t.Run(scenario, func(t *testing.T) {
			parent, child := q034Pair(t)
			proof := q034FixtureProof()
			initial := strings.Repeat("1", 64)
			done := make(chan error, 1)
			var trace task0CAConfirmedHandshakeTrace
			ready := false
			go func() {
				done <- completeTask0CAConfirmedPREPHandshake(child, &proof, initial, &trace, &ready, func() error { return nil }, func() (int, error) { return 3, nil })
			}()
			count := 1
			if scenario == "fourth-resample" {
				count = 4
			}
			for i := 0; i < count; i++ {
				var frame task0CAFrame
				if _, err := task0CAConfirmedReadFrame(parent, &frame); err != nil {
					t.Fatal(err)
				}
				frame.Operation = "CA_ADMIT"
				frame.Nonce = strings.Repeat(string(rune('2'+i)), 64)
				switch scenario {
				case "replay":
					frame.Nonce = initial
				case "binding":
					frame.BindingSHA = strings.Repeat("9", 64)
				case "generation":
					frame.Generation = strings.Repeat("9", 64)
				case "proof":
					frame.Proof.ExecutableSHA = strings.Repeat("9", 64)
				case "result":
					frame.Result = &task0PreparationResult{}
				case "business":
					frame.Operation = "CREATE"
				case "fourth-resample":
					frame.Operation = "CA_RESAMPLE"
				}
				if task0CAPacket(parent, &frame, true) != nil {
					t.Fatal("synthetic response write")
				}
			}
			if err := <-done; err != ErrRuntimeLaunch || trace.CAConfirmed || trace.StoppedBeforeBusiness {
				t.Fatal("replay, excessive resample or business operation accepted")
			}
		})
	}
}

func TestTask0CAConfirmedNegativeEntryCannotReachRuntime(t *testing.T) {
	t.Setenv("DEEPSEEK_API_KEY", "NON_CANON_NOT_A_KEY")
	var out bytes.Buffer
	o := &task0PreparationCAConfirmedObserver{context: context.Background(), output: &out}
	if runTask0ParentCAConfirmedMode("", nil, nil, nil, nil, o) != ErrRuntimeLaunch {
		t.Fatal("unbound entry accepted")
	}
	var r task0PreparationCAConfirmedObservation
	if json.Unmarshal(out.Bytes(), &r) != nil || r.Outcome != "REJECTED" || r.PreparationSpawnAttempted || r.StopACKObserved || r.Retirement != nil {
		t.Fatal("negative entry reached a target")
	}
	if RunObserveTask0CAConfirmedPreparation("") != ErrRuntimeLaunch {
		t.Fatal("unbound PREP accepted")
	}
}
