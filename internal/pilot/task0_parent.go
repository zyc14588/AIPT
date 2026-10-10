package pilot

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"
)

type task0ParentBinding struct {
	Schema          string               `json:"schema"`
	AuthoritySHA    string               `json:"authority_sha256"`
	SystemCA        task0SystemCABinding `json:"system_ca"`
	PreparationSHA  string               `json:"preparation_binding_sha256"`
	Preparation     []byte               `json:"preparation_binding_bytes"`
	ExecutableSHA   string               `json:"preparation_executable_sha256"`
	ExecutableBytes int64                `json:"preparation_executable_bytes"`
}

type task0PreparationResult struct {
	Schema           string `json:"schema"`
	BindingSHA       string `json:"binding_sha256"`
	RunID            string `json:"run_id"`
	Status           string `json:"status"`
	EvidenceRootSHA  string `json:"ciphertext_evidence_root_sha256"`
	Generation       string `json:"generation"`
	CAAdmissionNonce string `json:"ca_admission_nonce"`
	SetupCreated     int    `json:"setup_created_children"`
	SetupJoined      int    `json:"setup_directly_joined_children"`
	SetupWaited      bool   `json:"setup_direct_wait_completed"`
}

func decodeTask0ParentBinding(raw []byte, expectedSHA string) (task0ParentBinding, error) {
	var b task0ParentBinding
	if !digest(expectedSHA) || inputSHA(raw) != expectedSHA || decodeFrozenJSON(raw, task0ParentBindingMaxBytes, &b) != nil || b.Schema != "aipt.private.b007-task0-parent-binding/v2" || !task0SystemCABindingValid(b.SystemCA) ||
		b.AuthoritySHA != LocalClosureAuthoritySHA || !digest(b.PreparationSHA) || inputSHA(b.Preparation) != b.PreparationSHA || !digest(b.ExecutableSHA) || b.ExecutableBytes < 64 || b.ExecutableBytes > 128<<20 {
		return task0ParentBinding{}, ErrRuntimeLaunch
	}
	if _, err := decodeTask0Preparation(b.Preparation, b.PreparationSHA); err != nil {
		return task0ParentBinding{}, ErrRuntimeLaunch
	}
	return b, nil
}

func task0ParentResultValid(r task0PreparationResult, bindingSHA string) bool {
	return r.Schema == "aipt.private.b007-task0-preparation-result/v2" && r.BindingSHA == bindingSHA && r.RunID == task0DiagnosticRunID && r.Status == "COMPLETED_NON_QUAL" && digest(r.EvidenceRootSHA) &&
		digest(r.Generation) && digest(r.CAAdmissionNonce) && r.SetupCreated >= 2 && r.SetupCreated <= 34 && r.SetupJoined == r.SetupCreated && r.SetupWaited
}

// Parent opens the fixed root-owned system CA and owns its snapshot and empty
// mountpoint. Fresh outside readback admits Cap0 PREP before a verifier or
// model call. Inputs close only after this parent's actual command.Wait.
func RunAcceptedTask0Parent(expectedBindingSHA string) (runErr error) {
	inputsRetained := false
	if !digest(expectedBindingSHA) || len(os.Args) != 1 {
		return ErrRuntimeLaunch
	}
	credential := os.Getenv("DEEPSEEK_API_KEY")
	if !task0PreparationCredentialValid(credential) {
		return ErrRuntimeLaunch
	}
	incoming, err := frozenBorrowFile(3)
	if err != nil {
		return ErrRuntimeLaunch
	}
	info, err := incoming.Stat()
	incoming.Close()
	if err != nil || info.Size() < 1 || info.Size() > task0ParentBindingMaxBytes {
		return ErrRuntimeLaunch
	}
	held, err := frozenSealedFile(3, expectedBindingSHA, info.Size())
	if err != nil {
		return ErrRuntimeLaunch
	}
	defer func() {
		if !inputsRetained {
			_ = held.Close()
		}
	}()
	raw, err := io.ReadAll(io.NewSectionReader(held, 0, info.Size()))
	defer clear(raw)
	if err != nil {
		return ErrRuntimeLaunch
	}
	b, err := decodeTask0ParentBinding(raw, expectedBindingSHA)
	if err != nil {
		return ErrRuntimeLaunch
	}
	defer clear(b.Preparation)
	self, err := frozenSealedFile(4, b.ExecutableSHA, b.ExecutableBytes)
	if err != nil {
		return ErrRuntimeLaunch
	}
	defer func() {
		if !inputsRetained {
			_ = self.Close()
		}
	}()
	if !staticPreparationFile(self) {
		return ErrRuntimeLaunch
	}
	binding, err := task0SealedBytes(b.Preparation)
	if err != nil {
		return ErrRuntimeLaunch
	}
	defer func() {
		if !inputsRetained {
			_ = binding.Close()
		}
	}()
	ca, err := openTask0ParentSystemCA()
	if err != nil {
		return ErrRuntimeLaunch
	}
	directory, err := openTask0CAParentDirectory()
	if err != nil {
		ca.close()
		return ErrRuntimeLaunch
	}
	var p *freshPreparationProcess
	directoryRemoved := false
	defer func() {
		// The direct child join comes first even on a failed admission.
		if p != nil && p.retire() != nil {
			runErr = ErrRuntimeLaunch
		}
		if p != nil && !task0DirectJoinCompleted(p) {
			runErr, inputsRetained = ErrRuntimeLaunch, true
			task0RetainInputsUntilDirectJoin(p, func() {
				_ = directory.removeAfterJoin(true)
				directory.close()
				ca.close()
				task0CloseInputFiles([]*os.File{binding, self, held})
			})
			return
		}
		if !directoryRemoved && directory.removeAfterJoin(true) != nil {
			runErr = ErrRuntimeLaunch
		}
		directory.close()
		ca.close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 31*time.Minute)
	defer cancel()
	environment := frozenEnvironment(map[string]string{"DEEPSEEK_API_KEY": credential})
	var admissionNonce string
	var initialProof *task0CAProof
	p, admissionNonce, initialProof, err = launchTask0CAPreparation(ctx, self, binding, b, ca, directory, environment)
	if err != nil {
		return ErrRuntimeLaunch
	}
	deadline, _ := ctx.Deadline()
	if p.control.SetReadDeadline(deadline) != nil {
		return ErrRuntimeLaunch
	}
	var final task0CAFrame
	if task0CAPacket(p.control, &final, false) != nil || !task0CAFrameValid(final, "COMPLETE", b.PreparationSHA, ca.generation, admissionNonce) ||
		final.Result == nil || final.Proof == nil || !task0ParentResultValid(*final.Result, b.PreparationSHA) || final.Result.Generation != ca.generation || final.Result.CAAdmissionNonce != admissionNonce {
		return ErrRuntimeLaunch
	}
	current := *final.Proof
	current.Threads = initialProof.Threads
	if current != *initialProof {
		return ErrRuntimeLaunch
	}
	if _, err = task0ParentCAReadback(p, self, b, ca, directory, final.Proof); err != nil {
		return ErrRuntimeLaunch
	}
	final.Operation = "RESULT_ACCEPTED"
	if task0CAPacket(p.control, &final, true) != nil {
		return ErrRuntimeLaunch
	}
	select {
	case <-p.exit:
		if p.waitErr != nil {
			return ErrRuntimeLaunch
		}
	case <-ctx.Done():
		return ErrRuntimeLaunch
	}
	if !ca.stableOriginal() || !directory.stableEmpty() {
		return ErrRuntimeLaunch
	}
	// All values are fixed control identities or independently verified root
	// hashes. The Owner's private evidence/key paths never enter this result.
	directoryRemoved, err = task0PublishJoinedParentResult(os.Stdout, p, directory, final.Result)
	return err
}

func task0PublishJoinedParentResult(output io.Writer, p *freshPreparationProcess, directory *task0CAParentDirectory, result *task0PreparationResult) (removed bool, err error) {
	if output == nil || result == nil || directory == nil || !task0DirectJoinCompleted(p) || p.waitErr != nil || !directory.stableEmpty() {
		return false, ErrRuntimeLaunch
	}
	if directory.removeAfterJoin(true) != nil {
		return false, ErrRuntimeLaunch
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return true, ErrRuntimeLaunch
	}
	return true, nil
}

func task0PreparationCredentialValid(value string) bool {
	return len(value) > 0 && len(value) <= 4096 && !strings.ContainsAny(value, "\x00\r\n") && strings.TrimSpace(value) == value
}
