package pilot

import (
	"bytes"
	"encoding/json"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/zyc14588/AIPT/internal/evidence"
	"github.com/zyc14588/AIPT/internal/modelgateway"
)

const task0MemoryRecordName = "task0-local-memory.private.jsonl"

var task0MemoryPhases = []string{"BEFORE_START", "AFTER_START", "AFTER_RETIRE"}

// This writer exists before local startup. Every successful memory gate is
// durably recorded through the held budget root. Failed/partial records are
// retained, sealed on retirement and cannot be replaced by another start.
type task0MemoryReceiptWriter struct {
	mu             sync.Mutex
	budget         *GlobalBudget
	profile        modelgateway.ModelProfile
	file           *os.File
	count          int
	last           time.Time
	failed, closed bool
}

func newTask0MemoryReceiptWriter(budget *GlobalBudget, local *acceptedPilotLocalGrant) (*task0MemoryReceiptWriter, error) {
	if budget == nil || budget.checkRoot() != nil || local == nil || local.binding.Profile.LocalRuntimeIdentity == nil {
		return nil, ErrTask0
	}
	fd, err := syscall.Openat(int(budget.root.Fd()), task0MemoryRecordName, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrTask0
	}
	f := os.NewFile(uintptr(fd), "held private local memory gate history")
	if f == nil {
		syscall.Close(fd)
		return nil, ErrTask0
	}
	if budget.root.Sync() != nil {
		f.Chmod(0400)
		f.Close()
		return nil, ErrTask0
	}
	return &task0MemoryReceiptWriter{budget: budget, profile: local.binding.Profile, file: f}, nil
}

func task0ValidateMemoryGate(receipt MemoryGateReceipt, profile modelgateway.ModelProfile, index int, previous time.Time) bool {
	r := profile.LocalRuntimeIdentity
	if r == nil || index < 0 || index >= len(task0MemoryPhases) || receipt.Schema != "aipt.private.b007-local-memory-gate/v1" || receipt.Phase != task0MemoryPhases[index] ||
		receipt.SystemGlobalCacheCleared || receipt.Scope != "HELD_REGISTERED_LOCAL_MODEL_AND_EXECUTABLE_FILE_PAGE_CACHE" || len(receipt.Assets) != 2 ||
		receipt.Before.ObservedAt.IsZero() || receipt.After.ObservedAt.IsZero() || receipt.Before.ObservedAt.Before(previous) || receipt.After.ObservedAt.Before(receipt.Before.ObservedAt) {
		return false
	}
	for _, snapshot := range []MemorySnapshot{receipt.Before, receipt.After} {
		if snapshot.TotalBytes == 0 || snapshot.AvailableBytes > snapshot.TotalBytes || snapshot.FreeBytes > snapshot.TotalBytes {
			return false
		}
	}
	seen := map[string]bool{}
	for _, asset := range receipt.Assets {
		if seen[asset.AssetID] || (asset.AssetID != r.ExecutableReference && asset.AssetID != r.GGUFReference) || asset.Bytes < 1 || !asset.HintAccepted ||
			asset.ResidentBeforeBytes > uint64(asset.Bytes) || asset.ResidentAfterBytes > uint64(asset.Bytes) || asset.ReleaseObserved != (asset.ResidentAfterBytes < asset.ResidentBeforeBytes || asset.ResidentAfterBytes == 0) ||
			(asset.ResidentAfterBytes > 0 && asset.RemainingExplanation != "PAGES_STILL_REFERENCED_OR_KERNEL_RETENTION_HINT_IS_NOT_GLOBAL_CACHE_CLEAR") ||
			(asset.ResidentAfterBytes == 0 && asset.RemainingExplanation != "") || (asset.AssetID == r.GGUFReference && asset.Bytes != b007GGUFBytes) {
			return false
		}
		seen[asset.AssetID] = true
	}
	return len(seen) == 2
}

func (w *task0MemoryReceiptWriter) Write(raw []byte) (int, error) {
	if w == nil {
		return 0, ErrTask0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.failed {
		return 0, ErrTask0
	}
	w.failed = true
	if w.file == nil || w.budget.checkRoot() != nil || len(raw) < 2 || len(raw) > 65536 || raw[len(raw)-1] != '\n' {
		return 0, ErrTask0
	}
	var receipt MemoryGateReceipt
	if decodeFrozenJSON(bytes.TrimSuffix(raw, []byte{'\n'}), 65536, &receipt) != nil || !task0ValidateMemoryGate(receipt, w.profile, w.count, w.last) {
		return 0, ErrTask0
	}
	exact, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(append(exact, '\n'), raw) {
		return 0, ErrTask0
	}
	n, err := w.file.Write(raw)
	if err != nil || n != len(raw) || w.file.Sync() != nil || w.budget.root.Sync() != nil || w.budget.checkRoot() != nil {
		return n, ErrTask0
	}
	w.count++
	w.last = receipt.After.ObservedAt
	w.failed = false
	return n, nil
}

func (w *task0MemoryReceiptWriter) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.file == nil {
		return ErrTask0
	}
	modeErr, syncErr := w.file.Chmod(0400), w.file.Sync()
	closeErr := w.file.Close()
	if modeErr != nil || syncErr != nil || closeErr != nil || w.budget.root.Sync() != nil || w.budget.checkRoot() != nil {
		return ErrTask0
	}
	return nil
}

func task0DecodeMemoryHistory(raw []byte, profile modelgateway.ModelProfile) ([]MemoryGateReceipt, error) {
	if len(raw) < 2 || len(raw) > 3*65536 || raw[len(raw)-1] != '\n' {
		return nil, ErrTask0
	}
	lines := bytes.Split(raw[:len(raw)-1], []byte{'\n'})
	if len(lines) != 3 {
		return nil, ErrTask0
	}
	receipts := make([]MemoryGateReceipt, 3)
	var previous time.Time
	for i, line := range lines {
		if decodeFrozenJSON(line, 65536, &receipts[i]) != nil || !task0ValidateMemoryGate(receipts[i], profile, i, previous) {
			return nil, ErrTask0
		}
		exact, err := json.Marshal(receipts[i])
		if err != nil || !bytes.Equal(exact, line) {
			return nil, ErrTask0
		}
		previous = receipts[i].After.ObservedAt
	}
	return receipts, nil
}

func task0CollectPrivateLocalGates(budget *GlobalBudget, grant *acceptedTask0DispatchGrant, models []evidence.ModelExecutionReference) ([]evidence.LogicalAssetInput, error) {
	var local *task0DispatchProfile
	var requestID string
	for _, model := range models {
		entry, ok := grant.profiles[model.ModelProfile]
		if !ok {
			return nil, ErrTask0
		}
		if entry.Profile.BackendKind == modelgateway.BackendLocalLlamaCPP {
			if local != nil {
				return nil, ErrTask0
			}
			copy := entry
			local, requestID = &copy, model.ExecutionID
		}
	}
	if local == nil || local.Profile.LocalRuntimeIdentity == nil {
		return nil, ErrTask0
	}
	memoryRaw, err := task0ReadPrivateRecord(budget, task0MemoryRecordName)
	if err != nil {
		return nil, ErrTask0
	}
	defer clear(memoryRaw)
	receipts, err := task0DecodeMemoryHistory(memoryRaw, local.Profile)
	if err != nil {
		return nil, ErrTask0
	}
	_, terminal, intentRaw, resultRaw, err := task0ReadModelEvidence(budget, grant, requestID)
	if err != nil {
		return nil, ErrTask0
	}
	defer clear(intentRaw)
	defer clear(resultRaw)
	proof, err := task0ReadPrivateRecord(budget, "task0-native-input-proof.private.jsonl")
	if err != nil {
		return nil, ErrTask0
	}
	defer clear(proof)
	if terminal.Result == nil || validateCompletedNativeProof(proof, grant.binding.RuntimeManifestSHA, local.Profile.LocalRuntimeIdentity.BinarySHA256, terminal.Result.BackendSerializedRequestSHA256) != nil {
		return nil, ErrTask0
	}
	completed := terminal.Result.CompletedAt
	if completed.IsZero() || completed.Before(receipts[1].After.ObservedAt) || completed.After(receipts[2].Before.ObservedAt) {
		return nil, ErrTask0
	}
	memoryAsset, _, err := task0PrivateEvidenceAsset("private/local-memory-gates.json", "b007-local-memory-gates", struct {
		Schema         string              `json:"schema"`
		ManifestSHA    string              `json:"manifest_sha256"`
		ProfileBinding string              `json:"profile_binding"`
		LocalRequestID string              `json:"local_request_id"`
		Receipts       []MemoryGateReceipt `json:"receipts"`
	}{"aipt.private.b007-local-memory-evidence/v1", grant.binding.ManifestSHA, local.Profile.BindingID(), requestID, receipts})
	if err != nil {
		return nil, ErrTask0
	}
	nativeAsset := evidence.LogicalAssetInput{Path: "private/final-native-input-proof.jsonl", MediaType: "application/x-ndjson", Classification: evidence.ContentTableHiddenRemote, ContentKind: evidence.ContentKindSupplemental, Data: bytes.Clone(proof)}
	return []evidence.LogicalAssetInput{memoryAsset, nativeAsset}, nil
}
