package pilot

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var ErrMemory = errors.New("B007 local memory/cache gate failed")

type MemorySnapshot struct {
	ObservedAt            time.Time `json:"observed_at_utc"`
	TotalBytes            uint64    `json:"total_bytes"`
	AvailableBytes        uint64    `json:"available_bytes"`
	FreeBytes             uint64    `json:"free_bytes"`
	FileCacheBytes        uint64    `json:"file_cache_bytes"`
	BufferBytes           uint64    `json:"buffer_bytes"`
	ReclaimableBytes      uint64    `json:"reclaimable_bytes"`
	SharedBytes           uint64    `json:"shared_bytes"`
	SwapUsedBytes         uint64    `json:"swap_used_bytes"`
	ProcessRSSBytes       uint64    `json:"process_rss_bytes"`
	ProcessAnonymousBytes uint64    `json:"process_anonymous_bytes"`
	ProcessFileBytes      uint64    `json:"process_file_bytes"`
	ProcessSharedBytes    uint64    `json:"process_shared_bytes"`
}

func parseMemoryValues(reader io.Reader) (map[string]uint64, error) {
	values := map[string]uint64{}
	scanner := bufio.NewScanner(io.LimitReader(reader, 1<<20))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || fields[2] != "kB" {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || value > ^uint64(0)/1024 {
			return nil, ErrMemory
		}
		if _, ok := values[key]; ok {
			return nil, ErrMemory
		}
		values[key] = value * 1024
	}
	if scanner.Err() != nil {
		return nil, ErrMemory
	}
	return values, nil
}

func ReadMemorySnapshot(modelPID int) (MemorySnapshot, error) {
	result := MemorySnapshot{ObservedAt: time.Now().UTC()}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return result, ErrMemory
	}
	memory, err := parseMemoryValues(f)
	_ = f.Close()
	if err != nil {
		return result, ErrMemory
	}
	for _, key := range []string{"MemTotal", "MemAvailable", "MemFree", "Cached", "Buffers", "SReclaimable", "Shmem", "SwapTotal", "SwapFree"} {
		if _, ok := memory[key]; !ok {
			return result, ErrMemory
		}
	}
	if memory["SwapFree"] > memory["SwapTotal"] || memory["MemAvailable"] > memory["MemTotal"] {
		return result, ErrMemory
	}
	result.TotalBytes, result.AvailableBytes, result.FreeBytes = memory["MemTotal"], memory["MemAvailable"], memory["MemFree"]
	result.FileCacheBytes, result.BufferBytes, result.ReclaimableBytes, result.SharedBytes = memory["Cached"], memory["Buffers"], memory["SReclaimable"], memory["Shmem"]
	result.SwapUsedBytes = memory["SwapTotal"] - memory["SwapFree"]
	if modelPID > 0 {
		f, err := os.Open("/proc/" + strconv.Itoa(modelPID) + "/status")
		if err != nil {
			return result, ErrMemory
		}
		process, err := parseMemoryValues(f)
		_ = f.Close()
		if err != nil {
			return result, ErrMemory
		}
		if _, ok := process["VmRSS"]; !ok {
			return result, ErrMemory
		}
		result.ProcessRSSBytes, result.ProcessAnonymousBytes, result.ProcessFileBytes, result.ProcessSharedBytes = process["VmRSS"], process["RssAnon"], process["RssFile"], process["RssShmem"]
	}
	return result, nil
}

type CacheAsset struct {
	AssetID string
	File    *os.File // Already held and authenticated by the asset preflight.
}
type CacheReleaseResult struct {
	AssetID              string `json:"asset_id"`
	Bytes                int64  `json:"bytes"`
	ResidentBeforeBytes  uint64 `json:"resident_before_bytes"`
	ResidentAfterBytes   uint64 `json:"resident_after_bytes"`
	HintAccepted         bool   `json:"fadvise_dontneed_accepted"`
	ReleaseObserved      bool   `json:"cache_release_observed"`
	RemainingExplanation string `json:"remaining_cache_explanation"`
}
type MemoryGateReceipt struct {
	Schema                   string               `json:"schema"`
	Phase                    string               `json:"phase"`
	Before                   MemorySnapshot       `json:"before"`
	After                    MemorySnapshot       `json:"after"`
	Assets                   []CacheReleaseResult `json:"assets"`
	SystemGlobalCacheCleared bool                 `json:"system_global_cache_cleared"`
	Scope                    string               `json:"scope"`
}

func fileResidency(file *os.File, size int64) (uint64, error) {
	if size <= 0 || size > 1<<40 || file == nil {
		return 0, ErrMemory
	}
	pages := (size + int64(os.Getpagesize()) - 1) / int64(os.Getpagesize())
	if pages > 1<<28 {
		return 0, ErrMemory
	}
	// PROT_NONE never reads the model or warms its cache; mincore inspects the
	// existing file residency through the same held inode without a path race.
	mapping, err := syscall.Mmap(int(file.Fd()), 0, int(size), syscall.PROT_NONE, syscall.MAP_PRIVATE)
	if err != nil {
		return 0, ErrMemory
	}
	defer syscall.Munmap(mapping)
	vector := make([]byte, int(pages))
	_, _, errno := syscall.Syscall(syscall.SYS_MINCORE, uintptr(unsafe.Pointer(&mapping[0])), uintptr(len(mapping)), uintptr(unsafe.Pointer(&vector[0])))
	runtime.KeepAlive(mapping)
	runtime.KeepAlive(vector)
	if errno != 0 {
		return 0, ErrMemory
	}
	var resident uint64
	for _, v := range vector {
		if v&1 != 0 {
			resident += uint64(os.Getpagesize())
		}
	}
	return min(resident, uint64(size)), nil
}

// CheckAndReleaseModelCache runs before startup, after startup and after
// retirement. It never kills unrelated processes, drops active model buffers
// or changes system-wide kernel controls. Linux may retain pages referenced
// by a live model; that distinction is recorded rather than claiming success.
func CheckAndReleaseModelCache(ctx context.Context, phase string, modelPID int, assets []CacheAsset, record io.Writer) (MemoryGateReceipt, error) {
	receipt := MemoryGateReceipt{Schema: "aipt.private.b007-local-memory-gate/v1", Phase: phase, Assets: []CacheReleaseResult{}, Scope: "HELD_REGISTERED_LOCAL_MODEL_AND_EXECUTABLE_FILE_PAGE_CACHE"}
	if ctx == nil || ctx.Err() != nil || record == nil || !slices.Contains([]string{"BEFORE_START", "AFTER_START", "AFTER_RETIRE"}, phase) || len(assets) == 0 {
		return receipt, ErrMemory
	}
	before, err := ReadMemorySnapshot(modelPID)
	if err != nil {
		return receipt, err
	}
	receipt.Before = before
	seen := map[string]bool{}
	for _, asset := range assets {
		if asset.AssetID == "" || seen[asset.AssetID] || asset.File == nil || ctx.Err() != nil {
			return receipt, ErrMemory
		}
		seen[asset.AssetID] = true
		info, err := asset.File.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
			return receipt, ErrMemory
		}
		before, err := fileResidency(asset.File, info.Size())
		if err != nil {
			return receipt, err
		}
		// POSIX_FADV_DONTNEED=4. A read-only held file is enough; this does not
		// alter source bytes, re-open locators or require system admin rights.
		_, _, errno := syscall.Syscall6(syscall.SYS_FADVISE64, asset.File.Fd(), 0, 0, 4, 0, 0)
		if errno != 0 {
			return receipt, ErrMemory
		}
		after, err := fileResidency(asset.File, info.Size())
		if err != nil {
			return receipt, err
		}
		result := CacheReleaseResult{AssetID: asset.AssetID, Bytes: info.Size(), ResidentBeforeBytes: before, ResidentAfterBytes: after, HintAccepted: true, ReleaseObserved: after < before || after == 0}
		if after > 0 {
			result.RemainingExplanation = "PAGES_STILL_REFERENCED_OR_KERNEL_RETENTION_HINT_IS_NOT_GLOBAL_CACHE_CLEAR"
		}
		receipt.Assets = append(receipt.Assets, result)
	}
	after, err := ReadMemorySnapshot(modelPID)
	if err != nil {
		return receipt, err
	}
	receipt.After = after
	if err := json.NewEncoder(record).Encode(receipt); err != nil {
		return receipt, ErrMemory
	}
	return receipt, nil
}
