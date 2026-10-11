package pilot

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"slices"
	"sync"
	"time"

	"github.com/zyc14588/AIPT/internal/protocol"
	"github.com/zyc14588/AIPT/internal/runcore"
)

const task0GameWireLimit = 1 << 20

type task0GameReply struct {
	Schema string                       `json:"schema"`
	Op     string                       `json:"operation"`
	Source runcore.SourcePackageBinding `json:"source_binding"`
	Result json.RawMessage              `json:"result"`
}

type task0PipeGame struct {
	lifetime context.Context
	cancel   context.CancelFunc
	input    io.WriteCloser
	output   io.ReadCloser
	owned    *frozenOwnedProcess
	serial   chan struct{}
	close    sync.Once
}

// Called only after the owned helper has entered and verified its accepted
// read-only runtime root. No host-side process, caller-selected Node, source
// path, environment or dynamically supplied program can enter this route.
func openTask0CapsuleGame(ctx context.Context, c *HeldCodeCapsule, p task0GameRootPolicy) (*task0PipeGame, error) {
	if ctx == nil || ctx.Err() != nil || c == nil || os.Getpid() != 1 || validateTask0GameRootPolicy(p, c.manifest) != nil ||
		validateTask0Capsule(c) != nil || verifyFrozenRuntimeRoot(c, p.Root) != nil || verifyZeroCapabilityThreads(1) != nil {
		return nil, ErrTask0
	}
	var nodeSpec RuntimeCodeFile
	for _, spec := range c.manifest.Files {
		if spec.AssetID == p.NodeAsset {
			nodeSpec = spec
		}
	}
	if nodeSpec.SHA256 != b007NodeSHA || nodeSpec.Kind != "ELF" || !nodeSpec.Executable || !slices.Contains(c.manifest.LaunchRoots, p.NodeAsset) {
		return nil, ErrTask0
	}
	node, err := c.Descriptor(p.NodeAsset)
	if err != nil {
		return nil, ErrTask0
	}
	defer node.Close()
	cmd := exec.Command("/proc/self/fd/3", "--no-warnings", task0GatewayPath)
	cmd.ExtraFiles = []*os.File{node}
	cmd.Dir = "/aipt/game"
	cmd.Env = frozenEnvironment(nil)
	cmd.Stderr = io.Discard
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, ErrTask0
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, ErrTask0
	}
	owned, err := startFrozenProcess(cmd, node)
	if err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, ErrTask0
	}
	lifetime, cancel := context.WithCancel(ctx)
	g := &task0PipeGame{lifetime: lifetime, cancel: cancel, input: input, output: output, owned: owned, serial: make(chan struct{}, 1)}
	g.serial <- struct{}{}
	context.AfterFunc(lifetime, g.retire)
	readyCtx, stop := context.WithTimeout(lifetime, 10*time.Second)
	defer stop()
	if err = g.acceptReady(readyCtx); err != nil {
		g.retire()
		return nil, ErrTask0
	}
	return g, nil
}

func task0ReadWire(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, ErrTask0
	}
	n := binary.BigEndian.Uint32(header[:])
	if n < 2 || n > task0GameWireLimit {
		return nil, ErrTask0
	}
	body := make([]byte, int(n))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, ErrTask0
	}
	return body, nil
}

func task0WriteWire(w io.Writer, body []byte) error {
	if len(body) < 2 || len(body) > task0GameWireLimit {
		return ErrTask0
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	for _, part := range [][]byte{header[:], body} {
		for len(part) > 0 {
			n, err := w.Write(part)
			if err != nil || n < 1 || n > len(part) {
				return ErrTask0
			}
			part = part[n:]
		}
	}
	return nil
}

func (g *task0PipeGame) retire() {
	if g == nil {
		return
	}
	g.close.Do(func() {
		g.cancel()
		_ = g.input.Close()
		_ = g.output.Close()
		if g.owned != nil {
			_ = g.owned.stop(time.Second)
		}
	})
}

// Every exchange has the Run lifetime and an independent short deadline,
// including Core invariants whose interface supplies no live action context.
func (g *task0PipeGame) readWithLifetime(ctx context.Context, operation func() ([]byte, error)) ([]byte, error) {
	if g == nil || ctx == nil || g.lifetime == nil || g.lifetime.Err() != nil || ctx.Err() != nil {
		return nil, ErrTask0
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(g.lifetime, cancel)
	defer stop()
	type result struct {
		raw []byte
		err error
	}
	done := make(chan result, 1)
	go func() { raw, err := operation(); done <- result{raw, err} }()
	select {
	case v := <-done:
		if v.err != nil || ctx.Err() != nil || g.lifetime.Err() != nil {
			g.retire()
			return nil, ErrTask0
		}
		return v.raw, nil
	case <-ctx.Done():
		g.retire()
		// Closing the owned pipes unblocks the outstanding exchange. Its
		// eventual result has no access to the next request's private pipe.
		return nil, ErrTask0
	}
}

func (g *task0PipeGame) acceptReady(ctx context.Context) error {
	raw, err := g.readWithLifetime(ctx, func() ([]byte, error) { return task0ReadWire(g.output) })
	var ready struct {
		Schema string                       `json:"schema"`
		Source runcore.SourcePackageBinding `json:"source_binding"`
	}
	if err != nil || decodeFrozenJSON(raw, 4096, &ready) != nil || ready.Schema != "aipt.private.b007-task0-game-ready/v1" || ready.Source != task0PrototypeSourceBinding || g.owned != nil && g.owned.check() != nil {
		return ErrTask0
	}
	return nil
}

func (g *task0PipeGame) invoke(ctx context.Context, operation string, fields map[string]any) (json.RawMessage, error) {
	if g == nil || ctx == nil || g.lifetime == nil || g.lifetime.Err() != nil || ctx.Err() != nil || g.serial == nil ||
		!slices.Contains([]string{"INITIAL", "PROPOSE", "CHECK_PROPOSAL", "APPLY", "INVARIANT", "PROJECTION"}, operation) {
		return nil, ErrTask0
	}
	request := map[string]any{"schema": "aipt.private.b007-task0-game-request/v1", "operation": operation, "source_binding": task0PrototypeSourceBinding}
	for key, value := range fields {
		if _, reserved := request[key]; reserved {
			return nil, ErrTask0
		}
		request[key] = value
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > task0GameWireLimit {
		return nil, ErrTask0
	}
	canonical, err := protocol.CanonicalJSON(body)
	if err != nil {
		return nil, ErrTask0
	}
	select {
	case <-ctx.Done():
		return nil, ErrTask0
	case <-g.lifetime.Done():
		return nil, ErrTask0
	case <-g.serial:
	}
	defer func() { g.serial <- struct{}{} }()
	if g.owned != nil && g.owned.check() != nil {
		g.retire()
		return nil, ErrTask0
	}
	raw, err := g.readWithLifetime(ctx, func() ([]byte, error) {
		if err := task0WriteWire(g.input, []byte(canonical)); err != nil {
			return nil, err
		}
		return task0ReadWire(g.output)
	})
	var reply task0GameReply
	if err != nil || decodeFrozenJSON(raw, task0GameWireLimit, &reply) != nil || reply.Schema != "aipt.private.b007-task0-game-reply/v1" ||
		reply.Op != operation || reply.Source != task0PrototypeSourceBinding || len(reply.Result) < 2 || string(reply.Result) == "null" || g.owned != nil && g.owned.check() != nil {
		g.retire()
		return nil, ErrTask0
	}
	return slices.Clone(reply.Result), nil
}
