package pilot

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// NON_CANON private-pipe fixtures exercise control framing, cancellation and
// reply authentication only. They create no executable, model or capsule.
func task0WireFixture(t *testing.T, respond func([]byte) []byte) *task0PipeGame {
	t.Helper()
	serverRead, clientWrite := io.Pipe()
	clientRead, serverWrite := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	g := &task0PipeGame{lifetime: ctx, cancel: cancel, input: clientWrite, output: clientRead, serial: make(chan struct{}, 1)}
	g.serial <- struct{}{}
	t.Cleanup(func() { g.retire(); _ = serverRead.Close(); _ = serverWrite.Close() })
	go func() {
		defer serverRead.Close()
		defer serverWrite.Close()
		for {
			raw, err := task0ReadWire(serverRead)
			if err != nil {
				return
			}
			if err = task0WriteWire(serverWrite, respond(raw)); err != nil {
				return
			}
		}
	}()
	return g
}

func task0FixtureReply() task0GameReply {
	return task0GameReply{Schema: "aipt.private.b007-task0-game-reply/v1", Op: "INVARIANT", Source: task0PrototypeSourceBinding, Result: json.RawMessage(`{"valid":true,"complete":false}`)}
}

func TestTask0GameWireRejectsChangedReplyAndContext(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong_schema", "wrong_operation", "wrong_source", "unknown_field", "case_alias", "duplicate_schema", "null_result", "trailing_json", "invalid_utf8", "malformed_result", "cancelled", "retired"} {
		t.Run(scenario, func(t *testing.T) {
			g := task0WireFixture(t, func(raw []byte) []byte {
				var request map[string]json.RawMessage
				if json.Unmarshal(raw, &request) != nil || string(request["operation"]) != `"INVARIANT"` {
					return []byte(`{}`)
				}
				r := task0FixtureReply()
				switch scenario {
				case "wrong_schema":
					r.Schema = "fixture/v1"
				case "wrong_operation":
					r.Op = "PROPOSE"
				case "wrong_source":
					r.Source.Commit = strings.Repeat("1", 40)
				case "null_result":
					r.Result = json.RawMessage(`null`)
				}
				b, _ := json.Marshal(r)
				switch scenario {
				case "unknown_field":
					b = append(b[:len(b)-1], []byte(`,"path":"fixture"}`)...)
				case "case_alias":
					b = bytes.Replace(b, []byte(`"schema"`), []byte(`"Schema"`), 1)
				case "duplicate_schema":
					b = append(b[:len(b)-1], []byte(`,"schema":"fixture/v1"}`)...)
				case "trailing_json":
					b = append(b, []byte(`{}`)...)
				case "invalid_utf8":
					b = []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
				case "malformed_result":
					b = []byte(`{"schema":false}`)
				}
				return b
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancelled" {
				cancel()
			}
			if scenario == "retired" {
				g.retire()
			}
			raw, err := g.invoke(ctx, "INVARIANT", map[string]any{"state": map[string]bool{"non_canon": true}})
			if (err == nil) != (scenario == "valid") {
				t.Fatal("wire admission differs", scenario)
			}
			if err == nil && !bytes.Equal(raw, task0FixtureReply().Result) {
				t.Fatal("reply result changed")
			}
			if scenario != "valid" && scenario != "cancelled" && scenario != "retired" && g.lifetime.Err() == nil {
				t.Fatal("corrupt generation was not retired")
			}
		})
	}
}

func TestTask0GameWireBoundsBeforeBodyAllocation(t *testing.T) {
	for _, scenario := range []string{"short_header", "zero_length", "one_byte", "oversize", "truncated_body", "valid"} {
		t.Run(scenario, func(t *testing.T) {
			var h [4]byte
			binary.BigEndian.PutUint32(h[:], 2)
			body := append(h[:], []byte(`{}`)...)
			switch scenario {
			case "short_header":
				body = body[:3]
			case "zero_length":
				binary.BigEndian.PutUint32(body, 0)
			case "one_byte":
				binary.BigEndian.PutUint32(body, 1)
			case "oversize":
				binary.BigEndian.PutUint32(body, task0GameWireLimit+1)
			case "truncated_body":
				body = body[:5]
			}
			raw, err := task0ReadWire(bytes.NewReader(body))
			if (err == nil) != (scenario == "valid") {
				t.Fatal("framing outcome differs", scenario)
			}
			if err == nil && string(raw) != `{}` {
				t.Fatal("framed bytes changed")
			}
		})
	}
	var out bytes.Buffer
	if task0WriteWire(&out, make([]byte, task0GameWireLimit+1)) == nil || out.Len() != 0 {
		t.Fatal("oversized outgoing frame was written")
	}
}

func TestTask0GameWireCancellationRetiresOnlyOwnedPipe(t *testing.T) {
	serverRead, clientWrite := io.Pipe()
	clientRead, serverWrite := io.Pipe()
	lifetime, cancel := context.WithCancel(context.Background())
	g := &task0PipeGame{lifetime: lifetime, cancel: cancel, input: clientWrite, output: clientRead, serial: make(chan struct{}, 1)}
	g.serial <- struct{}{}
	t.Cleanup(func() { g.retire(); serverRead.Close(); serverWrite.Close() })
	started := make(chan struct{})
	go func() { _, _ = task0ReadWire(serverRead); close(started) }()
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := g.invoke(ctx, "INITIAL", nil); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("fixture request not read")
	}
	stop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stalled reply passed")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation left a blocked exchange")
	}
	if g.lifetime.Err() == nil {
		t.Fatal("cancelled exchange can reuse its generation")
	}
}

func TestTask0GameWireConcurrentOperationsRemainSerialized(t *testing.T) {
	g := task0WireFixture(t, func(raw []byte) []byte { r := task0FixtureReply(); b, _ := json.Marshal(r); return b })
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := g.invoke(context.Background(), "INVARIANT", map[string]any{"state": map[string]bool{"non_canon": true}})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("serialized request failed")
		}
	}
}

func TestTask0GameWireCannotSelectSourceOrExecutable(t *testing.T) {
	g := task0WireFixture(t, func(raw []byte) []byte { r := task0FixtureReply(); b, _ := json.Marshal(r); return b })
	for _, key := range []string{"schema", "operation", "source_binding"} {
		if _, err := g.invoke(context.Background(), "INVARIANT", map[string]any{key: "NON_CANON_SELECTOR"}); err == nil {
			t.Fatal("reserved control field accepted", key)
		}
	}
	if _, err := g.invoke(context.Background(), "EXEC", nil); err == nil {
		t.Fatal("filesystem operation accepted")
	}
	if runtime, err := openTask0CapsuleGame(context.Background(), nil, task0GameRootPolicy{}); runtime != nil || err == nil {
		t.Fatal("unadmitted process launch succeeded")
	}
}
