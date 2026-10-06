package runcontrol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRPCFramingRejectsUnboundedAndAmbiguousHeaders(t *testing.T) {
	cases := []string{"Content-Length: 0\r\n\r\n", "Content-Length: 1048577\r\n\r\n", "Content-Length: 01\r\n\r\nx", "Content-Length: +1\r\n\r\nx", "Content-Length: 1\n\nx", "content-length: 1\r\n\r\nx", "Content-Length: 1\r\nX: y\r\n\r\nx", "Content-Length: " + strings.Repeat("9", 5000) + "\r\n\r\n", "Content-Length: 3\r\n\r\n{}"}
	for i, raw := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := readFrame(bufio.NewReaderSize(strings.NewReader(raw), 4096)); err == nil {
				t.Fatal("bad framing accepted")
			}
		})
	}
}
func TestRPCSharesServiceAndJoinsIdleOrBlockedStreams(t *testing.T) {
	q := newTestQueue()
	s := testService(t, q, nil, nil, definition(t, "run-a", false))
	reader, requestWriter := io.Pipe()
	responseReader, writer := io.Pipe()
	rpc, err := StartRPC(context.Background(), reader, writer, s)
	if err != nil {
		t.Fatal(err)
	}
	defer requestWriter.Close()
	defer responseReader.Close()
	raw := []byte(`{"jsonrpc":"2.0","protocol_version":1,"id":"rpc-a","method":"aipt.v1.queue.pause","params":{"paused":true}}`)
	sent := make(chan error, 1)
	go func() {
		_, err := fmt.Fprintf(requestWriter, "Content-Length: %d\r\n\r\n%s", len(raw), raw)
		sent <- err
	}()
	encoded, err := readFrame(bufio.NewReader(responseReader))
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(encoded, &response); err != nil || response.Error != nil {
		t.Fatalf("RPC failed: %s %v", encoded, err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.Snapshot(context.Background(), 100)
	if err != nil || !snapshot.Paused {
		t.Fatal("stdio wrote a different service")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rpc.Stop(ctx); err != nil {
		t.Fatal("idle RPC read was not joined")
	}
	// A client that stops draining output must also be synchronously stopped.
	reader2, input2 := io.Pipe()
	output2, writer2 := io.Pipe()
	defer input2.Close()
	defer output2.Close()
	rpc2, err := StartRPC(context.Background(), reader2, writer2, s)
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan struct{})
	go func() { _, _ = fmt.Fprintf(input2, "Content-Length: %d\r\n\r\n%s", len(raw), raw); close(written) }()
	<-written
	if err := rpc2.Stop(ctx); err != nil {
		t.Fatal("blocked RPC response was not joined")
	}
}
func TestStrictJSONDuplicateDeepAndTrailingRejections(t *testing.T) {
	for _, raw := range []string{`{"a":{"b":1,"b":2}}`, `{"a":1,"A":1}`, `{"a":null}x`, `null`, `[]`, strings.Repeat(`{"a":`, 40) + `1` + strings.Repeat(`}`, 40), string([]byte{'{', '"', 'a', '"', ':', '"', 0xff, '"', '}'})} {
		var v struct {
			A int `json:"a"`
		}
		if err := DecodeObject([]byte(raw), &v, "a"); err == nil {
			t.Fatalf("unsafe JSON accepted: %q", raw)
		}
	}
	var empty struct{}
	if err := DecodeObject([]byte(`{}`), &empty); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := DecodeObject([]byte(`{"a":{"b":[1,2]}}`), &value, "a"); err != nil {
		t.Fatal(err)
	}
}
func TestRPCResponseRedactsPrivateCauses(t *testing.T) {
	if code := PublicCode(fmt.Errorf("postgresql://private:password@host/db /private/path hidden prompt")); code != ErrUnavailable.Error() {
		t.Fatal("private error exposed")
	}
	q := newTestQueue()
	s := testService(t, q, nil, nil)
	response := s.Respond(context.Background(), []byte(`{"jsonrpc":"2.0","protocol_version":1,"id":"rpc-a","method":"aipt.v1.report.export","params":{"run_id":"run-a","format":"../../credential"}}`))
	data, _ := json.Marshal(response)
	if bytes.Contains(data, []byte("credential")) {
		t.Fatal("caller values exposed in error")
	}
}
