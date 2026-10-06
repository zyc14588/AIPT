package runcontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Request deliberately supports string IDs only, no batches/notifications.
// Both transports use this exact versioned, strict request envelope.
type Request struct {
	JSONRPC         string          `json:"jsonrpc"`
	ProtocolVersion int             `json:"protocol_version"`
	ID              string          `json:"id"`
	Method          string          `json:"method"`
	Params          json.RawMessage `json:"params"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type Response struct {
	JSONRPC         string    `json:"jsonrpc"`
	ProtocolVersion int       `json:"protocol_version"`
	ID              *string   `json:"id"`
	Result          any       `json:"result,omitempty"`
	Error           *RPCError `json:"error,omitempty"`
}

func DecodeRequest(raw []byte) (Request, error) {
	var request Request
	if err := DecodeObject(raw, &request, "jsonrpc", "protocol_version", "id", "method", "params"); err != nil {
		return Request{}, err
	}
	if request.JSONRPC != "2.0" || request.ProtocolVersion != 1 || !identityPattern.MatchString(request.ID) || len(request.ID) > 64 || len(request.Method) > 64 {
		return Request{}, ErrInvalid
	}
	if err := DecodeObject(request.Params, &map[string]any{}, objectKeys(request.Params)...); err != nil {
		return Request{}, ErrInvalid
	}
	return request, nil
}
func objectKeys(raw []byte) []string {
	var value map[string]json.RawMessage
	_ = json.Unmarshal(raw, &value)
	keys := []string{}
	for key := range value {
		keys = append(keys, key)
	}
	return keys
}
func (s *Service) Respond(ctx context.Context, raw []byte) Response {
	request, err := DecodeRequest(raw)
	response := Response{JSONRPC: "2.0", ProtocolVersion: 1}
	if err != nil {
		response.Error = &RPCError{Code: -32600, Message: PublicCode(err)}
		return response
	}
	response.ID = &request.ID
	result, err := s.Invoke(ctx, request.Method, request.Params)
	if err != nil {
		code := -32000
		if err == ErrUnknownMethod {
			code = -32601
		}
		if err == ErrInvalid {
			code = -32602
		}
		response.Error = &RPCError{Code: code, Message: PublicCode(err)}
	} else {
		response.Result = result
	}
	return response
}

// RPC owns both stream endpoints. Stop closes them before joining, so a
// blocked header read or response write cannot leave an orphan goroutine.
type RPC struct {
	input  io.ReadCloser
	output io.WriteCloser
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func StartRPC(ctx context.Context, input io.ReadCloser, output io.WriteCloser, service *Service) (*RPC, error) {
	if ctx == nil || ctx.Err() != nil || input == nil || output == nil || service == nil {
		return nil, ErrInvalid
	}
	lifetime, cancel := context.WithCancel(ctx)
	rpc := &RPC{input: input, output: output, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(rpc.done)
		defer rpc.close()
		reader := bufio.NewReaderSize(input, 4096)
		for {
			body, err := readFrame(reader)
			if err != nil {
				return
			}
			requestCtx, stop := context.WithTimeout(lifetime, 10*time.Second)
			response := service.Respond(requestCtx, body)
			stop()
			encoded, err := json.Marshal(response)
			if err != nil {
				return
			}
			if err := writeAll(output, []byte(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(encoded)))); err != nil {
				return
			}
			if err := writeAll(output, encoded); err != nil {
				return
			}
			if lifetime.Err() != nil {
				return
			}
		}
	}()
	go func() {
		select {
		case <-lifetime.Done():
			rpc.close()
		case <-rpc.done:
		}
	}()
	return rpc, nil
}
func (r *RPC) close() { r.once.Do(func() { r.cancel(); _ = r.input.Close(); _ = r.output.Close() }) }
func (r *RPC) Stop(ctx context.Context) error {
	r.close()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ErrUnavailable
	}
}
func (r *RPC) Done() <-chan struct{} { return r.done }
func readFrame(reader *bufio.Reader) ([]byte, error) {
	// A single exact header keeps framing bounded before allocating the body.
	header, err := reader.ReadSlice('\n')
	if err != nil || len(header) > 80 || !strings.HasSuffix(string(header), "\r\n") {
		return nil, ErrInvalid
	}
	line := strings.TrimSuffix(string(header), "\r\n")
	if !strings.HasPrefix(line, "Content-Length: ") {
		return nil, ErrInvalid
	}
	text := strings.TrimPrefix(line, "Content-Length: ")
	size, err := strconv.Atoi(text)
	if err != nil || size < 1 || size > MaxRequestBytes || strconv.Itoa(size) != text {
		return nil, ErrInvalid
	}
	blank, err := reader.ReadSlice('\n')
	if err != nil || string(blank) != "\r\n" {
		return nil, ErrInvalid
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, ErrInvalid
	}
	return body, nil
}
func writeAll(writer io.Writer, body []byte) error {
	for len(body) > 0 {
		n, err := writer.Write(body)
		if err != nil {
			return err
		}
		if n < 1 || n > len(body) {
			return io.ErrShortWrite
		}
		body = body[n:]
	}
	return nil
}
