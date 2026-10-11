package pilot

import (
	"context"
	"encoding/json"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/protocol"
)

// The fixed Harness worker returns its original agent-response/v1 envelope.
// The Task0 frame is data inside speech; an optional provider action never
// receives mutation authority. This preserves the existing worker/bundle
// identities and lets the trusted B003 adapter construct the Core proposal.
type task0FrameGateway struct{ upstream orchestrator.AgentInvoker }

func task0ModelFrameGateway(g *modelgateway.Gateway) (*task0FrameGateway, error) {
	if g == nil {
		return nil, ErrTask0
	}
	return &task0FrameGateway{upstream: g}, nil
}

func (g *task0FrameGateway) Invoke(ctx context.Context, session orchestrator.Session, invocation orchestrator.InvocationRequest) (orchestrator.InvocationResult, error) {
	fail := func() (orchestrator.InvocationResult, error) {
		return orchestrator.InvocationResult{}, orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
	}
	if g == nil || g.upstream == nil || ctx == nil || ctx.Err() != nil || invocation.Kind != orchestrator.InvocationOriginal || invocation.Attempt != 1 ||
		orchestrator.ValidateContextHash(invocation.Context) != nil {
		return fail()
	}
	turn, ok := ctx.Value(task0TurnKey{}).(task0AuthenticatedTurn)
	actor, valid := task0Actor(turn.seat)
	if !ok || !valid || turn.seat != session.SeatID || turn.seat != invocation.SeatID || turn.runID != session.RunID || turn.runID != invocation.RunID ||
		session.Schema != orchestrator.SessionSchema || session.Generation != 1 || session.SessionID != invocation.SessionID ||
		invocation.Context.SeatID != turn.seat || invocation.Context.RunID != turn.runID || invocation.Context.SessionID != session.SessionID {
		return fail()
	}
	result, err := g.upstream.Invoke(ctx, session, invocation)
	if err != nil {
		return orchestrator.InvocationResult{}, err
	}
	var outer orchestrator.AgentResponse
	if ctx.Err() != nil || decodeFrozenJSON(result.Response, MaxOutputPerAttempt, &outer) != nil || outer.Schema != orchestrator.AgentResponseSchema ||
		outer.InvocationID != invocation.InvocationID || outer.RunID != turn.runID || outer.SeatID != turn.seat || outer.SessionID != session.SessionID ||
		outer.Metadata.ProtocolVersion != "v1" || outer.Metadata.SpeechActionClaim != nil || outer.Action != nil {
		return fail()
	}
	var frame task0Frame
	if decodeFrozenJSON([]byte(outer.Speech), MaxOutputPerAttempt, &frame) != nil || frame.ActorID != actor || len(frame.Payload) < 2 || len(frame.Payload) > 1024 {
		return fail()
	}
	canonical, err := protocol.CanonicalJSON([]byte(outer.Speech))
	if err != nil {
		return fail()
	}
	result.Response = json.RawMessage(canonical)
	return result, nil
}

func (g *task0FrameGateway) Recover(context.Context, orchestrator.Session, orchestrator.RecoveryRequest) (orchestrator.Session, error) {
	return orchestrator.Session{}, orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
}
