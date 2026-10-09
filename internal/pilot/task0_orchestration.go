package pilot

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/runcore"
)

// B003 wire actors are its authenticated seat IDs. Game actors are the
// accepted character IDs. Only this bounded trusted adapter translates
// between them; provider frames retain the three accepted game fields.
type task0B003Invoker struct {
	upstream orchestrator.AgentInvoker
	run      *runcore.Run
	kernel   *task0KernelCore
}

func (i *task0B003Invoker) Invoke(ctx context.Context, session orchestrator.Session, invocation orchestrator.InvocationRequest) (orchestrator.InvocationResult, error) {
	fail := func() (orchestrator.InvocationResult, error) {
		return orchestrator.InvocationResult{}, orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
	}
	if i == nil || i.upstream == nil || i.run == nil || i.kernel == nil || ctx == nil || ctx.Err() != nil ||
		invocation.Kind != orchestrator.InvocationOriginal || invocation.Attempt != 1 || orchestrator.ValidateContextHash(invocation.Context) != nil {
		return fail()
	}
	turn, ok := ctx.Value(task0TurnKey{}).(task0AuthenticatedTurn)
	if !ok || turn.seat != invocation.SeatID || turn.seat != session.SeatID || turn.runID != invocation.RunID || turn.runID != session.RunID ||
		session.Schema != orchestrator.SessionSchema || session.SessionID != invocation.SessionID || session.Generation != 1 ||
		invocation.Context.SeatID != turn.seat || invocation.Context.RunID != turn.runID || invocation.Context.SessionID != session.SessionID {
		return fail()
	}
	before := i.run.State()
	if before.Binding != i.kernel.binding || before.Binding.RunID != turn.runID || before.Sequence != turn.sequence {
		return fail()
	}
	result, err := i.upstream.Invoke(ctx, session, invocation)
	if err != nil {
		return orchestrator.InvocationResult{}, err
	}
	if ctx.Err() != nil || i.run.State().Sequence != before.Sequence || len(result.Response) > MaxOutputPerAttempt {
		return fail()
	}
	proposal, err := i.kernel.normalizeFrame(ctx, before, result.Response)
	if err != nil {
		return fail()
	}
	// Identity and protocol envelopes originate from the trusted invocation,
	// never from the provider's JSON. No provider speech/action claim is used.
	proposal.ActorID = string(turn.seat)
	response := orchestrator.AgentResponse{Schema: orchestrator.AgentResponseSchema, InvocationID: invocation.InvocationID,
		RunID: turn.runID, SeatID: turn.seat, SessionID: session.SessionID, Action: &proposal,
		Metadata: orchestrator.ProtocolMetadata{ProtocolVersion: "v1"}}
	raw, err := json.Marshal(response)
	if err != nil {
		return fail()
	}
	return orchestrator.InvocationResult{Response: raw, CompletedAt: result.CompletedAt}, nil
}

func (i *task0B003Invoker) Recover(context.Context, orchestrator.Session, orchestrator.RecoveryRequest) (orchestrator.Session, error) {
	// The accepted pilot consumes no implicit retry or recovery call.
	return orchestrator.Session{}, orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
}

type task0B003Submitter struct {
	run    *runcore.Run
	kernel *task0KernelCore
}

func (s task0B003Submitter) Submit(ctx context.Context, proposal runcore.ActionProposal) (runcore.Receipt, error) {
	if s.run == nil || s.kernel == nil || ctx == nil || ctx.Err() != nil {
		return runcore.Receipt{}, ErrTask0
	}
	turn, ok := ctx.Value(task0TurnKey{}).(task0AuthenticatedTurn)
	actor, valid := task0Actor(turn.seat)
	if !ok || !valid || proposal.ActorID != string(turn.seat) || proposal.RNGRequests == nil || proposal.TemporaryRuling != nil {
		return runcore.Receipt{}, ErrTask0
	}
	proposal.ActorID = actor
	proposal.Payload = slices.Clone(proposal.Payload)
	proposal.RNGRequests = slices.Clone(proposal.RNGRequests)
	if s.kernel.authorize(ctx, s.run.State(), proposal) != nil {
		return runcore.Receipt{}, ErrTask0
	}
	raw, err := json.Marshal(proposal)
	if err != nil {
		return runcore.Receipt{}, ErrTask0
	}
	// Preserve explicit empty arrays. The frozen predecessor B003 submitter
	// normalizes empty RNG requests to null, which is not the new game wire
	// contract. This additive route still commits solely through Run Core.
	return s.run.Execute(ctx, raw)
}
