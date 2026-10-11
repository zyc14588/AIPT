package pilot

import (
	"context"
	"testing"
)

// These admission negatives own no processes and make no calls. An empty or
// conflicting ownership record must fail before any kernel or database use.
// Real delegated GAME admission is verified by the private production-entry
// integration fixture; these records never stand in for a positive process.
func TestTask0TableRejectsIncompleteGameOwnership(t *testing.T) {
	for _, scenario := range []string{"nil_game", "nil_wire", "nil_lifetime", "cancelled_lifetime", "nil_transport", "nil_grant", "closed_transport", "no_process", "nil_owner", "wrong_role", "conflicting_owners", "closed_owner", "joined_owner", "missing_kernel_process"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			owner := &task0SetupClient{process: &freshPreparationProcess{exit: make(chan struct{})}, grant: &acceptedTask0Setup{}}
			game := &task0OwnedGameHelper{wire: &task0PipeGame{lifetime: ctx}, delegated: &task0DelegatedProcess{owner: owner, role: task0SetupRole{Role: "GAME"}}}
			grant := &acceptedTask0DispatchGrant{}
			remote := &task0FrozenRemoteTransport{lifetime: ctx, setup: owner, grant: grant}
			transport := &task0BudgetTransport{grant: grant, upstream: remote}
			switch scenario {
			case "nil_game":
				game = nil
			case "nil_wire":
				game.wire = nil
			case "nil_lifetime":
				game.wire.lifetime = nil
			case "cancelled_lifetime":
				cancel()
			case "nil_transport":
				transport = nil
			case "nil_grant":
				transport.grant = nil
			case "closed_transport":
				transport.closed = true
			case "no_process":
				game.delegated = nil
			case "nil_owner":
				game.delegated.owner = nil
			case "wrong_role":
				game.delegated.role.Role = "GM"
			case "conflicting_owners":
				game.process = &freshPreparationProcess{}
			case "closed_owner":
				owner.closed = true
			case "joined_owner":
				close(owner.process.exit)
			}
			if task0TableGameOwnership(game, transport) == nil {
				t.Fatal("incomplete ownership admitted", scenario)
			}
		})
	}
}
