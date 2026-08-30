package launcher

// Gate identifies one mandatory launch gate.
type Gate string

const (
	GateConfig     Gate = "CONFIG"
	GatePostgreSQL Gate = "POSTGRESQL"
	GateMigrations Gate = "MIGRATIONS"
	GateModel      Gate = "MODEL"
	GateHarness    Gate = "HARNESS"
	GateCore       Gate = "CORE"
	GateIPC        Gate = "IPC"
	GateWeb        Gate = "WEB"
)

var fixedGateOrder = [...]Gate{
	GateConfig,
	GatePostgreSQL,
	GateMigrations,
	GateModel,
	GateHarness,
	GateCore,
	GateIPC,
	GateWeb,
}

// FixedGateOrder returns a copy of the mandatory order. Callers cannot mutate
// the package-owned order and no launcher option can reorder it.
func FixedGateOrder() []Gate {
	order := make([]Gate, len(fixedGateOrder))
	copy(order, fixedGateOrder[:])
	return order
}

// Implementation describes whether the current construction contains a
// production implementation for a gate. An implemented later gate does not
// permit an earlier mandatory unimplemented gate to be skipped.
type Implementation string

const (
	Implemented    Implementation = "IMPLEMENTED"
	NotImplemented Implementation = "NOT_IMPLEMENTED"
)

// PlanGate is one deterministic machine-readable plan entry.
type PlanGate struct {
	Position       int            `json:"position"`
	Gate           Gate           `json:"gate"`
	Implementation Implementation `json:"implementation"`
}

// LaunchPlan is a declarative plan, never evidence that the runtime started.
type LaunchPlan struct {
	Schema            string     `json:"schema"`
	Gates             []PlanGate `json:"gates"`
	RuntimeReady      bool       `json:"runtime_ready"`
	FirstBlockingGate Gate       `json:"first_blocking_gate"`
}

const planSchema = "aipt.launch.plan/v1"

func productionImplementation(gate Gate) Implementation {
	switch gate {
	case GateConfig, GatePostgreSQL, GateMigrations, GateModel, GateHarness, GateCore, GateWeb:
		return Implemented
	case GateIPC:
		return NotImplemented
	default:
		return NotImplemented
	}
}

// Plan returns the fixed B004 production plan. RuntimeReady is deliberately
// false because IPC is the first mandatory gate without an implementation.
func Plan() LaunchPlan {
	gates := make([]PlanGate, 0, len(fixedGateOrder))
	var firstBlocking Gate
	for index, gate := range fixedGateOrder {
		implementation := productionImplementation(gate)
		gates = append(gates, PlanGate{
			Position:       index + 1,
			Gate:           gate,
			Implementation: implementation,
		})
		if firstBlocking == "" && implementation == NotImplemented {
			firstBlocking = gate
		}
	}
	return LaunchPlan{
		Schema:            planSchema,
		Gates:             gates,
		RuntimeReady:      false,
		FirstBlockingGate: firstBlocking,
	}
}
