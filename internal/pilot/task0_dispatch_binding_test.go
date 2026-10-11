package pilot

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/testplan"
)

func TestTask0DispatchRejectsUncertifiableRequirementsAndForeignCredential(t *testing.T) {
	for _, scenario := range []string{"extra_requirement", "missing_requirement", "duplicate_requirement", "native_output_requirement", "foreign_credential"} {
		t.Run(scenario, func(t *testing.T) {
			b, f := task0DispatchBindingFixture(t)
			p := b.Profiles[0].Profile
			switch scenario {
			case "extra_requirement":
				p.CapabilityRequirements = append(p.CapabilityRequirements, modelgateway.CapabilityTransportStability)
			case "missing_requirement":
				p.CapabilityRequirements = p.CapabilityRequirements[:2]
			case "duplicate_requirement":
				p.CapabilityRequirements[2] = p.CapabilityRequirements[0]
			case "native_output_requirement":
				p.CapabilityRequirements[1] = modelgateway.CapabilityStructuredOutputNative
			case "foreign_credential":
				p.CredentialReference.Locator = "NON_CANON_OTHER_CREDENTIAL"
			}
			bound, err := modelgateway.BindModelProfile(p)
			if err != nil {
				// B004 already rejects some structurally invalid combinations.
				return
			}
			b.Profiles[0].Profile = bound
			m := f.Manifest
			m.CanonicalSHA256 = ""
			m.ModelAssignments[0].ModelProfileID = bound.BindingID()
			f, err = testplan.BindRunManifest(m)
			if err != nil {
				t.Fatal("altered fixture manifest rejected")
			}
			b.ManifestSHA = hex.EncodeToString(f.Digest[:])
			raw, err := json.Marshal(b)
			if err != nil {
				t.Fatal("fixture encoding failed")
			}
			if grant, err := decodeTask0DispatchGrant(raw, inputSHA(raw), f); err == nil || grant != nil {
				t.Fatal("unaccepted dispatch requirements reached construction")
			}
		})
	}
}

func TestTask0DispatchLocalRetirementRejectsConcurrentConstruction(t *testing.T) {
	// Empty fixture transports hold no process, credential, model or FD.
	local := &preparedPilotLocal{grant: &acceptedPilotLocalGrant{}, transport: &modelgateway.AdapterProcessTransport{}}
	var group sync.WaitGroup
	group.Go(func() {
		for count := 0; count < 50; count++ {
			if err := local.retire(); err != nil {
				t.Error("empty fixture retirement failed")
			}
		}
	})
	for count := 0; count < 50; count++ {
		if transport, err := newTask0LocalBudgetTransport(context.Background(), &GlobalBudget{}, local, &acceptedTask0DispatchGrant{}); err == nil || transport != nil {
			t.Fatal("unbound or revoked local fixture reached construction")
		}
	}
	group.Wait()
}
