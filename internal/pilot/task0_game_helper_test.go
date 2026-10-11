package pilot

import (
	"context"
	"encoding/json"
	"testing"
)

func TestTask0GameRelayRejectsControlSubstitutionAndOperationFields(t *testing.T) {
	for _, scenario := range []string{"valid", "missing_source_fields", "wrong_source", "case_alias", "duplicate_operation", "extra_field", "missing_state", "unknown_operation", "trailing_json"} {
		t.Run(scenario, func(t *testing.T) {
			object := map[string]any{"schema": "aipt.private.b007-task0-game-request/v1", "operation": "INVARIANT", "source_binding": task0PrototypeSourceBinding, "state": map[string]any{"NON_CANON": true}}
			switch scenario {
			case "missing_source_fields":
				object["source_binding"] = map[string]any{}
			case "wrong_source":
				source := task0PrototypeSourceBinding
				source.Commit = "NON_CANON_OTHER_SOURCE"
				object["source_binding"] = source
			case "case_alias":
				object["Operation"] = object["operation"]
				delete(object, "operation")
			case "extra_field":
				object["frame"] = map[string]any{}
			case "missing_state":
				delete(object, "state")
			case "unknown_operation":
				object["operation"] = "EXECUTE_HOST_CODE"
			}
			raw, _ := json.Marshal(object)
			if scenario == "duplicate_operation" {
				raw = append(raw[:len(raw)-1], []byte(`,"operation":"INVARIANT"}`)...)
			}
			if scenario == "trailing_json" {
				raw = append(raw, []byte(`{}`)...)
			}
			op, fields, err := task0RelayRequest(raw)
			if (err == nil) != (scenario == "valid") {
				t.Fatal("game relay admission differs", scenario)
			}
			if scenario == "valid" && (op != "INVARIANT" || len(fields) != 1 || fields["state"] == nil) {
				t.Fatal("relay changed accepted operation data")
			}
		})
	}
}

func TestTask0GameHelperRejectsUnboundHostEntryBeforeAnyProcess(t *testing.T) {
	if _, err := launchTask0GameHelper(context.Background(), nil, "", ""); err == nil {
		t.Fatal("unbound game helper launched")
	}
	if RunFrozenTask0Game("") == nil {
		t.Fatal("unbound host entered accepted game runtime")
	}
	if verifyTask0GameChild(nil, nil) == nil {
		t.Fatal("unowned process passed game ownership check")
	}
}
