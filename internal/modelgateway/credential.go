package modelgateway

import (
	"context"
	"errors"
	"os"
	"strings"
)

// CredentialBroker exposes write-only process binding. Validation returns
// only reference metadata; BindChildEnvironment is the sole secret-bearing
// path and its result must be passed directly to exec.Cmd.Env.
type CredentialBroker interface {
	Validate(context.Context, CredentialReference) (CredentialValidation, error)
	BindChildEnvironment(context.Context, CredentialReference, map[string]string) (map[string]string, error)
}

// EnvironmentCredentialBroker implements the first B004 credential provider.
// It reads one explicitly named environment variable and maps it to the exact
// child variable expected by the governed Harness. It never logs or stores the
// value and never includes it in validation metadata.
type EnvironmentCredentialBroker struct {
	Lookup func(string) (string, bool)
}

func (b EnvironmentCredentialBroker) lookup(name string) (string, bool) {
	if b.Lookup != nil {
		return b.Lookup(name)
	}
	return os.LookupEnv(name)
}

func (b EnvironmentCredentialBroker) Validate(_ context.Context, reference CredentialReference) (CredentialValidation, error) {
	if err := validateCredentialReference(reference); err != nil {
		return CredentialValidation{}, newError(CodeCredentialPolicy, "validate_credential", reference.ReferenceID, err)
	}
	if reference.Kind != CredentialEnvironment {
		return CredentialValidation{}, newError(CodeCredentialPolicy, "validate_credential", reference.ReferenceID, errors.New("encrypted file references require an injected decrypting broker"))
	}
	value, present := b.lookup(reference.Locator)
	if !present || value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return CredentialValidation{}, newError(CodeCredentialUnavailable, "validate_credential", reference.ReferenceID, errors.New("credential reference is unavailable"))
	}
	return CredentialValidation{
		ReferenceID: reference.ReferenceID, Kind: reference.Kind, State: "VALID",
		Metadata: map[string]string{"source": "environment", "exposure": "write-only"},
	}, nil
}

func (b EnvironmentCredentialBroker) BindChildEnvironment(ctx context.Context, reference CredentialReference, base map[string]string) (map[string]string, error) {
	if _, err := b.Validate(ctx, reference); err != nil {
		return nil, err
	}
	value, _ := b.lookup(reference.Locator)
	result := make(map[string]string, len(base)+1)
	for key, item := range base {
		if secretRE.MatchString(key) || strings.HasPrefix(key, "DSH_") || key == "DEEPSEEK_API_KEY" {
			continue
		}
		result[key] = item
	}
	result["DEEPSEEK_API_KEY"] = value
	return result, nil
}

func allowlistedBaseEnvironment(source map[string]string) map[string]string {
	result := map[string]string{}
	for _, name := range []string{"LANG", "LC_ALL", "TZ", "PATH"} {
		if value, ok := source[name]; ok && value != "" && !strings.ContainsRune(value, 0) {
			result[name] = value
		}
	}
	return result
}
