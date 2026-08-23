package web

import (
	"errors"

	"github.com/zyc14588/AIPT/internal/config"
)

var ErrInvalidConfig = errors.New("AIPT_WEB_INVALID_CONFIG")

// ConfigHealth projects the already validated shared Config into the Web
// read model. It deliberately selects only non-credential accessors.
func ConfigHealth(validated *config.Config) (ConfigPanel, HealthPanel, error) {
	if validated == nil {
		return ConfigPanel{}, HealthPanel{}, ErrInvalidConfig
	}
	database := validated.Database()
	evidence := validated.Evidence()
	configPanel := ConfigPanel{
		Schema:            validated.Schema(),
		Profile:           validated.Profile().String(),
		DatabaseIdentity:  database.Identity(),
		DatabaseNamespace: database.Namespace(),
		EvidenceNamespace: evidence.Namespace(),
	}
	healthPanel := HealthPanel{
		ServingStatus:    StatusServing,
		RuntimeReadiness: ReadinessNotAsserted,
	}
	return configPanel, healthPanel, nil
}
