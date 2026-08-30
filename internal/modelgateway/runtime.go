package modelgateway

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"
)

const RuntimeConfigSchema = "aipt.model-runtime-config/v1"

// RuntimeConfig is a private operator configuration. Unlike ModelProfile and
// certification evidence, its process paths are intentionally local and must
// never be copied into a Run Manifest, log, or exported evidence bundle.
type RuntimeConfig struct {
	Schema         string                `json:"schema"`
	Samplings      []SamplingProfile     `json:"samplings"`
	Profiles       []ModelProfile        `json:"profiles"`
	Certifications []Certification       `json:"certifications"`
	LocalRuntimes  []LocalRuntimeConfig  `json:"local_runtimes"`
	AdapterRoutes  []AdapterRuntimeRoute `json:"adapter_routes"`
}

type LocalRuntimeConfig struct {
	ProfileBinding      string            `json:"profile_binding"`
	ExecutablePath      string            `json:"executable_path"`
	GGUFPath            string            `json:"gguf_path"`
	AdditionalArguments []string          `json:"additional_arguments"`
	Environment         map[string]string `json:"environment"`
	WorkingDirectory    string            `json:"working_directory"`
	StartupTimeoutMS    int64             `json:"startup_timeout_ms"`
	ShutdownTimeoutMS   int64             `json:"shutdown_timeout_ms"`
}

type AdapterRuntimeRoute struct {
	ProfileBinding          string            `json:"profile_binding"`
	ExecutablePath          string            `json:"executable_path"`
	ExecutableSHA256        string            `json:"executable_sha256"`
	AdapterEntrypointPath   string            `json:"adapter_entrypoint_path"`
	AdapterEntrypointSHA256 string            `json:"adapter_entrypoint_sha256"`
	RouteConfigPath         string            `json:"route_config_path"`
	RouteConfigSHA256       string            `json:"route_config_sha256"`
	Arguments               []string          `json:"arguments"`
	Environment             map[string]string `json:"environment"`
	WorkingDirectory        string            `json:"working_directory"`
	StartupTimeoutMS        int64             `json:"startup_timeout_ms"`
	ShutdownTimeoutMS       int64             `json:"shutdown_timeout_ms"`
	LocalEndpointEnv        string            `json:"local_endpoint_environment,omitempty"`
}

type loadedRuntime struct {
	config   RuntimeConfig
	registry *Registry
	local    map[string]*ManagedLlama
	routes   map[string]AdapterRuntimeRoute
}

// RuntimeCoordinator implements the production MODEL and HARNESS launcher
// gates. MODEL validates formal certifications/credentials/assets and starts
// managed local backends. HARNESS then launches only the exact governed ACP
// adapter routes and probes their identities. IPC remains a later gate.
type RuntimeCoordinator struct {
	configPath string
	broker     CredentialBroker

	mu           sync.Mutex
	loaded       *loadedRuntime
	transport    *AdapterProcessTransport
	modelStarted bool
	harnessReady bool
}

func NewRuntimeCoordinator(configPath string, broker CredentialBroker) *RuntimeCoordinator {
	return &RuntimeCoordinator{configPath: configPath, broker: broker}
}

func loadRuntimeConfig(ctx context.Context, path string, broker CredentialBroker) (*loadedRuntime, error) {
	if path == "" {
		return nil, newError(CodeInvalidProfile, "load_runtime_config", "", errors.New("runtime config reference is required"))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, newError(CodeInvalidProfile, "load_runtime_config", "", err)
	}
	var config RuntimeConfig
	if err := decodeExact(raw, &config, 4<<20); err != nil {
		return nil, newError(CodeInvalidProfile, "decode_runtime_config", "", err)
	}
	if config.Schema != RuntimeConfigSchema || len(config.Profiles) == 0 ||
		len(config.Samplings) == 0 || len(config.Certifications) == 0 {
		return nil, newError(CodeInvalidProfile, "validate_runtime_config", "", errors.New("complete formal runtime configuration required"))
	}
	registry, err := NewRegistry(config.Samplings, config.Profiles, config.Certifications)
	if err != nil {
		return nil, err
	}
	backendSeen := map[BackendKind]bool{}
	localConfig := make(map[string]LocalRuntimeConfig, len(config.LocalRuntimes))
	for _, item := range config.LocalRuntimes {
		if item.ProfileBinding == "" || localConfig[item.ProfileBinding].ProfileBinding != "" {
			return nil, newError(CodeLocalProcessMismatch, "register_local_runtime", item.ProfileBinding, errors.New("duplicate or empty local runtime binding"))
		}
		localConfig[item.ProfileBinding] = item
	}
	routes := make(map[string]AdapterRuntimeRoute, len(config.AdapterRoutes))
	for _, route := range config.AdapterRoutes {
		if route.ProfileBinding == "" || routes[route.ProfileBinding].ProfileBinding != "" {
			return nil, newError(CodeHarnessTransport, "register_runtime_route", route.ProfileBinding, errors.New("duplicate or empty adapter route binding"))
		}
		routes[route.ProfileBinding] = route
	}
	localManagers := make(map[string]*ManagedLlama, len(localConfig))
	for _, profile := range config.Profiles {
		backendSeen[profile.BackendKind] = true
		if _, exists := routes[profile.BindingID()]; !exists {
			return nil, newError(CodeHarnessTransport, "validate_runtime_routes", profile.BindingID(), errors.New("exact Harness route missing"))
		}
		if profile.BackendKind == BackendRemoteDeepSeek {
			if broker == nil {
				return nil, newError(CodeCredentialUnavailable, "validate_runtime_credential", profile.BindingID(), errors.New("credential broker unavailable"))
			}
			if _, err := broker.Validate(ctx, *profile.CredentialReference); err != nil {
				return nil, err
			}
			if _, exists := localConfig[profile.BindingID()]; exists {
				return nil, newError(CodeLocalProcessMismatch, "validate_runtime_config", profile.BindingID(), errors.New("remote profile has a local process"))
			}
			continue
		}
		item, exists := localConfig[profile.BindingID()]
		if !exists {
			return nil, newError(CodeLocalProcessMismatch, "validate_runtime_config", profile.BindingID(), errors.New("registered local process missing"))
		}
		manager, err := NewManagedLlama(profile, ManagedLlamaSpec{
			ExecutablePath: item.ExecutablePath, GGUFPath: item.GGUFPath,
			AdditionalArguments: append([]string(nil), item.AdditionalArguments...),
			Environment:         cloneStringMap(item.Environment), WorkingDirectory: item.WorkingDirectory,
			StartupTimeout:  time.Duration(item.StartupTimeoutMS) * time.Millisecond,
			ShutdownTimeout: time.Duration(item.ShutdownTimeoutMS) * time.Millisecond,
		})
		if err != nil {
			return nil, err
		}
		localManagers[profile.BindingID()] = manager
	}
	if len(routes) != len(config.Profiles) || len(localConfig) != len(localManagers) ||
		!backendSeen[BackendRemoteDeepSeek] || !backendSeen[BackendLocalLlamaCPP] {
		return nil, newError(CodeInvalidProfile, "validate_runtime_config", "", errors.New("closed B004 backend inventory must contain exactly routed REMOTE_DEEPSEEK and LOCAL_LLAMACPP profiles"))
	}
	return &loadedRuntime{config: config, registry: registry, local: localManagers, routes: routes}, nil
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func (c *RuntimeCoordinator) StartModel(ctx context.Context) (func(context.Context) error, error) {
	if c == nil || ctx == nil {
		return nil, newError(CodeInvalidProfile, "start_model_gate", "", errors.New("coordinator and context required"))
	}
	c.mu.Lock()
	if c.modelStarted || c.loaded != nil {
		c.mu.Unlock()
		return nil, newError(CodeInvalidProfile, "start_model_gate", "", errors.New("MODEL gate already started"))
	}
	c.mu.Unlock()
	loaded, err := loadRuntimeConfig(ctx, c.configPath, c.broker)
	if err != nil {
		return nil, err
	}
	started := make([]*ManagedLlama, 0, len(loaded.local))
	for _, profile := range loaded.config.Profiles {
		manager := loaded.local[profile.BindingID()]
		if manager == nil {
			continue
		}
		if err := manager.Start(ctx); err != nil {
			for index := len(started) - 1; index >= 0; index-- {
				_ = started[index].Stop(context.Background())
			}
			return nil, err
		}
		started = append(started, manager)
	}
	c.mu.Lock()
	c.loaded = loaded
	c.modelStarted = true
	c.mu.Unlock()
	return c.StopModel, nil
}

func (c *RuntimeCoordinator) StartHarness(ctx context.Context) (func(context.Context) error, error) {
	if c == nil || ctx == nil {
		return nil, newError(CodeHarnessTransport, "start_harness_gate", "", errors.New("coordinator and context required"))
	}
	c.mu.Lock()
	if !c.modelStarted || c.loaded == nil || c.harnessReady || c.transport != nil {
		c.mu.Unlock()
		return nil, newError(CodeHarnessTransport, "start_harness_gate", "", errors.New("MODEL gate is not ready or HARNESS already started"))
	}
	loaded := c.loaded
	c.mu.Unlock()

	specs := make([]AdapterRouteSpec, 0, len(loaded.config.Profiles))
	for _, profile := range loaded.config.Profiles {
		route := loaded.routes[profile.BindingID()]
		environment := cloneStringMap(route.Environment)
		if environment == nil {
			environment = map[string]string{}
		}
		if profile.BackendKind == BackendLocalLlamaCPP {
			if !envNameRE.MatchString(route.LocalEndpointEnv) {
				return nil, newError(CodeLocalEndpointNotLoopback, "bind_local_harness_route", profile.BindingID(), errors.New("local endpoint environment binding missing"))
			}
			endpoint, err := loaded.local[profile.BindingID()].Endpoint()
			if err != nil || !IsIPv4LoopbackURL(endpoint) {
				return nil, newError(CodeLocalEndpointNotLoopback, "bind_local_harness_route", profile.BindingID(), err)
			}
			environment[route.LocalEndpointEnv] = endpoint.String()
		} else if route.LocalEndpointEnv != "" {
			return nil, newError(CodeHarnessTransport, "bind_remote_harness_route", profile.BindingID(), errors.New("remote route contains a local endpoint binding"))
		}
		specs = append(specs, AdapterRouteSpec{
			ProfileBinding: route.ProfileBinding, ExecutablePath: route.ExecutablePath,
			ExecutableSHA256: route.ExecutableSHA256, AdapterEntrypointPath: route.AdapterEntrypointPath,
			AdapterEntrypointSHA256: route.AdapterEntrypointSHA256,
			RouteConfigPath:         route.RouteConfigPath, RouteConfigSHA256: route.RouteConfigSHA256,
			Arguments: append([]string(nil), route.Arguments...), Environment: environment,
			WorkingDirectory: route.WorkingDirectory,
			StartupTimeout:   time.Duration(route.StartupTimeoutMS) * time.Millisecond,
			ShutdownTimeout:  time.Duration(route.ShutdownTimeoutMS) * time.Millisecond,
		})
	}
	transport, err := NewAdapterProcessTransport(loaded.config.Profiles, specs, c.broker)
	if err != nil {
		return nil, err
	}
	for _, profile := range loaded.config.Profiles {
		sampling, err := loaded.registry.Sampling(profile.SamplingProfileID)
		if err != nil {
			_ = transport.Close(context.Background())
			return nil, err
		}
		probe, err := transport.Probe(ctx, profile, sampling)
		if err != nil {
			_ = transport.Close(context.Background())
			return nil, err
		}
		if err := validateProbe(profile, probe); err != nil {
			_ = transport.Close(context.Background())
			return nil, err
		}
	}
	c.mu.Lock()
	c.transport = transport
	c.harnessReady = true
	c.mu.Unlock()
	return c.StopHarness, nil
}

func (c *RuntimeCoordinator) StopHarness(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	transport := c.transport
	c.transport = nil
	c.harnessReady = false
	c.mu.Unlock()
	if transport == nil {
		return nil
	}
	return transport.Close(ctx)
}

func (c *RuntimeCoordinator) StopModel(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := c.StopHarness(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	loaded := c.loaded
	c.loaded = nil
	c.modelStarted = false
	c.mu.Unlock()
	if loaded == nil {
		return nil
	}
	var failures []error
	// Stop in exact reverse profile order, mirroring startup. Map iteration is
	// intentionally never used for process lifecycle decisions.
	for index := len(loaded.config.Profiles) - 1; index >= 0; index-- {
		manager := loaded.local[loaded.config.Profiles[index].BindingID()]
		if manager == nil {
			continue
		}
		if err := manager.Stop(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (c *RuntimeCoordinator) Registry() (*Registry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.harnessReady || c.loaded == nil || c.transport == nil {
		return nil, newError(CodeHarnessTransport, "runtime_registry", "", errors.New("Harness runtime not ready"))
	}
	return c.loaded.registry, nil
}

func (c *RuntimeCoordinator) Transport() (HarnessTransport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.harnessReady || c.transport == nil {
		return nil, newError(CodeHarnessTransport, "runtime_transport", "", errors.New("Harness runtime not ready"))
	}
	return c.transport, nil
}

// MarshalRuntimeConfig is intentionally not provided. Private operator paths
// must be supplied locally, and no generic export API should accidentally
// turn this private input into a public artifact.
