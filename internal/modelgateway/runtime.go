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
	ProfileBinding            string            `json:"profile_binding"`
	ExecutablePath            string            `json:"executable_path"`
	GGUFPath                  string            `json:"gguf_path"`
	AdditionalArguments       []string          `json:"additional_arguments"`
	Environment               map[string]string `json:"environment"`
	WorkingDirectory          string            `json:"working_directory"`
	StartupTimeoutMS          int64             `json:"startup_timeout_ms"`
	ShutdownTimeoutMS         int64             `json:"shutdown_timeout_ms"`
	IsolationExecutablePath   string            `json:"isolation_executable_path"`
	IsolationExecutableSHA256 string            `json:"isolation_executable_sha256"`
	IsolationArguments        []string          `json:"isolation_arguments,omitempty"`
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

func adapterProcessSpec(route AdapterRuntimeRoute) AdapterRouteSpec {
	return AdapterRouteSpec{
		ProfileBinding: route.ProfileBinding, ExecutablePath: route.ExecutablePath,
		ExecutableSHA256: route.ExecutableSHA256, AdapterEntrypointPath: route.AdapterEntrypointPath,
		AdapterEntrypointSHA256: route.AdapterEntrypointSHA256,
		RouteConfigPath:         route.RouteConfigPath, RouteConfigSHA256: route.RouteConfigSHA256,
		Arguments: append([]string(nil), route.Arguments...), Environment: cloneStringMap(route.Environment),
		WorkingDirectory: route.WorkingDirectory,
		StartupTimeout:   time.Duration(route.StartupTimeoutMS) * time.Millisecond,
		ShutdownTimeout:  time.Duration(route.ShutdownTimeoutMS) * time.Millisecond,
	}
}

// RuntimeCoordinator implements the production MODEL and HARNESS launcher
// gates. MODEL validates formal certifications/credentials/assets and starts
// managed local backends. HARNESS then launches only the exact governed ACP
// adapter routes and probes their identities. IPC remains a later gate.
type RuntimeCoordinator struct {
	configPath string
	broker     CredentialBroker

	opMu         sync.Mutex
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
	loadedComplete := false
	defer func() {
		if loadedComplete {
			return
		}
		for _, manager := range localManagers {
			_ = manager.Retire(context.Background())
		}
	}()
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
			if routes[profile.BindingID()].LocalEndpointEnv != "" {
				return nil, newError(CodeHarnessTransport, "validate_runtime_config", profile.BindingID(), errors.New("remote route contains a local endpoint binding"))
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
			StartupTimeout:            time.Duration(item.StartupTimeoutMS) * time.Millisecond,
			ShutdownTimeout:           time.Duration(item.ShutdownTimeoutMS) * time.Millisecond,
			IsolationExecutablePath:   item.IsolationExecutablePath,
			IsolationExecutableSHA256: item.IsolationExecutableSHA256,
			IsolationArguments:        append([]string(nil), item.IsolationArguments...),
		})
		if err != nil {
			return nil, err
		}
		route := routes[profile.BindingID()]
		if !envNameRE.MatchString(route.LocalEndpointEnv) {
			_ = manager.Retire(context.Background())
			return nil, newError(CodeLocalEndpointNotLoopback, "bind_local_harness_route", profile.BindingID(), errors.New("local endpoint environment binding missing"))
		}
		if err := manager.PrepareIsolatedAdapter(adapterProcessSpec(route), route.LocalEndpointEnv); err != nil {
			_ = manager.Retire(context.Background())
			return nil, err
		}
		localManagers[profile.BindingID()] = manager
	}
	if len(routes) != len(config.Profiles) || len(localConfig) != len(localManagers) ||
		!backendSeen[BackendRemoteDeepSeek] || !backendSeen[BackendLocalLlamaCPP] {
		return nil, newError(CodeInvalidProfile, "validate_runtime_config", "", errors.New("closed B004 backend inventory must contain exactly routed REMOTE_DEEPSEEK and LOCAL_LLAMACPP profiles"))
	}
	loadedComplete = true
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
	c.opMu.Lock()
	defer c.opMu.Unlock()
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
	for _, profile := range loaded.config.Profiles {
		manager := loaded.local[profile.BindingID()]
		if manager == nil {
			continue
		}
		if err := manager.Start(ctx); err != nil {
			var cleanupFailures []error
			for index := len(loaded.config.Profiles) - 1; index >= 0; index-- {
				candidate := loaded.local[loaded.config.Profiles[index].BindingID()]
				if candidate != nil {
					if cleanupErr := candidate.Retire(context.Background()); cleanupErr != nil {
						cleanupFailures = append(cleanupFailures, cleanupErr)
					}
				}
			}
			if len(cleanupFailures) > 0 {
				// Preserve the loaded generation so StopModel can retry cleanup;
				// it is deliberately not marked ready for Harness startup.
				c.mu.Lock()
				c.loaded = loaded
				c.modelStarted = false
				c.mu.Unlock()
			}
			return nil, errors.Join(err, errors.Join(cleanupFailures...))
		}
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
	c.opMu.Lock()
	defer c.opMu.Unlock()
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
			manager := loaded.local[profile.BindingID()]
			endpoint, err := manager.Endpoint()
			if err != nil || !IsIPv4LoopbackURL(endpoint) {
				return nil, newError(CodeLocalEndpointNotLoopback, "bind_local_harness_route", profile.BindingID(), err)
			}
			// The URL is meaningful only inside the manager's private network
			// namespace. It is injected there by the isolation supervisor and is
			// deliberately never exposed in the host adapter environment.
		} else if route.LocalEndpointEnv != "" {
			return nil, newError(CodeHarnessTransport, "bind_remote_harness_route", profile.BindingID(), errors.New("remote route contains a local endpoint binding"))
		}
		spec := adapterProcessSpec(route)
		spec.Environment = environment
		if profile.BackendKind == BackendLocalLlamaCPP {
			spec.IsolatedLauncher = loaded.local[profile.BindingID()]
		}
		specs = append(specs, spec)
	}
	transport, err := NewAdapterProcessTransport(loaded.config.Profiles, specs, c.broker)
	if err != nil {
		return nil, err
	}
	for _, profile := range loaded.config.Profiles {
		sampling, err := loaded.registry.Sampling(profile.SamplingProfileID)
		if err != nil {
			cleanupErr := transport.Close(context.Background())
			if cleanupErr != nil {
				c.mu.Lock()
				c.transport = transport
				c.harnessReady = false
				c.mu.Unlock()
			}
			return nil, errors.Join(err, cleanupErr)
		}
		probe, err := transport.Probe(ctx, profile, sampling)
		if err != nil {
			cleanupErr := transport.Close(context.Background())
			if cleanupErr != nil {
				c.mu.Lock()
				c.transport = transport
				c.harnessReady = false
				c.mu.Unlock()
			}
			return nil, errors.Join(err, cleanupErr)
		}
		if err := validateProbe(profile, probe); err != nil {
			cleanupErr := transport.Close(context.Background())
			if cleanupErr != nil {
				c.mu.Lock()
				c.transport = transport
				c.harnessReady = false
				c.mu.Unlock()
			}
			return nil, errors.Join(err, cleanupErr)
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
	c.opMu.Lock()
	defer c.opMu.Unlock()
	return c.stopHarnessLifecycle(ctx)
}

func (c *RuntimeCoordinator) stopHarnessLifecycle(ctx context.Context) error {
	c.mu.Lock()
	transport := c.transport
	c.harnessReady = false
	c.mu.Unlock()
	if transport == nil {
		return nil
	}
	if err := transport.Close(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	if c.transport == transport {
		c.transport = nil
	}
	c.mu.Unlock()
	return nil
}

func (c *RuntimeCoordinator) StopModel(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.opMu.Lock()
	defer c.opMu.Unlock()
	if err := c.stopHarnessLifecycle(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	loaded := c.loaded
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
		if err := manager.Retire(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		// Keep the generation reachable so the caller can retry bounded
		// retirement of any process whose ownership could not yet settle.
		return errors.Join(failures...)
	}
	c.mu.Lock()
	if c.loaded == loaded {
		c.loaded = nil
	}
	c.mu.Unlock()
	return nil
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
