// Package modelgateway binds the provider-neutral B003 AgentInvoker boundary
// to a governed external Harness runtime.  It owns model/sampling profiles,
// execution identity, egress enforcement, bounded context preparation,
// credential references, Harness protocol validation, and local llama.cpp
// lifecycle controls.  It never mutates Run Core state and never calls a
// provider or llama.cpp inference endpoint directly.
package modelgateway
