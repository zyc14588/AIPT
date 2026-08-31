// Versioned resource limits for every caller-controlled JSON value accepted
// by the public Adapter SDK.  The limits are deliberately part of the
// exported contract: callers can size requests deterministically and an
// implementation change cannot silently widen the denial-of-service surface.
//
// Depth is zero-based (the root is depth 0), node count includes containers
// and scalar values, and aggregate bytes count UTF-8 object keys and string
// values plus the canonical scalar spellings.  Schema traversal/ref depth is
// separately bounded because a wide $defs table can encode a deep ref chain
// without a deeply nested JSON container.
export const SDK_JSON_RESOURCE_LIMITS_V1 = Object.freeze({
  identity: 'aipt.adapter-sdk.json-resource-limits/v1',
  max_depth: 64,
  max_nodes: 10_000,
  max_container_width: 10_000,
  max_aggregate_bytes: 4 * 1024 * 1024,
  max_issues: 128,
  max_fixture_documents: 256,
  max_fixture_document_key_bytes: 64 * 1024,
  // A fixture bundle repeatedly traverses the canonical schema and supplied
  // documents while checking digests, schema targets, identity, and semantic
  // compatibility.  These aggregate limits cover the complete bundle call;
  // they are deliberately distinct from the per-JSON-value limits above.
  max_fixture_aggregate_nodes: 250_000,
  max_fixture_aggregate_bytes: 64 * 1024 * 1024,
  max_fixture_semantic_comparisons: 1_024,
  max_schema_traversal_depth: 64,
  max_schema_evaluation_steps: 100_000,
  max_schema_preflight_steps: 100_000,
  // Instance string constraints may revisit the same value through schema
  // combinators.  Cached results are free; every uncached Unicode-length or
  // safe-regex pass charges the input's UTF-16 code-unit length here.  Two
  // complete passes over the largest accepted JSON value remain available.
  max_schema_string_work_code_units: 2 * 4 * 1024 * 1024,
  max_schema_pattern_code_units: 256,
  max_schema_pattern_repetition: 1024,
} as const);

export type SdkJsonResourceLimitsV1 = typeof SDK_JSON_RESOURCE_LIMITS_V1;
