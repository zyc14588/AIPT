-- AIPT-MVP-B001 authoritative Test Plan Run queue (migration 000002).
--
-- PostgreSQL is the sole queue/lease authority. This forward-only migration
-- adds the Campaign -> Suite -> Case -> Run hierarchy, immutable canonical Run
-- Manifests, deterministic eligibility/selection state, lease generations and
-- append-only Attempt history. It contains no down, force or repair bypass.

CREATE TABLE aipt.playtest_campaigns (
    campaign_id text PRIMARY KEY CHECK (campaign_id <> ''),
    name        text        NOT NULL CHECK (name <> ''),
    created_at  timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE TABLE aipt.playtest_suites (
    suite_id    text PRIMARY KEY CHECK (suite_id <> ''),
    campaign_id text        NOT NULL,
    name        text        NOT NULL CHECK (name <> ''),
    created_at  timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT playtest_suites_campaign_fkey FOREIGN KEY (campaign_id)
        REFERENCES aipt.playtest_campaigns (campaign_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE aipt.playtest_cases (
    case_id    text PRIMARY KEY CHECK (case_id <> ''),
    suite_id   text        NOT NULL,
    name       text        NOT NULL CHECK (name <> ''),
    task_type  text        NOT NULL CONSTRAINT playtest_cases_task_type_check CHECK (task_type IN (
        'SYSTEM_QUALIFICATION', 'RULE', 'PROSE', 'ORACLE',
        'HUMAN_SIMULATION', 'ADVERSARIAL', 'PACKAGE_BUILD',
        'CALIBRATION', 'REGRESSION'
    )),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT playtest_cases_suite_fkey FOREIGN KEY (suite_id)
        REFERENCES aipt.playtest_suites (suite_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
);

-- The digest binds the canonical projection defined by aipt.run-manifest/v1,
-- while manifest_bytes stores the complete canonical document (including its
-- canonical_sha256 field). Exact digest validation also occurs in the Go
-- contract before this insert. No UPDATE/DELETE/TRUNCATE is permitted.
CREATE TABLE aipt.run_manifests (
    manifest_id      text        PRIMARY KEY CHECK (manifest_id <> ''),
    run_id           text        NOT NULL UNIQUE CHECK (run_id <> ''),
    schema_identity  text        NOT NULL CONSTRAINT run_manifests_schema_check CHECK (schema_identity = 'aipt.run-manifest/v1'),
    manifest_bytes   bytea       NOT NULL CHECK (octet_length(manifest_bytes) > 0),
    canonical_sha256 bytea       NOT NULL CONSTRAINT run_manifests_sha256_length_check CHECK (octet_length(canonical_sha256) = 32),
    enqueued_at      timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT run_manifests_identity_pair_key UNIQUE (manifest_id, run_id)
);

CREATE FUNCTION aipt.run_manifests_immutable() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'AIPT_RUN_MANIFEST_IMMUTABLE' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER run_manifests_immutable
    BEFORE UPDATE OR DELETE OR TRUNCATE ON aipt.run_manifests
    FOR EACH STATEMENT
    EXECUTE FUNCTION aipt.run_manifests_immutable();

CREATE TABLE aipt.playtest_runs (
    run_id                    text        PRIMARY KEY CHECK (run_id <> ''),
    manifest_id               text        NOT NULL UNIQUE CHECK (manifest_id <> ''),
    case_id                   text        NOT NULL,
    run_type                  text        NOT NULL CONSTRAINT playtest_runs_type_check CHECK (run_type IN (
        'SYSTEM_QUALIFICATION', 'RULE', 'PROSE', 'ORACLE',
        'HUMAN_SIMULATION', 'ADVERSARIAL', 'PACKAGE_BUILD',
        'CALIBRATION', 'REGRESSION'
    )),
    classification            text        NOT NULL CONSTRAINT playtest_runs_classification_check CHECK (classification IN ('QUALIFICATION', 'DIAGNOSTIC')),
    qualification_eligible    boolean     NOT NULL,
    priority_class            text        NOT NULL CONSTRAINT playtest_runs_priority_check CHECK (priority_class IN (
        'RELEASE', 'HOTFIX', 'MILESTONE', 'SYSTEM',
        'CALIBRATION', 'EXPLORATORY', 'BACKGROUND'
    )),
    required_resource_id      text        NOT NULL CHECK (required_resource_id <> ''),
    required_model_id         text        NOT NULL CHECK (required_model_id <> ''),
    required_certification_id text        NOT NULL CHECK (required_certification_id <> ''),
    required_labels           text[]      NOT NULL DEFAULT ARRAY[]::text[],
    status                    text        NOT NULL DEFAULT 'QUEUED' CONSTRAINT playtest_runs_status_check CHECK (status IN ('QUEUED', 'LEASED', 'COMPLETED', 'CANCELED')),
    eligible_after            timestamptz NOT NULL DEFAULT statement_timestamp(),
    queued_at                 timestamptz NOT NULL DEFAULT statement_timestamp(),
    created_at                timestamptz NOT NULL DEFAULT statement_timestamp(),
    completed_at              timestamptz,
    canceled_at               timestamptz,
    cancel_reason             text,
    CONSTRAINT playtest_runs_classification_eligibility_check CHECK (
        (classification = 'QUALIFICATION' AND qualification_eligible)
        OR (classification = 'DIAGNOSTIC' AND NOT qualification_eligible)
    ),
    CONSTRAINT playtest_runs_case_fkey FOREIGN KEY (case_id)
        REFERENCES aipt.playtest_cases (case_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT playtest_runs_manifest_fkey FOREIGN KEY (manifest_id, run_id)
        REFERENCES aipt.run_manifests (manifest_id, run_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT playtest_runs_terminal_time_check CHECK (
        (status = 'COMPLETED' AND completed_at IS NOT NULL AND canceled_at IS NULL)
        OR (status = 'CANCELED' AND canceled_at IS NOT NULL AND completed_at IS NULL)
        OR (status IN ('QUEUED', 'LEASED') AND completed_at IS NULL AND canceled_at IS NULL)
    )
);

-- Run identity, ancestry, Manifest binding and selection contract are frozen
-- after enqueue. Only lifecycle columns may change.
CREATE FUNCTION aipt.playtest_runs_identity_immutable() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.run_id IS DISTINCT FROM NEW.run_id
       OR OLD.manifest_id IS DISTINCT FROM NEW.manifest_id
       OR OLD.case_id IS DISTINCT FROM NEW.case_id
       OR OLD.run_type IS DISTINCT FROM NEW.run_type
       OR OLD.classification IS DISTINCT FROM NEW.classification
       OR OLD.qualification_eligible IS DISTINCT FROM NEW.qualification_eligible
       OR OLD.priority_class IS DISTINCT FROM NEW.priority_class
       OR OLD.required_resource_id IS DISTINCT FROM NEW.required_resource_id
       OR OLD.required_model_id IS DISTINCT FROM NEW.required_model_id
       OR OLD.required_certification_id IS DISTINCT FROM NEW.required_certification_id
       OR OLD.required_labels IS DISTINCT FROM NEW.required_labels
       OR OLD.eligible_after IS DISTINCT FROM NEW.eligible_after
       OR OLD.queued_at IS DISTINCT FROM NEW.queued_at
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'AIPT_RUN_IDENTITY_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER playtest_runs_identity_immutable
    BEFORE UPDATE ON aipt.playtest_runs
    FOR EACH ROW
    EXECUTE FUNCTION aipt.playtest_runs_identity_immutable();

CREATE TABLE aipt.run_dependencies (
    run_id            text NOT NULL,
    depends_on_run_id text NOT NULL,
    CONSTRAINT run_dependencies_pkey PRIMARY KEY (run_id, depends_on_run_id),
    CONSTRAINT run_dependencies_not_self CHECK (run_id <> depends_on_run_id),
    CONSTRAINT run_dependencies_run_fkey FOREIGN KEY (run_id)
        REFERENCES aipt.playtest_runs (run_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT run_dependencies_predecessor_fkey FOREIGN KEY (depends_on_run_id)
        REFERENCES aipt.playtest_runs (run_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
);

-- A single row serializes queue-level acquisition and expresses the supported
-- pause boundary. It pauses new claims only. Manual pause/resume of an active
-- formal Run is intentionally absent; diagnostic pause remains executor-level
-- UNSUPPORTED in B001 and cannot create qualification evidence.
CREATE TABLE aipt.playtest_queue_control (
    control_id  text        PRIMARY KEY CONSTRAINT playtest_queue_control_singleton_check CHECK (control_id = 'GLOBAL'),
    paused      boolean     NOT NULL DEFAULT false,
    pause_scope text        NOT NULL DEFAULT 'QUEUE_ONLY' CONSTRAINT playtest_queue_pause_scope_check CHECK (pause_scope = 'QUEUE_ONLY'),
    reason      text,
    updated_at  timestamptz NOT NULL DEFAULT statement_timestamp()
);

INSERT INTO aipt.playtest_queue_control (control_id) VALUES ('GLOBAL');

CREATE TABLE aipt.run_leases (
    lease_id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id         text        NOT NULL,
    generation     bigint      NOT NULL CHECK (generation > 0),
    holder_id      text        NOT NULL CHECK (holder_id <> ''),
    token_sha256   bytea       NOT NULL UNIQUE CONSTRAINT run_leases_token_sha256_length_check CHECK (octet_length(token_sha256) = 32),
    formal_slot    smallint    CONSTRAINT run_leases_formal_slot_check CHECK (formal_slot IS NULL OR formal_slot = 1),
    status         text        NOT NULL CONSTRAINT run_leases_status_check CHECK (status IN ('ACTIVE', 'EXPIRED', 'RELEASED', 'COMPLETED')),
    acquired_at    timestamptz NOT NULL DEFAULT statement_timestamp(),
    heartbeat_at   timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at     timestamptz NOT NULL,
    ended_at       timestamptz,
    CONSTRAINT run_leases_generation_key UNIQUE (run_id, generation),
    CONSTRAINT run_leases_run_fkey FOREIGN KEY (run_id)
        REFERENCES aipt.playtest_runs (run_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT run_leases_time_check CHECK (expires_at > acquired_at),
    CONSTRAINT run_leases_end_state_check CHECK (
        (status = 'ACTIVE' AND ended_at IS NULL)
        OR (status <> 'ACTIVE' AND ended_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX run_leases_one_active_per_run
    ON aipt.run_leases (run_id) WHERE status = 'ACTIVE';

-- This database constraint is the GLOBAL_WIP=1 authority for formal Runs.
-- Diagnostics have NULL formal_slot and remain qualification-ineligible.
CREATE UNIQUE INDEX run_leases_one_active_formal_slot
    ON aipt.run_leases (formal_slot)
    WHERE status = 'ACTIVE' AND formal_slot = 1;

CREATE INDEX run_leases_active_expiry
    ON aipt.run_leases (expires_at, lease_id) WHERE status = 'ACTIVE';

CREATE TABLE aipt.run_attempts (
    run_id         text        NOT NULL,
    attempt_number bigint      NOT NULL CHECK (attempt_number > 0),
    attempt_id     text        NOT NULL UNIQUE CHECK (attempt_id <> ''),
    attempt_kind   text        NOT NULL CONSTRAINT run_attempts_kind_check CHECK (attempt_kind IN ('NEW_RUN', 'SAME_RUN_RECOVERY', 'ATTEMPT')),
    outcome        text        NOT NULL CONSTRAINT run_attempts_outcome_check CHECK (outcome IN ('STARTED', 'FAILED', 'SUCCEEDED', 'CANCELED')),
    evidence_sha256 bytea      CONSTRAINT run_attempts_evidence_sha256_length_check CHECK (evidence_sha256 IS NULL OR octet_length(evidence_sha256) = 32),
    recorded_at    timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT run_attempts_pkey PRIMARY KEY (run_id, attempt_number),
    CONSTRAINT run_attempts_run_fkey FOREIGN KEY (run_id)
        REFERENCES aipt.playtest_runs (run_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE FUNCTION aipt.run_attempts_append_only() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'AIPT_RUN_ATTEMPT_APPEND_ONLY' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER run_attempts_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON aipt.run_attempts
    FOR EACH STATEMENT
    EXECUTE FUNCTION aipt.run_attempts_append_only();

-- Fixed deterministic priority ranks: Release, Hotfix, Milestone, System,
-- Calibration, Exploratory, Background. Every production selector repeats
-- this CASE then queued_at ASC and run_id COLLATE "C" ASC as the final tie.
CREATE FUNCTION aipt.playtest_priority_rank(p_priority text) RETURNS integer
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
RETURN CASE p_priority
    WHEN 'RELEASE' THEN 10
    WHEN 'HOTFIX' THEN 20
    WHEN 'MILESTONE' THEN 30
    WHEN 'SYSTEM' THEN 40
    WHEN 'CALIBRATION' THEN 50
    WHEN 'EXPLORATORY' THEN 60
    WHEN 'BACKGROUND' THEN 70
    ELSE 2147483647
END;

CREATE INDEX playtest_runs_deterministic_queue_order
    ON aipt.playtest_runs (
        aipt.playtest_priority_rank(priority_class),
        queued_at ASC,
        run_id COLLATE "C" ASC
    ) WHERE status = 'QUEUED';
