-- AIPT ledger schema (migration 000001).
--
-- This migration creates the append-only ledger storage contract:
--
--   * aipt.ledger_event_hash_v1       -- versioned event-hash function that
--                                       reproduces the hash.go preimage layout
--                                       byte for byte;
--   * aipt.ledger_streams             -- one row per stream carrying the append
--                                       cursor (last_sequence, last_event_hash);
--   * aipt.ledger_events              -- the append-only event chain;
--   * aipt.ledger_events_append_only  -- statement-level BEFORE trigger that
--                                       rejects every UPDATE/DELETE/TRUNCATE of
--                                       aipt.ledger_events -- including
--                                       zero-row statements -- with the stable
--                                       code AIPT_LEDGER_APPEND_ONLY and
--                                       SQLSTATE 55000.
--
-- The aipt schema and the runner metadata table aipt.schema_migrations are
-- created by the migration runner bootstrap before this file runs. This file
-- needs no extension: sha256(bytea) and convert_to(text, text) are core
-- built-ins, and the integer-to-bytea casts are the documented PostgreSQL 18
-- casts (the big-endian send representation), never int4send/int8send.
--
-- Cursor semantics: last_sequence and sequence are positive signed BIGINT (int64)
-- values; zero is reserved for the empty-stream cursor state.

-- ---------------------------------------------------------------------------
-- aipt.ledger_event_hash_v1: the versioned preimage (committed_at excluded)
--
-- The preimage layout must byte-for-byte match encodeLedgerPreimage in
-- hash.go under the literal domain AIPT_LEDGER_V1:
--
--   uint32 BE len(domain)     || domain UTF-8 bytes
--   uint32 BE len(stream_id)  || stream_id UTF-8 bytes
--   uint64 BE sequence              (positive signed BIGINT, 8 bytes)
--   uint32 BE len(event_id)   || event_id UTF-8 bytes
--   uint32 BE len(event_type) || event_type UTF-8 bytes
--   payload SHA-256 (raw 32 bytes)
--   0x00, or 0x01 || previous event hash (raw 32 bytes)
--
-- Length prefixes use the 4-byte big-endian int4-to-bytea cast and the
-- sequence uses the 8-byte big-endian int8-to-bytea cast. For a positive
-- signed BIGINT the big-endian two's-complement bytes are exactly the uint64
-- big-endian bytes hash.go writes, so the digests agree on the shared value
-- domain. committed_at is deliberately not part of the preimage.
CREATE FUNCTION aipt.ledger_event_hash_v1(
    p_stream_id       text,
    p_sequence        bigint,
    p_event_id        text,
    p_event_type      text,
    p_payload_sha256  bytea,
    p_prev_event_hash bytea
) RETURNS bytea
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
RETURN sha256(
    octet_length(convert_to('AIPT_LEDGER_V1', 'UTF8'))::int4::bytea || convert_to('AIPT_LEDGER_V1', 'UTF8')
    || octet_length(convert_to(p_stream_id, 'UTF8'))::int4::bytea || convert_to(p_stream_id, 'UTF8')
    || p_sequence::int8::bytea
    || octet_length(convert_to(p_event_id, 'UTF8'))::int4::bytea || convert_to(p_event_id, 'UTF8')
    || octet_length(convert_to(p_event_type, 'UTF8'))::int4::bytea || convert_to(p_event_type, 'UTF8')
    || p_payload_sha256
    || CASE WHEN p_prev_event_hash IS NULL THEN '\x00'::bytea ELSE '\x01'::bytea || p_prev_event_hash END
);

-- ---------------------------------------------------------------------------
-- aipt.ledger_streams: one row per stream. The cursor is advanced only by the
-- Go Append path (an explicit UPDATE of last_sequence and last_event_hash), so
-- this migration defines no function or trigger that mutates this table, and
-- no GREATEST-based or trigger-based cursor advance exists anywhere.
--
-- Cursor invariant: an empty stream has last_sequence = 0 with a NULL
-- last_event_hash; a nonempty stream has a positive signed BIGINT
-- last_sequence with a non-NULL 32-byte last_event_hash.
CREATE TABLE aipt.ledger_streams (
    stream_id       text        PRIMARY KEY CHECK (stream_id <> ''),
    last_sequence   bigint      NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    last_event_hash bytea       CHECK (last_event_hash IS NULL OR octet_length(last_event_hash) = 32),
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ledger_streams_cursor_invariant CHECK (
        (last_sequence = 0 AND last_event_hash IS NULL)
        OR (last_sequence > 0 AND last_event_hash IS NOT NULL)
    )
);

-- ---------------------------------------------------------------------------
-- aipt.ledger_events: the append-only event chain. INSERT is the only
-- permitted operation; every UPDATE, DELETE, and TRUNCATE is rejected at the
-- statement level, even when it matches zero rows.
--
-- Payload flow: Append receives the raw JSON payload, canonicalizes it with
-- the existing internal/protocol.CanonicalJSON before any database access, and
-- stores the canonical JSON as TEXT in payload_canonical. This migration
-- never duplicates canonical JSON logic: it stores the canonical TEXT as-is
-- and only verifies the digest.
--
-- Chain invariant: the genesis event has sequence = 1 (a positive signed
-- BIGINT) and a NULL prev_event_hash; every later event has sequence > 1 and a
-- non-NULL 32-byte prev_event_hash equal to the previous event's event_hash.
-- payload_sha256 must equal the core built-in sha256(convert_to(
-- payload_canonical, 'UTF8')), so the digest bytes exactly match Go SHA-256
-- over the canonical JSON's UTF-8 output and stay independent of the database
-- encoding, and event_hash must equal aipt.ledger_event_hash_v1(...), so the
-- database itself enforces the hash-chain contract.
CREATE TABLE aipt.ledger_events (
    stream_id         text        NOT NULL CHECK (stream_id <> ''),
    sequence          bigint      NOT NULL CHECK (sequence > 0),
    event_id          text        NOT NULL CHECK (event_id <> ''),
    event_type        text        NOT NULL CHECK (event_type <> ''),
    payload_canonical text        NOT NULL CHECK (payload_canonical <> ''),
    payload_sha256    bytea       NOT NULL CONSTRAINT ledger_events_payload_sha256_length_check CHECK (octet_length(payload_sha256) = 32),
    prev_event_hash   bytea       CHECK (prev_event_hash IS NULL OR octet_length(prev_event_hash) = 32),
    event_hash        bytea       NOT NULL CHECK (octet_length(event_hash) = 32),
    committed_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ledger_events_pkey PRIMARY KEY (stream_id, sequence),
    CONSTRAINT ledger_events_event_id_key UNIQUE (event_id),
    CONSTRAINT ledger_events_stream_fkey FOREIGN KEY (stream_id)
        REFERENCES aipt.ledger_streams (stream_id)
        ON DELETE RESTRICT
        ON UPDATE RESTRICT,
    CONSTRAINT ledger_events_chain_invariant CHECK (
        (sequence = 1 AND prev_event_hash IS NULL)
        OR (sequence > 1 AND prev_event_hash IS NOT NULL)
    ),
    CONSTRAINT ledger_events_payload_sha256_check CHECK (
        payload_sha256 = sha256(convert_to(payload_canonical, 'UTF8'))
    ),
    CONSTRAINT ledger_events_event_hash_check CHECK (
        event_hash = aipt.ledger_event_hash_v1(
            stream_id, sequence, event_id, event_type, payload_sha256, prev_event_hash
        )
    )
);

-- ---------------------------------------------------------------------------
-- aipt.ledger_events_append_only: statement-level BEFORE trigger (never a row
-- trigger, never AFTER) that rejects every UPDATE, DELETE, and TRUNCATE on
-- aipt.ledger_events -- including statements that match zero rows -- with the
-- stable code AIPT_LEDGER_APPEND_ONLY and SQLSTATE 55000. The trigger body
-- only raises; it never mutates any table.
CREATE FUNCTION aipt.ledger_events_append_only() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'AIPT_LEDGER_APPEND_ONLY' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER ledger_events_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON aipt.ledger_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION aipt.ledger_events_append_only();
