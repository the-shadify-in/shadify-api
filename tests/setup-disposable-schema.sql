CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'shadify_api_role') THEN
        CREATE ROLE shadify_api_role WITH LOGIN PASSWORD 'postgres';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'WeddingStatus') THEN
        CREATE TYPE "WeddingStatus" AS ENUM ('draft', 'published', 'archived');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'WeddingPlan') THEN
        CREATE TYPE "WeddingPlan" AS ENUM ('free', 'lite', 'pro');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'PhotoStatus') THEN
        CREATE TYPE "PhotoStatus" AS ENUM ('processing', 'approved', 'rejected');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'PhotoVisibility') THEN
        CREATE TYPE "PhotoVisibility" AS ENUM ('public', 'family', 'private');
    END IF;
END $$;

DROP TABLE IF EXISTS upload_sessions CASCADE;
DROP TABLE IF EXISTS delegation_jti_registry CASCADE;
DROP TABLE IF EXISTS revoked_delegation_keys CASCADE;
DROP TABLE IF EXISTS revoked_operators CASCADE;
DROP TABLE IF EXISTS guest_pin_attempts CASCADE;
DROP TABLE IF EXISTS revoked_guest_tokens CASCADE;

ALTER TABLE entitlements ADD COLUMN IF NOT EXISTS storage_allocated_bytes BIGINT NOT NULL DEFAULT 53687091200;
ALTER TABLE entitlements ADD COLUMN IF NOT EXISTS storage_used_bytes BIGINT NOT NULL DEFAULT 0;
ALTER TABLE entitlements ADD COLUMN IF NOT EXISTS photo_count_limit INT NOT NULL DEFAULT 5000;
ALTER TABLE entitlements ADD COLUMN IF NOT EXISTS photo_count_used INT NOT NULL DEFAULT 0;

ALTER TABLE photos ADD COLUMN IF NOT EXISTS sha256 CHAR(64) NULL;
ALTER TABLE photos ADD COLUMN IF NOT EXISTS upload_session_id BIGINT NULL;

CREATE TABLE delegation_jti_registry (
    jti UUID PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS idx_delegation_jti_expires_at ON delegation_jti_registry(expires_at);

CREATE TABLE revoked_delegation_keys (
    key_id TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    reason TEXT NOT NULL
);

CREATE TABLE revoked_operators (
    operator_id UUID PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    reason TEXT NOT NULL
);

CREATE TABLE guest_pin_attempts (
    wedding_slug TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ NULL,
    window_start TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (wedding_slug, ip_address)
);

CREATE TABLE revoked_guest_tokens (
    token_hash TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS weddings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL UNIQUE,
    bride_name TEXT NOT NULL,
    groom_name TEXT NOT NULL,
    wedding_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'published',
    plan TEXT NOT NULL DEFAULT 'free',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS entitlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wedding_id UUID NOT NULL REFERENCES weddings(id) ON DELETE CASCADE,
    storage_allocated_bytes BIGINT NOT NULL DEFAULT 53687091200, -- 50GB
    storage_used_bytes BIGINT NOT NULL DEFAULT 0,
    photo_count_limit INT NOT NULL DEFAULT 5000,
    photo_count_used INT NOT NULL DEFAULT 0,
    hosting_until TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '1 year'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_entitlements_wedding UNIQUE (wedding_id)
);

CREATE TABLE IF NOT EXISTS upload_sessions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    wedding_id UUID NOT NULL REFERENCES weddings(id) ON DELETE CASCADE,
    expected_bytes BIGINT NOT NULL,
    actual_bytes BIGINT NULL,
    object_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'RESERVED',
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NULL,
    verification_generation INT NOT NULL DEFAULT 0,
    verification_lease_token TEXT NULL,
    verification_lease_expires_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS photos (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wedding_id UUID NOT NULL REFERENCES weddings(id) ON DELETE CASCADE,
    upload_session_id BIGINT NULL REFERENCES upload_sessions(id) ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    sha256 CHAR(64) NULL,
    bytes_original BIGINT NULL,
    key_original TEXT NOT NULL,
    key_preview TEXT NOT NULL DEFAULT '',
    key_thumb TEXT NOT NULL DEFAULT '',
    width INT NOT NULL DEFAULT 0,
    height INT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'processing',
    visibility TEXT NOT NULL DEFAULT 'public',
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_photos_session UNIQUE (upload_session_id)
);

-- Drop any previous function signatures to avoid function overloading conflicts
DROP FUNCTION IF EXISTS public.complete_upload_session(BIGINT, BIGINT, TEXT);
DROP FUNCTION IF EXISTS public.complete_upload_session(BIGINT, BIGINT, TEXT, INT, TEXT);
DROP FUNCTION IF EXISTS public.claim_verification_lease(BIGINT, TEXT);
DROP FUNCTION IF EXISTS public.claim_verification_lease(BIGINT, TEXT, INT);
DROP FUNCTION IF EXISTS public.cancel_upload_session(BIGINT);

-- Real Stored Procedure with 3-Tier FOR UPDATE Transactional Isolation
CREATE OR REPLACE FUNCTION public.complete_upload_session(
    p_session_id BIGINT,
    p_actual_bytes BIGINT,
    p_sha256 TEXT,
    p_generation INT DEFAULT NULL,
    p_lease_token TEXT DEFAULT NULL
) RETURNS TABLE(out_photo_id UUID, out_wedding_id UUID, out_actual_bytes BIGINT, out_recovered BOOLEAN)
LANGUAGE plpgsql
AS $$
DECLARE
    v_session upload_sessions%ROWTYPE;
    v_entitlement entitlements%ROWTYPE;
    v_existing_photo photos%ROWTYPE;
    v_new_photo_id UUID;
BEGIN
    IF p_actual_bytes <= 0 THEN
        RAISE EXCEPTION 'p_actual_bytes must be strictly positive (got: %)', p_actual_bytes USING ERRCODE = '22023';
    END IF;

    -- Tier 1 Lock: Upload Session row locked FOR UPDATE
    SELECT * INTO v_session FROM upload_sessions WHERE id = p_session_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Upload session % not found', p_session_id USING ERRCODE = 'P0002';
    END IF;

    -- Stale Worker Fencing Enforcement (F08)
    IF p_generation IS NOT NULL THEN
        IF v_session.verification_generation IS DISTINCT FROM p_generation OR
           (p_lease_token IS NOT NULL AND v_session.verification_lease_token IS DISTINCT FROM p_lease_token) THEN
            RAISE EXCEPTION 'STALE_WORKER_FENCING: Worker generation % with token % rejected. Active generation is %',
                p_generation, p_lease_token, v_session.verification_generation USING ERRCODE = '55001';
        END IF;
    END IF;

    -- Idempotent Recovery: If already COMPLETED, return existing photo without re-settlement (F09)
    IF v_session.status = 'COMPLETED' THEN
        SELECT * INTO v_existing_photo FROM photos WHERE upload_session_id = p_session_id;
        IF NOT FOUND OR v_existing_photo.id IS NULL THEN
            RAISE EXCEPTION 'CORRUPT_STATE: Completed upload session % has no associated photo record', p_session_id USING ERRCODE = 'P0002';
        END IF;
        RETURN QUERY SELECT v_existing_photo.id, v_session.wedding_id, v_session.actual_bytes, true;
        RETURN;
    END IF;

    IF v_session.status = 'CANCELLED' THEN
        RAISE EXCEPTION 'Upload session % was CANCELLED; cannot complete', p_session_id USING ERRCODE = '55000';
    END IF;

    IF v_session.status = 'EXPIRED' THEN
        RAISE EXCEPTION 'Upload session % was EXPIRED; cannot complete', p_session_id USING ERRCODE = '55000';
    END IF;

    -- Tier 2 Lock: Entitlement row locked FOR UPDATE
    SELECT * INTO v_entitlement FROM entitlements WHERE wedding_id = v_session.wedding_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Entitlement for wedding % not found', v_session.wedding_id USING ERRCODE = 'P0002';
    END IF;

    -- Check Quota
    IF (v_entitlement.storage_used_bytes + p_actual_bytes) > v_entitlement.storage_allocated_bytes THEN
        RAISE EXCEPTION 'Storage quota exceeded' USING ERRCODE = '54000';
    END IF;

    -- Insert Photo bound 1:1 to upload_session_id
    INSERT INTO photos (
        wedding_id,
        upload_session_id,
        sha256,
        bytes_original,
        key_original,
        key_preview,
        key_thumb,
        width,
        height,
        status
    ) VALUES (
        v_session.wedding_id,
        p_session_id,
        p_sha256,
        p_actual_bytes,
        v_session.object_key,
        v_session.object_key,
        v_session.object_key,
        0,
        0,
        'processing'
    ) RETURNING id INTO v_new_photo_id;

    -- Atomic Quota Settlement
    UPDATE entitlements
    SET storage_used_bytes = storage_used_bytes + p_actual_bytes,
        photo_count_used = photo_count_used + 1,
        updated_at = clock_timestamp()
    WHERE wedding_id = v_session.wedding_id;

    -- Settle Session State
    UPDATE upload_sessions
    SET status = 'COMPLETED',
        actual_bytes = p_actual_bytes,
        completed_at = clock_timestamp()
    WHERE id = p_session_id;

    RETURN QUERY SELECT v_new_photo_id, v_session.wedding_id, p_actual_bytes, false;
END;
$$;

-- 9. Stored Procedure: Worker Verification Lease Claim & Fencing Generation (F08)
DROP FUNCTION IF EXISTS public.claim_verification_lease(BIGINT, TEXT);
DROP FUNCTION IF EXISTS public.claim_verification_lease(BIGINT, TEXT, INT);

CREATE OR REPLACE FUNCTION public.claim_verification_lease(
    p_session_id BIGINT,
    p_worker_id TEXT,
    p_lease_duration_seconds INT DEFAULT 30
) RETURNS TABLE(out_claimed BOOLEAN, out_generation INT, out_lease_token TEXT, out_session_status TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_session upload_sessions%ROWTYPE;
    v_new_gen INT;
    v_new_tok TEXT;
BEGIN
    SELECT * INTO v_session FROM upload_sessions WHERE id = p_session_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Upload session % not found', p_session_id USING ERRCODE = 'P0002';
    END IF;

    IF v_session.status = 'COMPLETED' THEN
        RETURN QUERY SELECT false, v_session.verification_generation, v_session.verification_lease_token, 'COMPLETED';
        RETURN;
    END IF;

    IF v_session.status = 'CANCELLED' OR v_session.status = 'REJECTED' THEN
        RETURN QUERY SELECT false, v_session.verification_generation, v_session.verification_lease_token, v_session.status;
        RETURN;
    END IF;

    -- Reject if active worker holds unexpired lease
    IF v_session.verification_lease_expires_at IS NOT NULL 
       AND v_session.verification_lease_expires_at > clock_timestamp() 
       AND v_session.status = 'VERIFYING' THEN
        RETURN QUERY SELECT false, v_session.verification_generation, v_session.verification_lease_token, 'VERIFYING';
        RETURN;
    END IF;

    -- Monotonically increment fencing generation counter
    v_new_gen := COALESCE(v_session.verification_generation, 0) + 1;
    v_new_tok := p_worker_id || ':' || gen_random_uuid()::text;

    UPDATE upload_sessions
    SET status = 'VERIFYING',
        verification_generation = v_new_gen,
        verification_lease_token = v_new_tok,
        verification_lease_expires_at = clock_timestamp() + (p_lease_duration_seconds || ' seconds')::INTERVAL
    WHERE id = p_session_id;

    RETURN QUERY SELECT true, v_new_gen, v_new_tok, 'VERIFYING';
END;
$$;

-- 10. Stored Procedure: Cancel Upload Session
DROP FUNCTION IF EXISTS public.cancel_upload_session(BIGINT);

CREATE OR REPLACE FUNCTION public.cancel_upload_session(
    p_session_id BIGINT
) RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_session upload_sessions%ROWTYPE;
BEGIN
    SELECT * INTO v_session FROM upload_sessions WHERE id = p_session_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Upload session % not found', p_session_id USING ERRCODE = 'P0002';
    END IF;

    IF v_session.status = 'COMPLETED' THEN
        RAISE EXCEPTION 'Cannot cancel completed upload session %', p_session_id USING ERRCODE = '55000';
    END IF;

    UPDATE upload_sessions
    SET status = 'CANCELLED'
    WHERE id = p_session_id;
END;
$$;

